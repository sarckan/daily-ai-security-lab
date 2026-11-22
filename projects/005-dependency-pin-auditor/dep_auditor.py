"""Dependency pin auditor: supply-chain hygiene checks for requirements.txt.

A ``requirements.txt`` decides exactly which code ends up running in your
build. Loose ranges, unpinned names, mutable git refs, plain-HTTP indexes and
look-alike package names all let *someone else* change that code without a
diff in your repository. This tool reads a requirements file (no network
access, nothing is installed) and reports each risk with a rule name, a
severity and a short fix, then rolls everything up into a 0-100 score.

Rules
-----
=============  ========  ====================================================
UNPINNED       error     no version at all (``numpy``)
TYPOSQUAT      error     one edit away from a popular package (``reqeusts``)
VCS_MUTABLE    error     git/hg URL without a full commit hash (``@main``)
INSECURE_URL   error     ``http://`` index or package URL
MISSING_HASH   error     some lines use ``--hash`` but this one does not
LOOSE          warning   range instead of ``==`` (``flask>=2.0``)
EXTRA_INDEX    warning   ``--extra-index-url`` (dependency-confusion risk)
TRUSTED_HOST   warning   ``--trusted-host`` turns off TLS verification
DUPLICATE      warning   the same project listed twice
NO_HASHES      info      file uses no ``--hash`` pins at all
=============  ========  ====================================================

Usage:
    python dep_auditor.py examples/requirements.txt
    python dep_auditor.py examples/requirements.txt --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass

SEVERITY: dict[str, str] = {
    "UNPINNED": "error", "TYPOSQUAT": "error", "VCS_MUTABLE": "error",
    "INSECURE_URL": "error", "MISSING_HASH": "error",
    "LOOSE": "warning", "EXTRA_INDEX": "warning", "TRUSTED_HOST": "warning",
    "DUPLICATE": "warning", "NO_HASHES": "info",
}
PENALTY: dict[str, int] = {"error": 15, "warning": 7, "info": 2}
GRADES: tuple[tuple[int, str], ...] = ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F"))

# Small offline list of heavily downloaded projects used for look-alike checks.
POPULAR: frozenset[str] = frozenset({
    "requests", "urllib3", "numpy", "pandas", "scipy", "flask", "django",
    "fastapi", "pydantic", "boto3", "botocore", "setuptools", "wheel", "pip",
    "six", "pyyaml", "cryptography", "certifi", "idna", "charset-normalizer",
    "jinja2", "click", "pytest", "matplotlib", "pillow", "sqlalchemy",
    "tensorflow", "torch", "scikit-learn", "openai", "httpx", "aiohttp",
    "beautifulsoup4", "lxml", "colorama", "rich", "typing-extensions",
    "attrs", "jsonschema", "pyjwt", "paramiko", "redis", "celery",
})

NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
EGG_RE = re.compile(r"#egg=([A-Za-z0-9._-]+)")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
VCS_PREFIXES = ("git+", "hg+", "svn+", "bzr+")


@dataclass(frozen=True)
class Finding:
    """One rule violation tied to a line of the requirements file."""

    rule: str
    line: int
    subject: str
    message: str

    @property
    def severity(self) -> str:
        return SEVERITY[self.rule]


@dataclass
class Requirement:
    """A parsed requirement line (only the parts the rules need)."""

    line: int
    name: str
    spec: str = ""
    url: str = ""
    hashes: int = 0


def normalize(name: str) -> str:
    """PEP 503 normalisation: ``Py_YAML`` and ``py.yaml`` are both ``py-yaml``."""
    return re.sub(r"[-_.]+", "-", name).lower()


def edit_distance(a: str, b: str) -> int:
    """Optimal-string-alignment distance (insert, delete, substitute, swap)."""
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[len(b)]


def lookalike(name: str) -> str | None:
    """Return the popular project ``name`` imitates, if any."""
    norm = normalize(name)
    if norm in POPULAR or len(norm) < 4:
        return None
    for target in sorted(POPULAR):
        if edit_distance(norm, target) == 1:
            return target
    return None


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Join ``\\`` continuations, strip comments; keep the starting line number."""
    out: list[tuple[int, str]] = []
    buf, start = "", 0
    for no, raw in enumerate(text.splitlines(), 1):
        line = re.sub(r"(^|\s)#(?!egg=).*$", "", raw).rstrip()
        if not buf:
            start = no
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        if buf.strip():
            out.append((start, buf.strip()))
        buf = ""
    if buf.strip():
        out.append((start, buf.strip()))
    return out


def audit(text: str) -> list[Finding]:
    """Run every rule over the contents of a requirements file."""
    findings: list[Finding] = []
    reqs: list[Requirement] = []

    for no, line in logical_lines(text):
        if line.startswith("-"):
            opt_match = re.match(r"^(-{1,2}[A-Za-z-]+)(?:=|\s+)?(.*)$", line)
            opt, value = (opt_match.group(1), opt_match.group(2).strip()) if opt_match else (line, "")
            if opt in ("-i", "--index-url", "--extra-index-url", "-f", "--find-links"):
                if value.lower().startswith("http://"):
                    findings.append(Finding("INSECURE_URL", no, value,
                                            "plain-HTTP index can be tampered with; use https://"))
                if opt == "--extra-index-url":
                    findings.append(Finding("EXTRA_INDEX", no, value,
                                            "pip merges all indexes: dependency-confusion risk"))
            elif opt == "--trusted-host":
                findings.append(Finding("TRUSTED_HOST", no, value,
                                        "disables TLS certificate checks for this host"))
            elif opt in ("-e", "--editable") and value.startswith(VCS_PREFIXES):
                reqs.append(_parse_url(no, value))
            continue
        if line.startswith(VCS_PREFIXES) or "://" in line.split("@")[0]:
            reqs.append(_parse_url(no, line))
            continue
        match = NAME_RE.match(line)
        if not match:
            continue
        rest = match.group(3)
        hashes = len(re.findall(r"--hash[= ]", rest))
        rest = re.sub(r"--hash[= ]\S+", "", rest)
        if rest.lstrip().startswith("@"):
            req = _parse_url(no, rest.lstrip()[1:].strip(), match.group(1))
            req.hashes = hashes
            reqs.append(req)
            continue
        spec = rest.split(";")[0].replace(" ", "")
        reqs.append(Requirement(no, match.group(1), spec, hashes=hashes))

    findings.extend(_check_requirements(reqs))
    return sorted(findings, key=lambda f: (f.line or sys.maxsize, f.rule))


def _parse_url(no: int, url: str, name: str = "") -> Requirement:
    egg = EGG_RE.search(url)
    return Requirement(no, name or (egg.group(1) if egg else url), url=url)


def _check_requirements(reqs: list[Requirement]) -> list[Finding]:
    findings: list[Finding] = []
    seen: dict[str, int] = {}
    hashed = any(r.hashes for r in reqs)
    for r in reqs:
        key = normalize(r.name)
        if key in seen:
            findings.append(Finding("DUPLICATE", r.line, r.name,
                                    f"same project as line {seen[key]} (names ignore case and -_.)"))
        seen.setdefault(key, r.line)
        if (target := lookalike(r.name)) is not None:
            findings.append(Finding("TYPOSQUAT", r.line, r.name,
                                    f"one edit away from '{target}' - check the spelling"))
        if r.url:
            findings.extend(_check_url(r))
        elif not r.spec:
            findings.append(Finding("UNPINNED", r.line, r.name,
                                    "no version: every install may pull a different release"))
        elif not r.spec.startswith(("==", "===")) or "*" in r.spec or "," in r.spec:
            findings.append(Finding("LOOSE", r.line, f"{r.name}{r.spec}",
                                    "range allows new releases in; pin with =="))
        if hashed and not r.hashes:
            findings.append(Finding("MISSING_HASH", r.line, r.name,
                                    "other lines use --hash; pip --require-hashes will reject this"))
    if reqs and not hashed:
        findings.append(Finding("NO_HASHES", 0, "file",
                                "no --hash pins; try pip-compile --generate-hashes"))
    return findings


def _check_url(r: Requirement) -> list[Finding]:
    out: list[Finding] = []
    if r.url.lower().removeprefix("git+").removeprefix("hg+").startswith("http://"):
        out.append(Finding("INSECURE_URL", r.line, r.name, "package fetched over plain HTTP"))
    if r.url.startswith(VCS_PREFIXES):
        path = r.url.split("#", 1)[0].split("://", 1)[-1]
        ref = path.rsplit("@", 1)[1] if "@" in path.split("/", 1)[-1] else ""
        if not COMMIT_RE.match(ref):
            what = f"'@{ref}'" if ref else "no ref"
            out.append(Finding("VCS_MUTABLE", r.line, r.name,
                               f"{what} can move; pin a full 40-char commit hash"))
    return out


def score(findings: list[Finding]) -> tuple[int, str]:
    """Start at 100, subtract a penalty per finding, map to a letter grade."""
    value = max(0, 100 - sum(PENALTY[f.severity] for f in findings))
    grade = next(letter for floor, letter in GRADES if value >= floor)
    return value, grade


def render(findings: list[Finding], path: str) -> str:
    """Human-readable report."""
    value, grade = score(findings)
    errors = sum(f.severity == "error" for f in findings)
    lines = [f"Audited {path}: {len(findings)} findings"]
    for f in findings:
        where = f"line {f.line:>2}" if f.line else "file   "
        lines.append(f"  [{f.rule:<12}] {where}: {f.subject}")
        lines.append(f"  {'':14} -> {f.message}")
    status = "FAIL" if errors else "PASS"
    lines.append(f"Score: {value}/100 (grade {grade}) - {status} ({errors} error(s))")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit a requirements.txt for supply-chain risks.")
    parser.add_argument("path", help="requirements file to audit")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    args = parser.parse_args(argv)
    try:
        with open(args.path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    findings = audit(text)
    if args.json:
        value, grade = score(findings)
        payload = {"score": value, "grade": grade,
                   "findings": [asdict(f) | {"severity": f.severity} for f in findings]}
        print(json.dumps(payload, indent=2))
    else:
        print(render(findings, args.path))
    return 1 if any(f.severity == "error" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())

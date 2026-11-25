"""Dockerfile Hardening Linter.

Offline, dependency-free static checks for the container-hardening mistakes
that show up most often in real Dockerfiles: running as root, floating base
image tags, ``curl | sh`` installers, disabled TLS verification, secrets baked
into ENV/ARG, world-writable permissions and more.

Every finding carries a weight; the sum (capped at 100) is a risk score that
maps to a PASS / WARN / FAIL verdict. Exit codes make it CI-friendly:
``0`` no FAIL, ``1`` FAIL, ``2`` unreadable file or no FROM instruction.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

WEIGHTS: dict[str, int] = {
    "CURL_PIPE_SHELL": 30,
    "SECRET_IN_ENV": 30,
    "ROOT_USER": 25,
    "TLS_VERIFY_OFF": 20,
    "LATEST_TAG": 15,
    "ADD_REMOTE_URL": 15,
    "WORLD_WRITABLE": 15,
    "SSH_EXPOSED": 15,
    "SUDO_IN_RUN": 10,
    "APT_CACHE_LEFT": 5,
    "NO_HEALTHCHECK": 5,
}
FAIL_AT = 60
WARN_AT = 25

SECRET_NAME = re.compile(r"(passw(or)?d|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)", re.I)
PIPE_SHELL = re.compile(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b")
TLS_OFF = re.compile(r"(\bcurl\b[^;&|]*\s(-k|--insecure)\b|--no-check-certificate|--trusted-host|GIT_SSL_NO_VERIFY|PYTHONHTTPSVERIFY=0)")
CHMOD_777 = re.compile(r"\bchmod\s+(-R\s+)?(0?777|a\+rwx|o\+w)\b")


@dataclass(frozen=True)
class Instruction:
    """One logical Dockerfile instruction (continuations already joined)."""

    line: int
    keyword: str
    args: str


@dataclass(frozen=True)
class Finding:
    rule: str
    line: int
    weight: int
    message: str


@dataclass
class Report:
    path: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return min(100, sum(f.weight for f in self.findings))

    @property
    def verdict(self) -> str:
        if self.score >= FAIL_AT:
            return "FAIL"
        return "WARN" if self.score >= WARN_AT else "PASS"

    def to_dict(self) -> dict:
        return {"path": self.path, "score": self.score, "verdict": self.verdict,
                "findings": [asdict(f) for f in self.findings]}


def parse(text: str) -> list[Instruction]:
    """Split a Dockerfile into instructions, joining ``\\`` continuations."""
    out: list[Instruction] = []
    buf: list[str] = []
    start = 0
    for no, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        if buf and stripped.startswith("#"):
            continue  # comment lines inside a continuation are ignored by Docker
        if not buf:
            start = no
        if stripped.endswith("\\"):
            buf.append(stripped[:-1].strip())
            continue
        buf.append(stripped)
        joined = " ".join(p for p in buf if p)
        buf = []
        keyword, _, args = joined.partition(" ")
        out.append(Instruction(start, keyword.upper(), args.strip()))
    if buf:
        joined = " ".join(p for p in buf if p)
        keyword, _, args = joined.partition(" ")
        out.append(Instruction(start, keyword.upper(), args.strip()))
    return out


def _env_pairs(args: str) -> list[tuple[str, str]]:
    """Return (name, value) pairs from ENV/ARG args (``K=V ...`` or ``K V``)."""
    if "=" not in args.split(" ", 1)[0]:
        name, _, value = args.partition(" ")
        return [(name, value.strip())]
    return [(m.group(1), m.group(2)) for m in re.finditer(r"([A-Za-z_][\w.-]*)=(\"[^\"]*\"|'[^']*'|\S*)", args)]


def _check_from(ins: Instruction, aliases: set[str]) -> Finding | None:
    parts = [p for p in ins.args.split() if not p.startswith("--")]
    if not parts:
        return None
    image = parts[0]
    if len(parts) >= 3 and parts[1].upper() == "AS":
        aliases.add(parts[2].lower())
    if image.lower() == "scratch" or image.lower() in aliases or "$" in image or "@sha256:" in image:
        return None
    name = image.rsplit("/", 1)[-1]
    if ":" not in name or name.endswith(":latest"):
        return Finding("LATEST_TAG", ins.line, WEIGHTS["LATEST_TAG"],
                       f"'{image}' floats: pin tag or digest")
    return None


def _check_run(ins: Instruction) -> list[Finding]:
    cmd = ins.args
    found: list[Finding] = []

    def add(rule: str, msg: str) -> None:
        found.append(Finding(rule, ins.line, WEIGHTS[rule], msg))

    if PIPE_SHELL.search(cmd):
        add("CURL_PIPE_SHELL", "remote script piped into a shell")
    if TLS_OFF.search(cmd):
        add("TLS_VERIFY_OFF", "TLS verification disabled")
    if CHMOD_777.search(cmd):
        add("WORLD_WRITABLE", "world-writable files (chmod 777)")
    if re.search(r"(^|[;&|]\s*)sudo\b", cmd):
        add("SUDO_IN_RUN", "sudo inside a RUN step")
    if re.search(r"\bapt-get\s+(-\S+\s+)*install\b", cmd) and "/var/lib/apt/lists" not in cmd:
        add("APT_CACHE_LEFT", "apt lists left in the layer")
    return found


def lint(text: str, path: str = "<string>") -> Report:
    """Lint Dockerfile *text* and return a :class:`Report`.

    Raises ``ValueError`` if the file contains no FROM instruction.
    """
    instructions = parse(text)
    if not any(i.keyword == "FROM" for i in instructions):
        raise ValueError("no FROM instruction found")
    report = Report(path)
    add = report.findings.append
    aliases: set[str] = set()
    last_user: tuple[int, str] | None = None
    has_healthcheck = False
    final_from = 0

    for ins in instructions:
        kw = ins.keyword
        if kw == "FROM":
            final_from = ins.line
            last_user, has_healthcheck = None, False  # USER/HEALTHCHECK are per stage
            if (f := _check_from(ins, aliases)) is not None:
                add(f)
        elif kw == "RUN":
            report.findings.extend(_check_run(ins))
        elif kw == "USER":
            last_user = (ins.line, ins.args.split(":")[0].strip())
        elif kw == "HEALTHCHECK":
            has_healthcheck = not ins.args.upper().startswith("NONE")
        elif kw == "ADD" and re.search(r"(^|\s)https?://", ins.args):
            add(Finding("ADD_REMOTE_URL", ins.line, WEIGHTS["ADD_REMOTE_URL"],
                        "ADD of a remote URL, no checksum"))
        elif kw in {"ENV", "ARG"}:
            for name, value in _env_pairs(ins.args):
                if SECRET_NAME.search(name) and value.strip("\"'"):
                    add(Finding("SECRET_IN_ENV", ins.line, WEIGHTS["SECRET_IN_ENV"],
                                f"{name} baked into image layers"))
        elif kw == "EXPOSE" and re.search(r"(^|\s)22(/tcp)?(\s|$)", ins.args):
            add(Finding("SSH_EXPOSED", ins.line, WEIGHTS["SSH_EXPOSED"],
                        "port 22 (sshd) exposed"))

    if last_user is None or last_user[1] in {"root", "0"}:
        line = last_user[0] if last_user else final_from
        add(Finding("ROOT_USER", line, WEIGHTS["ROOT_USER"],
                    "final stage runs as root"))
    if not has_healthcheck:
        add(Finding("NO_HEALTHCHECK", final_from, WEIGHTS["NO_HEALTHCHECK"],
                    "no HEALTHCHECK in final stage"))
    report.findings.sort(key=lambda f: (-f.weight, f.line))
    return report


def format_report(report: Report) -> str:
    lines = [f"{report.path}: {report.verdict} (risk {report.score}/100)"]
    if not report.findings:
        lines.append("  no issues found")
    for f in report.findings:
        lines.append(f"  [+{f.weight:>2}] L{f.line:<3} {f.rule:<16} {f.message}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Offline Dockerfile hardening linter.")
    ap.add_argument("paths", nargs="+", help="Dockerfile(s) to audit")
    ap.add_argument("--json", action="store_true", help="emit one JSON object per file")
    args = ap.parse_args(argv)
    worst = 0
    for p in args.paths:
        try:
            report = lint(Path(p).read_text(encoding="utf-8"), p)
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            print(f"{p}: error: {exc}", file=sys.stderr)
            worst = max(worst, 2)
            continue
        print(json.dumps(report.to_dict()) if args.json else format_report(report))
        if report.verdict == "FAIL":
            worst = max(worst, 1)
    return worst


if __name__ == "__main__":
    sys.exit(main())

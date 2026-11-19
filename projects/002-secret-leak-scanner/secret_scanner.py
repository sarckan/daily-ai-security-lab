"""Secret leak scanner: find hard-coded credentials before they reach git.

API keys, tokens and passwords committed to a repository are one of the most
common causes of cloud breaches. This tool walks a file or directory, runs a
set of named detection rules on every text line, filters out obvious
placeholders, and reports each finding with a severity and a *redacted*
preview, so the report itself never leaks the secret.

Detection combines two ideas:
  * signature rules for well-known token formats (AWS, GitHub, Slack, JWT,
    PEM private keys, credentials embedded in URLs), and
  * Shannon entropy for "random-looking" values assigned to sensitive names.

It is defensive and local-only: it reads your own files and never sends
anything over the network.

Usage:
    python secret_scanner.py examples/
    python secret_scanner.py . --json --min-severity high
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
IGNORE_MARKER = "secret-scan: ignore"
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".pytest_cache"}
MAX_FILE_BYTES = 1_000_000
ENTROPY_THRESHOLD = 3.5
PLACEHOLDER_WORDS = ("changeme", "example", "dummy", "placeholder", "your_", "xxxx", "<", "${", "redacted")


@dataclass(frozen=True)
class Rule:
    """A named signature rule. Group 1 of the pattern (if any) is the secret."""

    name: str
    severity: str
    pattern: re.Pattern[str]
    check_entropy: bool = False


RULES: tuple[Rule, ...] = (
    Rule("private_key_block", "critical",
         re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    Rule("aws_access_key_id", "critical", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    Rule("github_token", "critical", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b")),
    Rule("slack_token", "high", re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b")),
    Rule("jwt", "high",
         re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,})\b")),
    Rule("url_with_password", "high", re.compile(r"[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s:/@]{4,})@")),
    Rule("secret_assignment", "medium",
         re.compile(r"(?i)\b[\w.-]*(?:password|passwd|secret|api_?key|token|auth)[\w.-]*\s*[:=]\s*"
                    r"[\"']([^\"'\s]{8,})[\"']"),
         check_entropy=True),
)


@dataclass(frozen=True)
class Finding:
    """One suspected secret in one file."""

    path: str
    line: int
    rule: str
    severity: str
    preview: str
    entropy: float


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy of ``value`` in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def redact(secret: str) -> str:
    """Keep only the first 4 characters and the length: safe to print or log."""
    return f"{secret[:4]}…({len(secret)} chars)"


def is_placeholder(value: str) -> bool:
    """True for values that are obviously not real secrets."""
    low = value.lower()
    return any(word in low for word in PLACEHOLDER_WORDS) or len(set(value)) <= 3


def scan_line(text: str, path: str = "<string>", line_no: int = 1) -> list[Finding]:
    """Run every rule on a single line and return the findings."""
    if IGNORE_MARKER in text:
        return []
    findings: list[Finding] = []
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            secret = match.group(1) if match.groups() else match.group(0)
            entropy = round(shannon_entropy(secret), 2)
            if rule.check_entropy and (is_placeholder(secret) or entropy < ENTROPY_THRESHOLD):
                continue
            findings.append(Finding(path, line_no, rule.name, rule.severity, redact(secret), entropy))
    return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Drop a generic hit when a specific rule already matched the same line."""
    specific = [f for f in findings if f.rule != "secret_assignment"]
    return specific if specific else findings


def scan_text(text: str, path: str = "<string>") -> list[Finding]:
    """Scan a multi-line string."""
    results: list[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        results.extend(scan_line(line, path, number))
    return results


def iter_files(root: Path) -> Iterator[Path]:
    """Yield text-like files under ``root`` (or ``root`` itself if it is a file)."""
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            yield Path(dirpath) / name


def read_text(path: Path) -> str | None:
    """Return file contents, or None for large or binary files."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def scan_path(root: Path) -> list[Finding]:
    """Scan every readable text file under ``root``."""
    findings: list[Finding] = []
    for file in iter_files(root):
        text = read_text(file)
        if text is not None:
            findings.extend(scan_text(text, file.as_posix()))
    return findings


def filter_severity(findings: Iterable[Finding], minimum: str) -> list[Finding]:
    """Keep findings whose severity is at least ``minimum``."""
    floor = SEVERITY_ORDER[minimum]
    return [f for f in findings if SEVERITY_ORDER[f.severity] >= floor]


def format_report(findings: list[Finding]) -> str:
    """Human-readable report, most severe first."""
    if not findings:
        return "OK: no secrets found."
    ordered = sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.path, f.line))
    lines = [f"[{f.severity.upper():8}] {f.path}:{f.line}  {f.rule:18} {f.preview}  H={f.entropy}" for f in ordered]
    counts = Counter(f.severity for f in findings)
    summary = ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if counts[s])
    lines.append(f"\n{len(findings)} finding(s): {summary}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Find hard-coded secrets in files.")
    parser.add_argument("path", type=Path, help="file or directory to scan")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low")
    args = parser.parse_args(argv)

    if not args.path.exists():
        parser.error(f"path not found: {args.path}")
    findings = filter_severity(scan_path(args.path), args.min_severity)
    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False))
    else:
        print(format_report(findings))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())

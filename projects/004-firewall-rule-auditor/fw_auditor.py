"""Firewall rule auditor: find shadowed, redundant and conflicting ACL rules.

Firewalls evaluate rules top-down and stop at the first match. Over time,
rule sets grow and some rules can never fire because an earlier rule already
matches every packet they would match. This tool models each rule as a box in
a 4-dimensional packet space (protocol x source x destination x port) and
compares every pair of rules with exact set logic, so findings are proofs,
not heuristics.

Rule file format (one rule per line, ``#`` starts a comment)::

    <allow|deny> <tcp|udp|any> <src CIDR|any> <dst CIDR|any> <port|lo-hi|any>

Usage:
    python fw_auditor.py examples/rules.txt
    python fw_auditor.py examples/rules.txt --json
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from dataclasses import dataclass
from enum import Enum

PROTOCOLS = frozenset({"tcp", "udp"})
Interval = tuple[int, int]  # inclusive [lo, hi]


class Kind(str, Enum):
    """Finding categories, ordered from most to least severe."""

    SHADOWED = "SHADOWED"          # never fires, opposite action wins -> bug
    REDUNDANT = "REDUNDANT"        # never fires, same action -> dead rule
    CONFLICT = "CONFLICT"          # partial overlap, opposite actions
    GENERALIZATION = "GENERALIZATION"  # later rule is a broader opposite rule


SEVERITY = {Kind.SHADOWED: "error", Kind.REDUNDANT: "warning",
            Kind.CONFLICT: "info", Kind.GENERALIZATION: "info"}

VERB = {"allow": "allows", "deny": "denies"}


@dataclass(frozen=True)
class Rule:
    """A single first-match firewall rule as a box in packet space."""

    line: int
    action: str
    protos: frozenset[str]
    src: Interval
    dst: Interval
    ports: Interval
    text: str

    def dims(self) -> tuple[Interval, Interval, Interval]:
        return (self.src, self.dst, self.ports)


@dataclass(frozen=True)
class Finding:
    kind: Kind
    rule: Rule
    other: Rule
    message: str

    @property
    def severity(self) -> str:
        return SEVERITY[self.kind]


class RuleParseError(ValueError):
    """Raised when a rule line cannot be parsed."""


def _parse_net(token: str) -> Interval:
    if token == "any":
        return (0, 2**32 - 1)
    try:
        net = ipaddress.IPv4Network(token, strict=False)
    except ValueError as exc:
        raise RuleParseError(f"bad network {token!r}") from exc
    return (int(net.network_address), int(net.broadcast_address))


def _parse_ports(token: str) -> Interval:
    if token == "any":
        return (0, 65535)
    lo_s, _, hi_s = token.partition("-")
    try:
        lo, hi = int(lo_s), int(hi_s or lo_s)
    except ValueError as exc:
        raise RuleParseError(f"bad port {token!r}") from exc
    if not 0 <= lo <= hi <= 65535:
        raise RuleParseError(f"port out of range {token!r}")
    return (lo, hi)


def parse_rule(text: str, line: int = 0) -> Rule:
    """Parse one rule line into a :class:`Rule`."""
    parts = text.split()
    if len(parts) != 5:
        raise RuleParseError(f"line {line}: expected 5 fields, got {len(parts)}")
    action, proto, src, dst, ports = (p.lower() for p in parts)
    if action not in ("allow", "deny"):
        raise RuleParseError(f"line {line}: action must be allow/deny")
    if proto != "any" and proto not in PROTOCOLS:
        raise RuleParseError(f"line {line}: protocol must be tcp/udp/any")
    protos = PROTOCOLS if proto == "any" else frozenset({proto})
    return Rule(line, action, protos, _parse_net(src), _parse_net(dst),
                _parse_ports(ports), " ".join(parts))


def parse_rules(source: str) -> list[Rule]:
    """Parse a whole rule file, skipping blanks and comments."""
    rules: list[Rule] = []
    for no, raw in enumerate(source.splitlines(), start=1):
        body = raw.split("#", 1)[0].strip()
        if body:
            rules.append(parse_rule(body, no))
    return rules


def _contains(outer: Interval, inner: Interval) -> bool:
    return outer[0] <= inner[0] and inner[1] <= outer[1]


def _overlaps(a: Interval, b: Interval) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]


def covers(a: Rule, b: Rule) -> bool:
    """True if every packet matched by ``b`` is also matched by ``a``."""
    return b.protos <= a.protos and all(
        _contains(x, y) for x, y in zip(a.dims(), b.dims()))


def intersects(a: Rule, b: Rule) -> bool:
    """True if at least one packet is matched by both rules."""
    return bool(a.protos & b.protos) and all(
        _overlaps(x, y) for x, y in zip(a.dims(), b.dims()))


def classify(earlier: Rule, later: Rule) -> Kind | None:
    """Relationship of ``later`` to an ``earlier`` rule, or None if unrelated."""
    if not intersects(earlier, later):
        return None
    same = earlier.action == later.action
    if covers(earlier, later):
        return Kind.REDUNDANT if same else Kind.SHADOWED
    if same:
        return None  # partial overlap with same action is harmless
    if covers(later, earlier):
        return Kind.GENERALIZATION
    return Kind.CONFLICT


def audit(rules: list[Rule], include_info: bool = False) -> list[Finding]:
    """Compare every ordered pair of rules and return all findings.

    GENERALIZATION findings (an exception followed by a broader opposite
    rule, e.g. a final default-deny) are normal style, so they are only
    reported when ``include_info`` is true.
    """
    findings: list[Finding] = []
    dead: set[int] = set()
    for j, later in enumerate(rules):
        for earlier in rules[:j]:
            if earlier.line in dead:
                continue  # a rule that never fires cannot interact
            kind = classify(earlier, later)
            if kind is None or (kind is Kind.GENERALIZATION and not include_info):
                continue
            msg = {
                Kind.SHADOWED: "never matches; line {o} already {a} all its traffic",
                Kind.REDUNDANT: "never matches; already covered by line {o} (same action)",
                Kind.CONFLICT: "partially overlaps line {o} with the opposite action",
                Kind.GENERALIZATION: "broader than line {o} with the opposite action",
            }[kind].format(o=earlier.line, a=VERB[earlier.action])
            findings.append(Finding(kind, later, earlier, msg))
            if kind in (Kind.SHADOWED, Kind.REDUNDANT):
                dead.add(later.line)
                break  # rule is dead; first cause is enough
    order = list(Kind)
    findings.sort(key=lambda f: (order.index(f.kind), f.rule.line))
    return findings


def render(rules: list[Rule], findings: list[Finding]) -> str:
    """Human-readable report."""
    out = [f"Audited {len(rules)} rules, {len(findings)} findings"]
    for f in findings:
        out.append(f"  [{f.kind.value:<14}] line {f.rule.line:>2}: {f.rule.text}")
        out.append(f"  {'':16} -> {f.message}")
    errors = sum(f.severity == "error" for f in findings)
    out.append(f"Result: {'FAIL' if errors else 'PASS'} ({errors} error(s))")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Audit first-match firewall rules.")
    ap.add_argument("rules", help="rule file")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--all", action="store_true",
                    help="also report GENERALIZATION findings")
    args = ap.parse_args(argv)
    try:
        with open(args.rules, encoding="utf-8") as fh:
            rules = parse_rules(fh.read())
    except (OSError, RuleParseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    findings = audit(rules, include_info=args.all)
    if args.json:
        print(json.dumps([{"kind": f.kind.value, "severity": f.severity,
                           "line": f.rule.line, "rule": f.rule.text,
                           "other_line": f.other.line, "message": f.message}
                          for f in findings], indent=2))
    else:
        print(render(rules, findings))
    return 1 if any(f.severity == "error" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())

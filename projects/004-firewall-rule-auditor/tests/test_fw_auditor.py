"""Tests for the firewall rule auditor."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import fw_auditor as fa  # noqa: E402


def r(text: str, line: int = 1) -> fa.Rule:
    return fa.parse_rule(text, line)


def kinds(source: str, **kw: bool) -> list[tuple[str, int]]:
    return [(f.kind.value, f.rule.line) for f in fa.audit(fa.parse_rules(source), **kw)]


def test_parse_any_expands_to_full_space() -> None:
    rule = r("allow any any any any")
    assert rule.protos == frozenset({"tcp", "udp"})
    assert rule.src == (0, 2**32 - 1)
    assert rule.ports == (0, 65535)


def test_parse_port_range_and_cidr() -> None:
    rule = r("deny tcp 10.0.0.0/30 any 1000-2000")
    assert rule.src[1] - rule.src[0] == 3
    assert rule.ports == (1000, 2000)


@pytest.mark.parametrize("bad", [
    "allow tcp any any",                 # too few fields
    "permit tcp any any 80",             # bad action
    "allow icmp any any 80",             # bad protocol
    "allow tcp 10.0.0.300/8 any 80",     # bad address
    "allow tcp any any 70000",           # port out of range
    "allow tcp any any 90-80",           # reversed range
])
def test_parse_errors(bad: str) -> None:
    with pytest.raises(fa.RuleParseError):
        r(bad)


def test_covers_and_intersects() -> None:
    wide = r("allow tcp 10.0.0.0/8 any any")
    narrow = r("deny tcp 10.1.2.0/24 any 22")
    other = r("deny udp 10.1.2.0/24 any 22")
    assert fa.covers(wide, narrow) and not fa.covers(narrow, wide)
    assert fa.intersects(wide, narrow)
    assert not fa.intersects(wide, other)  # protocol mismatch


def test_shadowed_rule_is_error() -> None:
    src = "deny tcp any 10.0.2.0/24 any\nallow tcp 10.0.5.0/24 10.0.2.0/24 5432\n"
    assert kinds(src) == [("SHADOWED", 2)]


def test_redundant_rule() -> None:
    src = "allow tcp any 10.0.1.0/24 443\nallow tcp any 10.0.1.10/32 443\n"
    assert kinds(src) == [("REDUNDANT", 2)]


def test_conflict_partial_overlap() -> None:
    src = "allow tcp any 10.0.1.0/24 443\ndeny any 192.168.0.0/16 10.0.1.0/24 any\n"
    assert kinds(src) == [("CONFLICT", 2)]


def test_generalization_hidden_by_default() -> None:
    src = "allow tcp any any 443\ndeny any any any any\n"
    assert kinds(src) == []
    assert kinds(src, include_info=True) == [("GENERALIZATION", 2)]


def test_disjoint_rules_clean() -> None:
    src = "allow tcp any any 80\nallow tcp any any 443\ndeny udp any any 53\n"
    assert kinds(src) == []


def test_dead_rules_do_not_create_followups() -> None:
    src = ("allow tcp any 10.0.1.0/24 443\n"
           "allow tcp any 10.0.1.10/32 443\n"          # dead
           "deny tcp 192.168.0.0/16 10.0.1.0/24 any\n")  # conflicts only with 1
    assert kinds(src) == [("REDUNDANT", 2), ("CONFLICT", 3)]


def test_comments_and_line_numbers() -> None:
    rules = fa.parse_rules("# header\n\nallow tcp any any 80  # web\n")
    assert len(rules) == 1 and rules[0].line == 3


def test_example_file_cli(capsys: pytest.CaptureFixture[str]) -> None:
    code = fa.main([str(ROOT / "examples" / "rules.txt")])
    out = capsys.readouterr().out
    assert code == 1
    assert "Audited 8 rules, 4 findings" in out
    assert "Result: FAIL (1 error(s))" in out


def test_cli_json_and_clean_exit(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "ok.txt"
    path.write_text("allow tcp any any 443\ndeny any any any any\n")
    assert fa.main([str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_cli_bad_file(tmp_path: Path) -> None:
    path = tmp_path / "bad.txt"
    path.write_text("allow tcp nowhere any 80\n")
    assert fa.main([str(path)]) == 2

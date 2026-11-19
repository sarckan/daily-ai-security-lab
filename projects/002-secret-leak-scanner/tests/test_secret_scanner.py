"""Tests for secret_scanner. Fake tokens are assembled at runtime so this
file itself does not look like it contains secrets."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import secret_scanner as ss  # noqa: E402

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def rules(text: str) -> list[str]:
    return [f.rule for f in ss.scan_text(text)]


def test_entropy_basics() -> None:
    assert ss.shannon_entropy("") == 0.0
    assert ss.shannon_entropy("aaaa") == 0.0
    assert ss.shannon_entropy("abcd") == pytest.approx(2.0)


def test_redact_never_shows_full_secret() -> None:
    secret = "q8Zt3LmX4vR9pN2wK7bY5cH1"
    preview = ss.redact(secret)
    assert secret not in preview
    assert preview.startswith("q8Zt") and "24 chars" in preview


def test_aws_key_detected() -> None:
    key = "AKIA" + "Q3EGZ7XRTN5WJ2LM"
    assert rules(f'aws_key = "{key}"') == ["aws_access_key_id"]


def test_github_token_detected() -> None:
    token = "ghp" + "_" + "a1B2c3D4" * 5
    assert "github_token" in rules(f"TOKEN={token}")


def test_private_key_header_detected() -> None:
    header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    found = ss.scan_text(header)
    assert found[0].rule == "private_key_block" and found[0].severity == "critical"


def test_url_password_detected() -> None:
    assert rules("url = 'https://bob:hunter2pass@example.org/x'") == ["url_with_password"]


def test_jwt_detected() -> None:
    jwt = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiIxMjMifQ" + ".abcdefghijKLMNOP"
    assert rules(f"auth_header = '{jwt}'") == ["jwt"]


def test_high_entropy_assignment_detected() -> None:
    assert rules('api_key = "q8Zt3LmX4vR9pN2wK7bY5cH1"') == ["secret_assignment"]


@pytest.mark.parametrize("line", [
    'password = "changeme123"',
    'api_key = "your_api_key_here"',
    'secret = "aaaaaaaaaaaa"',
    'token = "${TOKEN}"',
    'password = "password"',
])
def test_placeholders_and_low_entropy_ignored(line: str) -> None:
    assert rules(line) == []


def test_ignore_marker() -> None:
    assert rules('api_key = "q8Zt3LmX4vR9pN2wK7bY5cH1"  # secret-scan: ignore') == []


def test_specific_rule_wins_over_generic() -> None:
    key = "AKIA" + "Q3EGZ7XRTN5WJ2LM"
    assert rules(f'secret_key = "{key}"') == ["aws_access_key_id"]


def test_scan_path_skips_binary_and_git(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text('token = "q8Zt3LmX4vR9pN2wK7bY5cH1"')
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01AKIA" + b"Q3EGZ7XRTN5WJ2LM")
    (tmp_path / "app.py").write_text('api_key = "q8Zt3LmX4vR9pN2wK7bY5cH1"\n')
    found = ss.scan_path(tmp_path)
    assert [(Path(f.path).name, f.line) for f in found] == [("app.py", 1)]


def test_demo_example_findings() -> None:
    found = ss.scan_path(EXAMPLES)
    assert sorted(f.rule for f in found) == [
        "aws_access_key_id", "jwt", "secret_assignment", "url_with_password",
    ]


def test_filter_severity() -> None:
    found = ss.scan_path(EXAMPLES)
    assert {f.rule for f in ss.filter_severity(found, "critical")} == {"aws_access_key_id"}


def test_cli_exit_codes_and_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    clean = tmp_path / "clean.py"
    clean.write_text("TIMEOUT = 30\n")
    assert ss.main([str(clean)]) == 0
    assert "OK" in capsys.readouterr().out
    assert ss.main([str(EXAMPLES), "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 4 and all("…" in d["preview"] for d in data)

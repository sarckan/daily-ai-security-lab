"""Tests for the dependency pin auditor."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dep_auditor as da  # noqa: E402


def rules(text: str) -> list[tuple[str, int]]:
    return [(f.rule, f.line) for f in da.audit(text)]


def fake_hash(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def test_normalize_pep503() -> None:
    assert da.normalize("Py_YAML") == da.normalize("py.yaml") == "py-yaml"


@pytest.mark.parametrize(("a", "b", "d"), [
    ("requests", "requests", 0), ("reqeusts", "requests", 1),
    ("request", "requests", 1), ("numpyy", "numpy", 1), ("flask", "django", 5),
])
def test_edit_distance(a: str, b: str, d: int) -> None:
    assert da.edit_distance(a, b) == d


def test_pinned_with_hash_is_clean() -> None:
    assert rules(f"requests==2.32.3 --hash={fake_hash('r')}\n") == []


def test_unpinned_and_loose() -> None:
    found = rules("numpy\nflask>=2.0\ndjango~=4.2\nrich==13.*\nattrs==23.1,<24\n")
    assert ("UNPINNED", 1) in found
    assert [line for rule, line in found if rule == "LOOSE"] == [2, 3, 4, 5]


def test_typosquat_detected_but_real_names_ignored() -> None:
    assert ("TYPOSQUAT", 1) in rules("reqeusts==1.0\n")
    assert ("TYPOSQUAT", 1) in rules("Djangoo==4.2\n")
    assert all(r != "TYPOSQUAT" for r, _ in rules("requests==1.0\nurllib3==2.0\nsix==1.16\n"))


def test_vcs_refs() -> None:
    commit = "a" * 40
    assert ("VCS_MUTABLE", 1) in rules("git+https://github.com/o/r.git@main#egg=r\n")
    assert ("VCS_MUTABLE", 1) in rules("git+https://github.com/o/r.git#egg=r\n")
    assert ("VCS_MUTABLE", 1) in rules("-e git+https://github.com/o/r.git@v1.0#egg=r\n")
    assert "VCS_MUTABLE" not in [r for r, _ in rules(f"git+https://github.com/o/r.git@{commit}#egg=r\n")]
    assert ("VCS_MUTABLE", 1) in rules("toolkit @ git+https://github.com/o/r.git@dev\n")


def test_index_options() -> None:
    found = rules("--extra-index-url=http://mirror.example/simple\n--trusted-host mirror.example\n"
                  "-i https://pypi.org/simple\nrequests==2.32.3\n")
    assert ("EXTRA_INDEX", 1) in found and ("INSECURE_URL", 1) in found
    assert ("TRUSTED_HOST", 2) in found
    assert not any(line == 3 for _, line in found)


def test_http_package_url() -> None:
    assert ("INSECURE_URL", 1) in rules("pkg @ http://files.example/pkg-1.0.whl\n")


def test_duplicate_is_case_and_separator_insensitive() -> None:
    assert ("DUPLICATE", 2) in rules("Typing_Extensions==4.12.2\ntyping.extensions==4.12.2\n")


def test_hash_consistency() -> None:
    text = f"requests==2.32.3 \\\n    --hash={fake_hash('a')}\nflask==3.0.3\n"
    found = rules(text)
    assert ("MISSING_HASH", 3) in found
    assert "NO_HASHES" not in [r for r, _ in found]
    assert ("NO_HASHES", 0) in rules("flask==3.0.3\n")


def test_comments_and_markers_ignored() -> None:
    text = "# comment\nrequests==2.32.3  # inline\ncolorama==0.4.6 ; sys_platform == 'win32'\n"
    assert rules(text) == [("NO_HASHES", 0)]


def test_score_and_grade() -> None:
    assert da.score([]) == (100, "A")
    f = [da.Finding("UNPINNED", 1, "x", ""), da.Finding("LOOSE", 2, "y", "")]
    assert da.score(f) == (78, "B")
    assert da.score([da.Finding("UNPINNED", 1, "x", "")] * 10) == (0, "F")


def test_example_file_matches_readme() -> None:
    text = (ROOT / "examples" / "requirements.txt").read_text()
    findings = da.audit(text)
    assert len(findings) == 8
    assert da.score(findings) == (17, "F")
    clean = da.audit((ROOT / "examples" / "requirements-clean.txt").read_text())
    assert clean == []


def test_cli_exit_codes_and_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "req.txt"
    bad.write_text("numpy\n")
    assert da.main([str(bad)]) == 1
    good = tmp_path / "ok.txt"
    good.write_text("numpy==2.1.3\n")
    capsys.readouterr()
    assert da.main([str(good), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["score"] == 98 and payload["findings"][0]["rule"] == "NO_HASHES"
    assert da.main([str(tmp_path / "missing.txt")]) == 2

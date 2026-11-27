"""Tests for the password strength auditor. Passwords are built at runtime."""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import password_auditor as pa  # noqa: E402


def patterns(pw: str, **kw) -> list[str]:
    return [m.pattern for m in pa.audit(pw, **kw).segments]


def test_common_password_with_leet_and_year_is_found():
    pw = "P@ssw0rd" + "2024" + "!"
    r = pa.audit(pw)
    assert patterns(pw) == ["common_password", "year", "bruteforce"]
    assert r.score <= 2
    assert any(w.startswith("COMMON_PASSWORD") for w in r.warnings)
    assert "l33t" in r.segments[0].detail


def test_keyboard_walk_detected():
    ms = pa.keyboard_matches("xx" + "asdfg" + "yy")
    assert any(m.token == "asdfg" for m in ms)


def test_sequences_both_directions():
    toks = {m.token: m.detail for m in pa.sequence_matches("a" + "4567" + "b" + "zyx")}
    assert toks["4567"] == "ascending"
    assert toks["zyx"] == "descending"


def test_repeat_block():
    pw = "abc" * 3
    m = pa.repeat_matches(pw)[0]
    assert m.token == pw and m.detail == "'abc' x3"


def test_dates_and_years():
    kinds = {m.pattern for m in pa.date_matches("x31121990y")}
    assert {"year", "date"} <= kinds
    assert not pa.date_matches("1850")


def test_user_input_penalised():
    r = pa.audit("sarkhan" + "1990", user_inputs=["sarkhan"])
    assert r.segments[0].pattern == "user_input"
    assert any(w.startswith("PERSONAL_INFO") for w in r.warnings)
    assert r.score == 0


def test_random_string_is_strong_and_one_chunk():
    pw = "k9#Tm2!" + "vQx8@Lp"
    r = pa.audit(pw)
    assert r.score == 4
    assert len(r.segments) == 1 and r.segments[0].pattern == "bruteforce"


def test_segments_cover_password_exactly():
    pw = "Summer" + "1990" + "qwerty" + "!!"
    r = pa.audit(pw)
    assert "".join(m.token for m in r.segments) == pw
    assert r.segments[0].i == 0 and r.segments[-1].j == len(pw) - 1


def test_dp_never_worse_than_bruteforce():
    pw = "dragon" + "dragon"
    log_g, _ = pa.cheapest_path(pw, pa.all_matches(pw))
    assert log_g <= math.log10(pa.bruteforce_guesses(pw))


def test_case_factor():
    assert pa._case_factor("summer") == 1
    assert pa._case_factor("Summer") == 2
    assert pa._case_factor("SUMMER") == 2
    assert pa._case_factor("sUmMeR") == 8


def test_score_monotonic_with_thresholds():
    weak = pa.audit("qwerty" + "123")
    strong = pa.audit("correct-horse-battery-staple")
    assert weak.score < strong.score
    assert strong.label == "very strong"


def test_short_warning_respects_min_length():
    assert any(w.startswith("SHORT") for w in pa.audit("abc", min_length=12).warnings)
    assert not any(w.startswith("SHORT") for w in pa.audit("abc", min_length=3).warnings)


def test_empty_password_rejected():
    with pytest.raises(ValueError):
        pa.audit("")


def test_human_time():
    assert pa.human_time(0.5) == "instant"
    assert pa.human_time(1) == "1 second"
    assert pa.human_time(3600) == "1 hour"
    assert pa.human_time(1e12) == "centuries+"


def test_cli_exit_codes_and_json(capsys):
    assert pa.main(["k9#Tm2!" + "vQx8@Lp"]) == 0
    capsys.readouterr()
    assert pa.main(["--json", "qwerty" + "123"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data[0]["score"] == 0
    assert pa.main([]) == 2


def test_cli_mask_hides_password(capsys):
    secret = "Summer" + "1990"
    pa.main(["--mask", secret])
    out = capsys.readouterr().out
    assert secret not in out and "S********0" in out

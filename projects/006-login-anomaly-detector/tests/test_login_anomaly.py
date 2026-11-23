"""Tests for the login anomaly detector."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import login_anomaly as la  # noqa: E402

T0 = datetime(2026, 11, 1, 9, 0)


def history(user: str = "alice", ip: str = "192.0.2.10", days: int = 6) -> list[la.Event]:
    """A user logging in at ~09:00 from the same /24 every day."""
    return [la.Event(T0 + timedelta(days=d, minutes=d), user, ip, True) for d in range(days)]


def run(events: list[la.Event], threshold: int = 1) -> list[la.Finding]:
    return la.analyse(events, threshold)[0]


def rules(f: la.Finding) -> set[str]:
    return {r.split(":")[0] for r in f.reasons}


def test_subnet_of_ipv4_and_ipv6() -> None:
    assert la.subnet_of("192.0.2.77") == "192.0.2.0/24"
    assert la.subnet_of("2001:db8:abcd:12::1") == "2001:db8:abcd::/48"


def test_normal_history_is_quiet() -> None:
    assert run(history()) == []


def test_new_subnet_and_odd_hour() -> None:
    ev = la.Event(T0 + timedelta(days=7, hours=-6), "alice", "203.0.113.9", True)
    (f,) = run(history() + [ev])
    assert rules(f) == {"NEW_SUBNET", "ODD_HOUR"}
    assert f.score == 50 and f.level == "MEDIUM"


def test_same_subnet_usual_hour_not_flagged() -> None:
    ev = la.Event(T0 + timedelta(days=7, minutes=30), "alice", "192.0.2.99", True)
    assert run(history() + [ev]) == []


def test_cold_start_skips_profile_rules() -> None:
    events = history(days=3) + [la.Event(T0 + timedelta(days=4, hours=-7), "alice", "203.0.113.9", True)]
    assert run(events) == []


def test_hour_window_wraps_midnight() -> None:
    det = la.Detector()
    prof = det.users["night"]
    prof.hours[23] = 4
    prof.logins = 4
    assert det.hour_share(prof, 0) == 1.0


def test_fail_burst_then_success_after_fail() -> None:
    t = T0 + timedelta(days=7)
    fails = [la.Event(t + timedelta(seconds=10 * k), "alice", "192.0.2.10", False) for k in range(5)]
    ok = la.Event(t + timedelta(minutes=2), "alice", "192.0.2.10", True)
    found = run(history() + fails + [ok])
    assert rules(found[0]) == {"FAIL_BURST"}
    assert "SUCCESS_AFTER_FAIL" in rules(found[-1])


def test_old_failures_expire() -> None:
    t = T0 + timedelta(days=7)
    fails = [la.Event(t + timedelta(seconds=k), "alice", "192.0.2.10", False) for k in range(4)]
    ok = la.Event(t + timedelta(minutes=30), "alice", "192.0.2.10", True)
    assert run(history() + fails + [ok], threshold=25) == []


def test_password_spray() -> None:
    t = T0 + timedelta(days=7)
    evs = [la.Event(t + timedelta(seconds=k), u, "203.0.113.50", False)
           for k, u in enumerate(["a", "b", "c"])]
    found = run(evs)
    assert len(found) == 1 and rules(found[0]) == {"PASSWORD_SPRAY"}


def test_score_capped_and_levels() -> None:
    assert la.level_for(100) == "HIGH"
    assert la.level_for(60) == "HIGH"
    assert la.level_for(25) == "MEDIUM"
    assert la.level_for(24) == "LOW"


def test_unsorted_input_is_scored_in_time_order() -> None:
    evs = list(reversed(history()))
    assert run(evs) == []


def test_demo_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = tmp_path / "auth.csv"
    assert la.main([str(log), "--make-demo"]) == 0
    assert la.main([str(log)]) == 1
    out = capsys.readouterr().out
    assert "8 flagged" in out and "SUCCESS_AFTER_FAIL" in out
    assert la.main([str(log), "--json", "--threshold", "60"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert [f["user"] for f in data["findings"]] == ["bob"]
    assert data["findings"][0]["score"] == 80


def test_demo_is_deterministic(tmp_path: Path) -> None:
    a, b = tmp_path / "a.csv", tmp_path / "b.csv"
    la.make_demo(a)
    la.make_demo(b)
    assert a.read_text() == b.read_text()


def test_bad_input_returns_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.csv"
    bad.write_text("when,who\n1,2\n")
    assert la.main([str(bad)]) == 2
    assert la.main([str(tmp_path / "missing.csv")]) == 2

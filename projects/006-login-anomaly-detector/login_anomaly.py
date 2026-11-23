"""Login anomaly detector: learns each user's normal sign-in pattern from an
auth log and scores every event for account-takeover signals.

The detector reads events in time order and *learns online*: each event is
scored only against what came before it, then folded into the baseline. That
means it needs no separate training file and never "sees the future".

Signals
-------
================  ======  ==================================================
NEW_SUBNET          30    successful login from a /24 the user never used
ODD_HOUR            20    login hour (+-1h) seen in < 5% of past logins
FAIL_BURST          25    >= 5 failed attempts on the user in 10 minutes
SUCCESS_AFTER_FAIL  30    success right after >= 3 failures (brute force?)
PASSWORD_SPRAY      25    one IP failing against >= 3 users in 10 minutes
================  ======  ==================================================

NEW_SUBNET and ODD_HOUR need at least 5 past successful logins (cold start).
Risk = sum of fired weights, capped at 100: HIGH >= 60, MEDIUM >= 25.

Usage:
    python login_anomaly.py examples/auth_log.csv
    python login_anomaly.py examples/auth_log.csv --json
    python login_anomaly.py --make-demo examples/auth_log.csv
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import random
import sys
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

WEIGHTS: dict[str, int] = {
    "NEW_SUBNET": 30,
    "ODD_HOUR": 20,
    "FAIL_BURST": 25,
    "SUCCESS_AFTER_FAIL": 30,
    "PASSWORD_SPRAY": 25,
}
MIN_HISTORY = 5          # successful logins before per-user signals apply
ODD_HOUR_RATIO = 0.05    # share of past logins within +-1h of this hour
WINDOW = timedelta(minutes=10)
BURST_FAILS = 5
SUCCESS_AFTER_FAILS = 3
SPRAY_USERS = 3
HIGH, MEDIUM = 60, 25


@dataclass(frozen=True)
class Event:
    """One authentication attempt."""

    ts: datetime
    user: str
    ip: str
    success: bool


@dataclass
class Finding:
    """A scored event with the reasons behind the score."""

    line: int
    ts: str
    user: str
    ip: str
    success: bool
    score: int
    level: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class UserProfile:
    """What 'normal' looks like for one user (built from successful logins)."""

    hours: Counter[int] = field(default_factory=Counter)
    subnets: set[str] = field(default_factory=set)
    logins: int = 0
    recent_fails: deque[datetime] = field(default_factory=deque)


def subnet_of(ip: str) -> str:
    """Return the /24 (IPv4) or /48 (IPv6) network an address belongs to."""
    addr = ipaddress.ip_address(ip)
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def parse_log(path: Path) -> list[Event]:
    """Read a CSV with header ``timestamp,user,ip,success``."""
    events: list[Event] = []
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            events.append(Event(
                ts=datetime.fromisoformat(row["timestamp"]),
                user=row["user"].strip().lower(),
                ip=row["ip"].strip(),
                success=row["success"].strip().lower() in {"1", "true", "yes", "ok"},
            ))
    return events


def _prune(q: deque, now: datetime) -> None:
    """Drop entries (timestamps or (timestamp, ...) tuples) older than WINDOW."""
    def ts(item: object) -> datetime:
        return item[0] if isinstance(item, tuple) else item  # type: ignore[return-value]
    while q and now - ts(q[0]) > WINDOW:
        q.popleft()


def level_for(score: int) -> str:
    """Map a 0-100 risk score to LOW / MEDIUM / HIGH."""
    return "HIGH" if score >= HIGH else "MEDIUM" if score >= MEDIUM else "LOW"


class Detector:
    """Online, explainable anomaly scorer for authentication events."""

    def __init__(self) -> None:
        self.users: dict[str, UserProfile] = defaultdict(UserProfile)
        self.ip_fails: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)

    def hour_share(self, prof: UserProfile, hour: int) -> float:
        """Share of past logins within +-1 hour of ``hour`` (circular)."""
        near = sum(prof.hours[(hour + d) % 24] for d in (-1, 0, 1))
        return near / prof.logins if prof.logins else 0.0

    def score(self, ev: Event) -> tuple[int, list[str]]:
        """Score ``ev`` against history, then learn from it."""
        prof = self.users[ev.user]
        reasons: list[str] = []
        _prune(prof.recent_fails, ev.ts)
        ip_q = self.ip_fails[ev.ip]
        _prune(ip_q, ev.ts)

        if ev.success:
            if prof.logins >= MIN_HISTORY:
                net = subnet_of(ev.ip)
                if net not in prof.subnets:
                    reasons.append(f"NEW_SUBNET: {net} never used by {ev.user}")
                share = self.hour_share(prof, ev.ts.hour)
                if share < ODD_HOUR_RATIO:
                    reasons.append(
                        f"ODD_HOUR: {ev.ts:%H:%M} matches {share:.0%} of past logins")
            fails = len(prof.recent_fails)
            if fails >= SUCCESS_AFTER_FAILS:
                reasons.append(f"SUCCESS_AFTER_FAIL: success after {fails} failures")
        else:
            prof.recent_fails.append(ev.ts)
            ip_q.append((ev.ts, ev.user))
            fails = len(prof.recent_fails)
            if fails >= BURST_FAILS:
                reasons.append(f"FAIL_BURST: {fails} failures in 10 min")
            targets = {u for _, u in ip_q}
            if len(targets) >= SPRAY_USERS:
                reasons.append(f"PASSWORD_SPRAY: {ev.ip} tried {len(targets)} users")

        total = min(100, sum(WEIGHTS[r.split(":")[0]] for r in reasons))
        if ev.success:  # learn only from successful logins
            prof.hours[ev.ts.hour] += 1
            prof.subnets.add(subnet_of(ev.ip))
            prof.logins += 1
            prof.recent_fails.clear()
        return total, reasons


def analyse(events: list[Event], threshold: int = MEDIUM) -> tuple[list[Finding], int]:
    """Score all events in time order; return findings >= threshold and the total."""
    det = Detector()
    out: list[Finding] = []
    order = sorted(range(len(events)), key=lambda i: events[i].ts)
    for i in order:
        ev = events[i]
        score, reasons = det.score(ev)
        if score >= threshold:
            out.append(Finding(i + 2, ev.ts.isoformat(sep=" "), ev.user, ev.ip,
                               ev.success, score, level_for(score), reasons))
    return out, len(events)


def make_demo(path: Path, seed: int = 7) -> None:
    """Write a deterministic synthetic log: 14 normal days plus 3 attacks."""
    rng = random.Random(seed)
    homes = {"alice": ("192.0.2.", 9), "bob": ("198.51.100.", 10), "carol": ("192.0.2.", 13)}
    rows: list[tuple[datetime, str, str, bool]] = []
    start = datetime(2026, 11, 9)
    for day in range(14):
        for user, (net, hour) in homes.items():
            ts = start + timedelta(days=day, hours=hour + rng.randint(-1, 1),
                                   minutes=rng.randint(0, 59))
            ip = net + str(rng.randint(10, 40))
            if rng.random() < 0.1:  # a normal typo first
                rows.append((ts - timedelta(seconds=30), user, ip, False))
            rows.append((ts, user, ip, True))
    attack = datetime(2026, 11, 23, 2, 40)
    for k, user in enumerate(["alice", "bob", "carol", "dave", "erin"]):  # spray
        rows.append((attack + timedelta(seconds=20 * k), user, "203.0.113.50", False))
    for k in range(6):  # brute force on bob, then it works
        rows.append((attack + timedelta(minutes=5, seconds=15 * k), "bob", "203.0.113.77", False))
    rows.append((attack + timedelta(minutes=7), "bob", "203.0.113.77", True))
    rows.append((attack + timedelta(minutes=32), "alice", "203.0.113.9", True))  # takeover
    rows.sort()
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "user", "ip", "success"])
        for ts, user, ip, ok in rows:
            w.writerow([ts.isoformat(), user, ip, "true" if ok else "false"])


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Exit 1 if any HIGH event, 2 on input error."""
    ap = argparse.ArgumentParser(description="Score auth logs for account-takeover signals.")
    ap.add_argument("log", type=Path, help="CSV: timestamp,user,ip,success")
    ap.add_argument("--threshold", type=int, default=MEDIUM, help="minimum score to report")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--make-demo", action="store_true", help="write a demo log to LOG and exit")
    args = ap.parse_args(argv)
    if args.make_demo:
        make_demo(args.log)
        print(f"Wrote demo log to {args.log}")
        return 0
    try:
        events = parse_log(args.log)
    except (OSError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    findings, total = analyse(events, args.threshold)
    high = sum(f.level == "HIGH" for f in findings)
    if args.json:
        print(json.dumps({"events": total, "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        print(f"Scanned {total} events from {len({e.user for e in events})} users: "
              f"{len(findings)} flagged")
        for f in findings:
            status = "OK  " if f.success else "FAIL"
            print(f"  [{f.level:<6} {f.score:>3}] {f.ts[5:16]} {f.user:<6} {f.ip:<13} {status}")
            for r in f.reasons:
                print(f"      - {r}")
        print(f"Verdict: {'ALERT' if high else 'OK'} ({high} high-risk event(s))")
    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())

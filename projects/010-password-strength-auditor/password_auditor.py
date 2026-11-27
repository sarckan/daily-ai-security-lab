#!/usr/bin/env python3
"""Password Strength Auditor: estimate how many guesses a smart attacker needs.

Instead of counting character classes ("has a digit, has a symbol"), the
auditor finds the *patterns* a cracker would try first (common passwords and
words, l33t substitutions, keyboard walks, sequences, repeats, years and
dates), then uses dynamic programming to find the cheapest way to build the
whole password out of those patterns plus brute-force chunks. The product of
the guesses along that cheapest path is the strength estimate.

Standard library only. Defensive / educational use: audit your own passwords
or a policy, never someone else's account.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import asdict, dataclass

# Ranked lists: rank r means "the r-th thing an attacker tries".
COMMON_PASSWORDS = (
    "123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 "
    "dragon 123123 baseball abc123 football monkey letmein shadow master "
    "666666 qwertyuiop 123321 mustang 1234567890 michael 654321 superman "
    "1qaz2wsx 7777777 121212 000000 qazwsx 123qwe killer trustno1 jordan "
    "jennifer zxcvbnm asdfgh hunter buster soccer harley batman andrew "
    "tigger sunshine iloveyou 2000 charlie robert thomas hockey ranger "
    "daniel starwars klaster 112233 george computer michelle jessica pepper "
    "1111 zxcvbn 555555 11111111 131313 freedom 777777 pass maggie 159753 "
    "aaaaaa ginger princess joshua cheese amanda summer love ashley nicole "
    "chelsea biteme matthew access yankees 987654321 dallas austin thunder "
    "taylor matrix admin welcome login secret"
).split()
COMMON_WORDS = (
    "the love summer winter spring autumn dragon monkey tiger lion eagle "
    "orange apple banana cherry coffee pizza music money power magic secret "
    "company office server cloud linux python java warsaw london paris "
    "football soccer hockey family friend happy angel heaven sunshine star "
    "moon flower purple silver golden black white blue green red house "
    "horse rabbit cookie chocolate november december january february "
    "march april june july august october sarkhan security"
).split()

LEET = {"4": "a", "@": "a", "8": "b", "(": "c", "3": "e", "6": "g", "1": "i",
        "!": "i", "|": "l", "0": "o", "$": "s", "5": "s", "7": "t", "+": "t",
        "2": "z"}
KEYBOARD_ROWS = ("`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./")
SCORE_THRESHOLDS = (3, 6, 8, 10)  # log10(guesses) cut-offs for scores 1..4
LABELS = ("very weak", "weak", "fair", "strong", "very strong")
ATTACKS = {  # guesses per second
    "online, throttled (100/h)": 100 / 3600,
    "offline, slow hash (10k/s)": 1e4,
    "offline, fast hash (10B/s)": 1e10,
}


@dataclass
class Match:
    """A substring password[i:j+1] explained by one pattern."""
    pattern: str
    i: int
    j: int
    token: str
    guesses: float
    detail: str = ""


def _ranked(words: list[str]) -> dict[str, int]:
    ranks: dict[str, int] = {}
    for r, w in enumerate(words, 1):
        ranks.setdefault(w.lower(), r)
    return ranks


def _case_factor(token: str) -> int:
    """Extra guesses for capitalisation (first-upper or all-upper are cheap)."""
    if token.islower() or not any(c.isalpha() for c in token):
        return 1
    if token[0].isupper() and token[1:].islower() or token.isupper():
        return 2
    return 2 ** min(sum(c.isupper() for c in token), 8)


def dictionary_matches(pw: str, user_inputs: list[str]) -> list[Match]:
    """Common passwords, words and user inputs: plain, l33t and reversed."""
    dicts = {
        "user_input": _ranked([u for u in user_inputs if len(u) >= 3]),
        "common_password": _ranked(COMMON_PASSWORDS),
        "word": _ranked(COMMON_WORDS),
    }
    out: list[Match] = []
    n = len(pw)
    for i in range(n):
        for j in range(i + 2, n):
            tok = pw[i:j + 1]
            low = tok.lower()
            subs = sum(1 for c in low if c in LEET)
            unleet = "".join(LEET.get(c, c) for c in low)
            for name, ranks in dicts.items():
                for cand, extra, how in ((low, 1, ""), (unleet, 2 ** subs, "l33t"),
                                         (low[::-1], 2, "reversed")):
                    if cand in ranks and (how != "l33t" or subs):
                        g = max(ranks[cand], 1) * extra * _case_factor(tok)
                        out.append(Match(name, i, j, tok, float(g),
                                         f"{cand} rank {ranks[cand]}" + (f", {how}" if how else "")))
    return out


def keyboard_matches(pw: str) -> list[Match]:
    """Runs of >=3 keys that are neighbours on one QWERTY row (either way)."""
    out: list[Match] = []
    low = pw.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(low)):
            j = i
            while j + 1 < len(low) and low[j] in row and low[j + 1] in row and \
                    abs(row.index(low[j + 1]) - row.index(low[j])) == 1:
                j += 1
            if j - i + 1 >= 3:
                out.append(Match("keyboard", i, j, pw[i:j + 1], 47.0 * 2 * (j - i + 1),
                                 f"row '{row[:4]}...' walk"))
    return out


def sequence_matches(pw: str) -> list[Match]:
    """abc, 4567, zyx: constant +/-1 steps in character code."""
    out: list[Match] = []
    i = 0
    while i < len(pw) - 2:
        step = ord(pw[i + 1]) - ord(pw[i])
        j = i + 1
        while step in (1, -1) and j + 1 < len(pw) and ord(pw[j + 1]) - ord(pw[j]) == step:
            j += 1
        if step in (1, -1) and j - i + 1 >= 3:
            base = 10 if pw[i].isdigit() else 26
            out.append(Match("sequence", i, j, pw[i:j + 1],
                             float(base * (j - i + 1) * (2 if step < 0 else 1)),
                             "ascending" if step > 0 else "descending"))
            i = j
        else:
            i += 1
    return out


def repeat_matches(pw: str) -> list[Match]:
    """aaaa or abcabcabc: a block repeated two or more times."""
    out: list[Match] = []
    for m in re.finditer(r"(.+?)\1+", pw):
        block, tok = m.group(1), m.group(0)
        if len(tok) >= 3:
            g = bruteforce_guesses(block) * (len(tok) // len(block))
            out.append(Match("repeat", m.start(), m.end() - 1, tok, float(g),
                             f"'{block}' x{len(tok) // len(block)}"))
    return out


def date_matches(pw: str) -> list[Match]:
    """Years 1900-2039 and 6/8-digit dates like 31121990 or 1990-12-31."""
    out: list[Match] = []
    for m in re.finditer(r"(?=((?:19|20)\d\d))", pw):
        if 1900 <= int(m.group(1)) <= 2039:
            out.append(Match("year", m.start(), m.start() + 3, m.group(1), 140.0, "1900-2039"))
    for m in re.finditer(r"(?=(\d{1,2}[-/.]?\d{1,2}[-/.]?(?:19|20)?\d\d))", pw):
        tok = m.group(1)
        if len(re.sub(r"\D", "", tok)) >= 6:
            out.append(Match("date", m.start(), m.start() + len(tok) - 1, tok,
                             365.0 * 140, "day-month-year"))
    return out


def charset_size(pw: str) -> int:
    """Size of the alphabet an attacker must brute-force for this password."""
    cs = 10 if any(c.isdigit() for c in pw) else 0
    cs += 26 if any(c.islower() for c in pw) else 0
    cs += 26 if any(c.isupper() for c in pw) else 0
    cs += 33 if any(not c.isalnum() for c in pw) else 0
    return max(cs, 10)


def bruteforce_guesses(token: str, charset: int | None = None) -> float:
    """Charset size ** length for an unexplained chunk."""
    return float((charset or charset_size(token)) ** len(token))


def all_matches(pw: str, user_inputs: list[str] | None = None) -> list[Match]:
    return (dictionary_matches(pw, user_inputs or []) + keyboard_matches(pw)
            + sequence_matches(pw) + repeat_matches(pw) + date_matches(pw))


def cheapest_path(pw: str, matches: list[Match]) -> tuple[float, list[Match]]:
    """DP: best[k] = fewest log10-guesses to explain pw[:k]."""
    n = len(pw)
    cs = charset_size(pw)
    best = [0.0] + [math.inf] * n
    back: list[Match | None] = [None] * (n + 1)
    by_end: dict[int, list[Match]] = {}
    for m in matches:
        by_end.setdefault(m.j, []).append(m)
    for k in range(1, n + 1):
        cands = list(by_end.get(k - 1, []))
        cands += [Match("bruteforce", i, k - 1, pw[i:k], bruteforce_guesses(pw[i:k], cs))
                  for i in range(k)]
        for m in cands:
            cost = best[m.i] + math.log10(max(m.guesses, 1.0))
            if cost < best[k]:
                best[k], back[k] = cost, m
    path: list[Match] = []
    k = n
    while k > 0:
        m = back[k]
        assert m is not None
        path.append(m)
        k = m.i
    path.reverse()
    merged: list[Match] = []  # glue neighbouring brute-force chunks together
    for m in path:
        if merged and m.pattern == merged[-1].pattern == "bruteforce":
            p = merged[-1]
            merged[-1] = Match("bruteforce", p.i, m.j, p.token + m.token, p.guesses * m.guesses)
        else:
            merged.append(m)
    path = merged
    # Attackers also have to guess how many pieces there are: +log10(pieces!).
    return best[n] + math.log10(math.factorial(len(path))), path


def human_time(seconds: float) -> str:
    if seconds < 1:
        return "instant"
    for unit, size in (("centuries", 3.15e9), ("years", 3.15e7), ("days", 86400),
                       ("hours", 3600), ("minutes", 60)):
        if seconds >= size:
            return "centuries+" if unit == "centuries" and seconds >= 3.15e9 else \
                f"{seconds / size:.0f} {unit if round(seconds / size) != 1 else unit[:-1]}"
    return f"{seconds:.0f} second" + ("s" if round(seconds) != 1 else "")


@dataclass
class Report:
    length: int
    log10_guesses: float
    score: int
    label: str
    segments: list[Match]
    crack_times: dict[str, str]
    warnings: list[str]


def audit(pw: str, user_inputs: list[str] | None = None, min_length: int = 12) -> Report:
    if not pw:
        raise ValueError("empty password")
    log_g, path = cheapest_path(pw, all_matches(pw, user_inputs))
    score = sum(log_g >= t for t in SCORE_THRESHOLDS)
    warnings: list[str] = []
    if len(pw) < min_length:
        warnings.append(f"SHORT: {len(pw)} chars, policy wants >= {min_length}")
    kinds = {m.pattern for m in path}
    if "common_password" in kinds:
        warnings.append("COMMON_PASSWORD: contains a top-100 password")
    if "user_input" in kinds:
        warnings.append("PERSONAL_INFO: contains your username/name/email part")
    if kinds & {"keyboard", "sequence", "repeat"}:
        warnings.append("PREDICTABLE_PATTERN: keyboard walk, sequence or repeat")
    if kinds & {"year", "date"}:
        warnings.append("DATE: years and birthdays are guessed early")
    times = {k: human_time(10 ** log_g / v) for k, v in ATTACKS.items()}
    return Report(len(pw), round(log_g, 2), score, LABELS[score], path, times, warnings)


def mask(pw: str) -> str:
    return pw if len(pw) <= 2 else pw[0] + "*" * (len(pw) - 2) + pw[-1]


def format_report(pw: str, r: Report, show: bool = True) -> str:
    lines = [f"Password: {pw if show else mask(pw)}  ({r.length} chars)",
             f"Score {r.score}/4 ({r.label})  ~10^{r.log10_guesses:.1f} guesses"]
    for m in r.segments:
        tok = m.token if show else mask(m.token)
        lines.append(f"  [{m.pattern:<15}] {tok:<16} 10^{math.log10(max(m.guesses, 1)):.1f}"
                     + (f"  {m.detail}" if m.detail and show else ""))
    lines += [f"  {k:<27} {v}" for k, v in r.crack_times.items()]
    lines += [f"  ! {w}" for w in r.warnings]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("passwords", nargs="*", help="passwords to audit (prefer --stdin)")
    ap.add_argument("--stdin", action="store_true", help="read one password per line from stdin")
    ap.add_argument("--user", action="append", default=[], help="username/name/email to penalise")
    ap.add_argument("--min-score", type=int, default=3, help="exit 1 if any score is below this")
    ap.add_argument("--min-length", type=int, default=12)
    ap.add_argument("--mask", action="store_true", help="hide password characters in output")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    pws = list(a.passwords) + ([l.rstrip("\n") for l in sys.stdin if l.strip()] if a.stdin else [])
    if not pws:
        ap.print_usage(sys.stderr)
        return 2
    users = [p for u in a.user for p in re.split(r"[@._\-\s]+", u.lower()) if p]
    reports = [audit(p, users, a.min_length) for p in pws]
    if a.json:
        print(json.dumps([asdict(r) for r in reports], indent=2))
    else:
        print("\n\n".join(format_report(p, r, not a.mask) for p, r in zip(pws, reports)))
    return 1 if any(r.score < a.min_score for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())

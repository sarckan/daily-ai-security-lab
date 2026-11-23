# 006 · Login Anomaly Detector

▶ **Watch the 30-second demo:** [demo.mp4](demo.mp4)

**Category:** AI/ML · **Language:** Python 3.11+ (standard library only)

Reads an authentication log and learns what "normal" looks like for every user: which networks they sign in from and at what time of day. Each new event is scored against that baseline plus a few rate signals (failure bursts, success right after failures, one IP spraying many accounts). Every flagged event gets a 0–100 risk score and the plain-English reasons behind it.

## Why it matters

Most account takeovers don't look like an exploit. They look like a *valid login*: the right password, just from a network the user has never touched, at 3 a.m., a minute after six failed attempts. Static rules ("alert on 5 failures") miss the login that finally works, and black-box ML models can't tell an analyst *why* they fired. A small per-user baseline with explainable signals catches the pattern and tells you exactly what was unusual.

## How it works

1. **Parse** a CSV with header `timestamp,user,ip,success` and sort it by time.
2. **Learn online.** Events are processed in order. Each one is scored only against what came *before* it, then (if it was a successful login) folded into that user's profile: an hour-of-day histogram and the set of /24 (IPv4) or /48 (IPv6) networks they used. No training file, no peeking at the future.
3. **Score five signals:**

   | Signal | Weight | Fires when |
   |---|---|---|
   | `NEW_SUBNET` | 30 | successful login from a /24 the user has never used |
   | `ODD_HOUR` | 20 | fewer than 5% of past logins fall within ±1 h of this hour (wraps midnight) |
   | `FAIL_BURST` | 25 | ≥ 5 failed attempts on the user within 10 minutes |
   | `SUCCESS_AFTER_FAIL` | 30 | a success right after ≥ 3 failures within 10 minutes |
   | `PASSWORD_SPRAY` | 25 | one IP failing against ≥ 3 different users within 10 minutes |

   `NEW_SUBNET` and `ODD_HOUR` only apply once a user has ≥ 5 successful logins (cold start).
4. **Risk** = sum of fired weights, capped at 100. `HIGH` ≥ 60, `MEDIUM` ≥ 25. Events at or above `--threshold` (default 25) are reported.
5. **Exit code** `1` if any HIGH event was found, `2` if the log can't be read, `0` otherwise, so it drops straight into a cron job or CI check.

## How to run

```bash
python login_anomaly.py examples/auth_log.csv
python login_anomaly.py examples/auth_log.csv --threshold 60   # only HIGH
python login_anomaly.py examples/auth_log.csv --json           # machine-readable
python login_anomaly.py --make-demo my_log.csv                 # regenerate the demo log
python -m pytest -q                                            # run the tests
```

`examples/auth_log.csv` is synthetic (documentation IP ranges from RFC 5737): two weeks of normal logins for alice, bob and carol, then a password spray from `203.0.113.50`, a brute force on bob from `203.0.113.77` that finally succeeds, and a 03:12 login to alice's account from a new network.

## Example output

```text
$ python login_anomaly.py examples/auth_log.csv
Scanned 58 events from 5 users: 8 flagged
  [MEDIUM  25] 11-23 02:40 carol  203.0.113.50  FAIL
      - PASSWORD_SPRAY: 203.0.113.50 tried 3 users
  [MEDIUM  25] 11-23 02:41 dave   203.0.113.50  FAIL
      - PASSWORD_SPRAY: 203.0.113.50 tried 4 users
  [MEDIUM  25] 11-23 02:41 erin   203.0.113.50  FAIL
      - PASSWORD_SPRAY: 203.0.113.50 tried 5 users
  [MEDIUM  25] 11-23 02:45 bob    203.0.113.77  FAIL
      - FAIL_BURST: 5 failures in 10 min
  [MEDIUM  25] 11-23 02:46 bob    203.0.113.77  FAIL
      - FAIL_BURST: 6 failures in 10 min
  [MEDIUM  25] 11-23 02:46 bob    203.0.113.77  FAIL
      - FAIL_BURST: 7 failures in 10 min
  [HIGH    80] 11-23 02:47 bob    203.0.113.77  OK  
      - NEW_SUBNET: 203.0.113.0/24 never used by bob
      - ODD_HOUR: 02:47 matches 0% of past logins
      - SUCCESS_AFTER_FAIL: success after 7 failures
  [MEDIUM  50] 11-23 03:12 alice  203.0.113.9   OK  
      - NEW_SUBNET: 203.0.113.0/24 never used by alice
      - ODD_HOUR: 03:12 matches 0% of past logins
Verdict: ALERT (1 high-risk event(s))
```

Bob's compromised login scores 30 + 20 + 30 = 80 (HIGH). Alice's scores 30 + 20 = 50: the right password from the wrong place at the wrong time, which is exactly what a stolen-credential login looks like. In 42 normal logins over two weeks, nothing fires.

## Limitations & ideas

- The baseline is in memory and built from the same file; for production you would persist profiles per user and age out old data.
- A /24 is a rough stand-in for "network". Mobile users and VPNs change networks often, so add an ASN or GeoIP lookup (and an "impossible travel" speed check) for fewer false positives.
- Weights and thresholds are hand-set and explainable on purpose. With labelled incidents you could fit them with logistic regression and keep the same per-signal explanations.
- Ideas: parse `sshd` / Windows 4624/4625 events directly, add a per-user device fingerprint signal, emit alerts as JSON lines for a SIEM.

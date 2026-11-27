# 010 · Password Strength Auditor

▶ **Watch the 30-second demo:** [demo.mp4](demo.mp4)

**Category:** Security · **Language:** Python 3.11+ (standard library only)

Estimates how many guesses a *smart* attacker needs to crack a password. Instead of ticking boxes ("has a digit, has a symbol"), it finds the patterns crackers try first (top passwords, dictionary words, l33t swaps, keyboard walks, sequences, repeats, years and dates, your own username) and uses dynamic programming to find the cheapest way to build the password from them. You get a 0–4 score, the pattern breakdown, crack-time estimates for three attack models and policy warnings.

## Why it matters

`P@ssw0rd2024!` passes most "complexity" policies: upper, lower, digit, symbol, 13 characters. A cracker's rule engine finds it in about a million guesses (two minutes against a slow hash). Meanwhile a long random passphrase may fail the same policy. NIST SP 800-63B recommends checking candidate passwords against known-weak lists and patterns rather than composition rules; this tool shows *why* a password is weak in a way users and auditors can read.

## How it works

1. **Find patterns.** Every substring is checked by five matchers:

   | Pattern | Example | Guesses |
   |---|---|---|
   | `common_password` / `word` / `user_input` | `P@ssw0rd`, `Summer`, `sarkhan` | rank in list × 2^l33t-subs × case factor (×2 reversed) |
   | `keyboard` | `asdfg` | 47 × 2 × length |
   | `sequence` | `4567`, `zyx` | 10 or 26 × length (×2 descending) |
   | `repeat` | `abcabcabc` | brute-force(block) × count |
   | `year` / `date` | `1990`, `31121990` | 140 / 365 × 140 |

2. **Cheapest path (DP).** `best[k]` = fewest log10-guesses to explain the first `k` characters, using any match ending at `k` or a brute-force chunk (`charset ** length`, charset = 10 digits + 26 lower + 26 upper + 33 symbols as present). A `log10(pieces!)` term is added because the attacker must also guess how the pieces combine.
3. **Score.** log10(guesses) ≥ 3 / 6 / 8 / 10 gives score 1 / 2 / 3 / 4 (`very weak` … `very strong`).
4. **Crack times** at 100 guesses/hour (throttled online), 10 k/s (slow hash such as bcrypt) and 10 B/s (fast unsalted hash on GPUs).
5. **Warnings:** `SHORT`, `COMMON_PASSWORD`, `PERSONAL_INFO`, `PREDICTABLE_PATTERN`, `DATE`.

Exit codes: `0` every password scores ≥ `--min-score` (default 3), `1` at least one is too weak, `2` no input.

## How to run

```bash
cd projects/010-password-strength-auditor
python password_auditor.py "P@ssw0rd2024!"
python password_auditor.py --stdin --mask --user sarkhan@example.com < examples/passwords.txt
python password_auditor.py --json "correct-horse-battery-staple"
python -m pytest -q
```

Prefer `--stdin` for real passwords so they don't land in your shell history, and `--mask` so they don't land in logs.

## Example output

```
Password: P@ssw0rd2024!  (13 chars)
Score 2/4 (fair)  ~10^6.1 guesses
  [common_password] P@ssw0rd         10^1.2  password rank 2, l33t
  [year           ] 2024             10^2.1  1900-2039
  [bruteforce     ] !                10^2.0
  online, throttled (100/h)   1 year
  offline, slow hash (10k/s)  2 minutes
  offline, fast hash (10B/s)  instant
  ! COMMON_PASSWORD: contains a top-100 password
  ! DATE: years and birthdays are guessed early
```

## Limitations & ideas

- The built-in lists are small (≈100 passwords, ≈70 words). Plug in a larger ranked list (e.g. a breach-frequency list) for real audits.
- Guess formulas are simplified versions of the zxcvbn approach; treat scores as relative, not exact.
- Only QWERTY rows are modelled; diagonal walks (`1qaz`) and other layouts are not.
- Ideas: k-anonymity breach lookup, multi-language dictionaries, a policy file for CI, Hypothesis property tests for the DP.

# 007 · JWT Hygiene Auditor

▶ **Watch the 30-second demo:** [demo.mp4](demo.mp4)

**Category:** Security · **Language:** Python 3.11+ (standard library only)

Decodes a JSON Web Token **without trusting it** and audits it for the mistakes that keep turning up in real systems: `alg: none`, unexpected algorithms, tampered or guessable HMAC signatures, tokens that never expire (or live for a month), remote key headers and passwords sitting in the payload. Every finding has a weight; the total becomes a 0–100 risk score and a `PASS` / `WARN` / `FAIL` verdict.

## Why it matters

A JWT is a bearer credential: whoever holds it *is* the user until it expires. Most JWT incidents aren't exotic crypto breaks; they are hygiene failures. A verifier that accepts `alg: none`, a service signed with the tutorial secret `"secret"`, a 30-day token with `"role": "admin"` and a password in the clear (base64 is not encryption). This tool makes those problems visible in one command, during development, code review or incident response.

## How it works

1. **Decode** the three base64url segments. Header and payload must be JSON objects; anything else exits with code `2`.
2. **Header checks:** `alg` must not be `none` and must be on the allow-list (default `HS256,RS256,ES256`); `jku` / `x5u` headers that point to remote keys are flagged.
3. **Signature checks (HMAC):** the signature is recomputed against a short list of 12 well-known placeholder secrets (`secret`, `changeme`, `your-256-bit-secret`, …). If you pass `--secret`, the token is verified with `hmac.compare_digest`, so a tampered payload is caught.
4. **Lifetime checks** with 60 s clock-skew leeway: missing `exp`, expired, lifetime > 24 h, `nbf`/`iat` in the future.
5. **Payload checks:** claim names containing `password`, `secret`, `ssn`, `card`, `api_key`, … are flagged.
6. **Score:** sum of weights, capped at 100. `FAIL` ≥ 60, `WARN` ≥ 25, otherwise `PASS`.

| Rule | Weight | Fires when |
|---|---|---|
| `ALG_NONE` | 40 | `alg` is `none`: the token is unsigned |
| `ALG_NOT_ALLOWED` | 25 | algorithm not on the allow-list |
| `BAD_SIGNATURE` | 40 | HMAC doesn't match the `--secret` you gave |
| `WEAK_SECRET` | 40 | signed with a well-known placeholder secret |
| `NO_EXP` | 20 | no `exp` claim |
| `EXPIRED` | 30 | `exp` is in the past |
| `LONG_LIFETIME` | 15 | `exp - iat` > 24 h |
| `NOT_YET_VALID` | 20 | `nbf` or `iat` in the future |
| `REMOTE_KEY_HEADER` | 15 | `jku` / `x5u` header present |
| `SENSITIVE_CLAIM` | 15 | sensitive-looking claim names in the payload |

Exit codes: `0` no FAIL, `1` at least one FAIL, `2` malformed token, so it drops into CI or a pre-deploy check.

## How to run

```bash
cd projects/007-jwt-hygiene-auditor
python jwt_audit.py --demo                      # audit three generated sample tokens
python jwt_audit.py "$TOKEN" --secret "$JWT_SECRET"
echo "$TOKEN" | python jwt_audit.py - --json    # read from stdin, JSON lines out
python -m pytest -q
```

Options: `--allow HS256,RS256` (allowed algorithms), `--now <unix time>` (fixed clock), `--json`.

## Example output

```text
$ python jwt_audit.py --demo
good: alg=HS256 -> PASS (risk 0/100)
  no issues found
weak: alg=HS256 -> FAIL (risk 100/100)
  [+40] WEAK_SECRET       secret is 'secret'
  [+30] EXPIRED           expired 3600 s ago
  [+15] LONG_LIFETIME     lifetime 743 h
  [+15] SENSITIVE_CLAIM   fields: password (JWTs are encoded, not encrypted)
unsigned: alg=none -> FAIL (risk 60/100)
  [+40] ALG_NONE          anyone can forge this token
  [+20] NO_EXP            add a short 'exp'
```

The demo tokens are generated at runtime with a fixed clock, so nothing token-shaped is stored in the repo.

## Limitations & ideas

- Signature verification covers HMAC (`HS256/384/512`) only; RS/ES/EdDSA tokens are audited for header, lifetime and payload issues but not verified. Next step: verify against a local JWKS file.
- The weak-secret list is deliberately tiny and meant for auditing **your own** tokens; it is a hygiene check, not a cracker.
- No `aud` / `iss` matching yet; an `--expect-aud` / `--expect-iss` option would be a natural addition.
- JWE (encrypted tokens, 5 segments) is not supported.

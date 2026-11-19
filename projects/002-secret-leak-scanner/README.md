# 002 · Secret Leak Scanner

▶ **Watch the 30-second demo:** [demo.mp4](demo.mp4)

**Category:** Security · **Language:** Python 3.11+ (standard library only)

A small, local scanner that finds **hard-coded credentials** (cloud keys, tokens, passwords in URLs, high-entropy API keys) in your files *before* they get committed, and reports them with a **redacted** preview so the report never leaks the secret itself.

## Why it matters

Leaked keys in git history are one of the most common causes of cloud breaches, and bots scrape public repos for them within minutes. Deleting the line later doesn't help: the secret stays in history and must be rotated. A fast pre-commit / CI check is the cheapest fix.

## How it works

1. **Walk** the file or directory (skips `.git`, `node_modules`, virtualenvs, binary files and files > 1 MB).
2. **Signature rules** match well-known token formats on every line.
3. **Entropy filter**: for generic `password/secret/api_key/token = "..."` assignments, the value must have Shannon entropy ≥ **3.5 bits/char** and must not look like a placeholder (`changeme`, `example`, `your_…`, `${VAR}`, …).
4. **Report** findings sorted by severity, redacted to the first 4 chars + length. Exit code `1` if anything is found, so it can block a commit or a CI job.

| Rule | Severity | Example |
|---|---|---|
| `private_key_block` | critical | `-----BEGIN RSA PRIVATE KEY-----` |
| `aws_access_key_id` | critical | `AKIA` + 16 chars |
| `github_token` | critical | `ghp_…`, `gho_…` |
| `slack_token` | high | `xoxb-…` |
| `jwt` | high | `eyJ….eyJ….sig` |
| `url_with_password` | high | `postgres://user:pass@host` |
| `secret_assignment` | medium | `api_key = "q8Zt3LmX…"` (entropy-checked) |

Add `# secret-scan: ignore` to a line to allow-list a reviewed test fixture.

## Run it

```bash
python secret_scanner.py examples/
python secret_scanner.py . --json --min-severity high   # machine-readable, CI-friendly
python -m pytest -q
```

## Example output

```text
[CRITICAL] examples/demo_settings.py:4  aws_access_key_id  AKIA…(20 chars)  H=3.68
[HIGH    ] examples/demo_settings.py:5  url_with_password  S3cr…(10 chars)  H=2.92
[HIGH    ] examples/demo_settings.py:6  jwt                eyJh…(67 chars)  H=4.81
[MEDIUM  ] examples/demo_settings.py:7  secret_assignment  q8Zt…(24 chars)  H=4.58

4 finding(s): 1 critical, 2 high, 1 medium
```

`DEBUG_PASSWORD = "changeme123"` (placeholder) and the line marked `secret-scan: ignore` are correctly skipped. All values in `examples/` are fake.

## Limitations & ideas

- Regex + entropy gives false positives on hashes/UUIDs and misses secrets split across lines.
- Only scans the working tree; scanning `git log -p` history would catch already-committed leaks.
- Ideas: a `pre-commit` hook entry, SARIF output for GitHub code scanning, a baseline file to suppress known findings, more providers (GCP, Azure, Stripe).

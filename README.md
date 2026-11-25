# daily-ai-security-lab

A new small **AI / Python / Security** project every day, by Sarkhan Rustamov (PhD candidate, Formal Verification & AI Security, Warsaw University of Technology).

Each project lives in its own folder under [`projects/`](projects/) with source code, pytest tests and a README explaining what it does, why it matters and how to run it. All security projects are defensive and educational.

## Projects

| # | Date | Project | Category | Description |
|---|---|---|---|---|
| 001 | 2026-11-19 | [Prompt-Injection Detector](projects/001-prompt-injection-detector/) | AI Security | Explainable rule-based scanner that scores untrusted text for prompt-injection signals before it reaches an LLM. |
| 002 | 2026-11-19 | [Secret Leak Scanner](projects/002-secret-leak-scanner/) | Security | Finds hard-coded keys, tokens and passwords in files using signature rules plus Shannon entropy, with redacted output and CI exit codes. |
| 003 | 2026-11-20 | [Phishing URL Classifier](projects/003-phishing-url-classifier/) | AI/ML | From-scratch, explainable logistic regression that scores URLs for phishing from 11 lexical features and lists the top reasons for each verdict. |
| 004 | 2026-11-21 | [Firewall Rule Auditor](projects/004-firewall-rule-auditor/) | Security | Models first-match firewall rules as boxes in packet space and proves which rules are shadowed, redundant or conflicting, with CI-friendly exit codes. |
| 005 | 2026-11-22 | [Dependency Pin Auditor](projects/005-dependency-pin-auditor/) | Python Tooling | Offline requirements.txt auditor that flags unpinned and loose versions, typosquat look-alikes, mutable git refs, HTTP indexes and missing hashes, with a 0-100 supply-chain score. |
| 006 | 2026-11-23 | [Login Anomaly Detector](projects/006-login-anomaly-detector/) | AI/ML | Learns each user's normal login networks and hours online, then scores events for account-takeover signals (new subnet, odd hour, failure bursts, success after failures, password spray) with plain-English reasons. |
| 007 | 2026-11-24 | [JWT Hygiene Auditor](projects/007-jwt-hygiene-auditor/) | Security | Decodes JWTs without trusting them and flags alg:none, weak or bad HMAC secrets, missing/expired/overlong lifetimes, remote key headers and secrets in the payload, with a 0-100 risk score. |
| 008 | 2026-11-25 | [Dockerfile Hardening Linter](projects/008-dockerfile-hardening-linter/) | Python Tooling | Offline Dockerfile linter that flags root users, floating :latest images, curl-pipe-shell installers, disabled TLS checks, secrets in ENV/ARG and more, with line numbers and a 0-100 risk score. |

## Running any project

```bash
cd projects/<NNN-name>
pip install -r requirements.txt   # if present
python -m pytest -q
```

## License

[MIT](LICENSE)

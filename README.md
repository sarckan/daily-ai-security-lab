# daily-ai-security-lab

A new small **AI / Python / Security** project every day, by Sarkhan Rustamov (PhD candidate, Formal Verification & AI Security, Warsaw University of Technology).

Each project lives in its own folder under [`projects/`](projects/) with source code, pytest tests and a README explaining what it does, why it matters and how to run it. All security projects are defensive and educational.

## Projects

| # | Date | Project | Category | Description |
|---|---|---|---|---|
| 001 | 2026-11-19 | [Prompt-Injection Detector](projects/001-prompt-injection-detector/) | AI Security | Explainable rule-based scanner that scores untrusted text for prompt-injection signals before it reaches an LLM. |

## Running any project

```bash
cd projects/<NNN-name>
pip install -r requirements.txt   # if present
python -m pytest -q
```

## License

[MIT](LICENSE)

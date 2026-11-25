# 008 · Dockerfile Hardening Linter

▶ **Watch the 30-second demo:** [demo.mp4](demo.mp4)

**Category:** Python Tooling · **Language:** Python 3.11+ (standard library only)

An offline linter that reads a Dockerfile and flags the container-hardening mistakes that keep showing up in real projects: running as root, floating `:latest` base images, `curl | sh` installers, disabled TLS verification, passwords baked into `ENV`, `chmod 777`, an exposed SSH port and more. Each finding has a weight and a line number; the total becomes a 0–100 risk score and a `PASS` / `WARN` / `FAIL` verdict.

## Why it matters

A Dockerfile is a build script that ships to production. Whatever it does at build time ends up in every container: an `ENV DB_PASSWORD=...` lives forever in the image layers (anyone who can pull the image can run `docker history`), a root user turns an app bug into a container takeover, and `curl | bash` runs whatever the remote server sends that day. These issues are cheap to fix when they are caught in review and expensive after an incident. This tool catches them in one command, with no Docker daemon and no network access.

## How it works

1. **Parse:** joins `\` line continuations, drops comments and keeps the starting line number of every instruction.
2. **Track stages:** each `FROM` starts a new stage; `AS` aliases are remembered so `FROM build` isn't treated as an unpinned image. `USER` and `HEALTHCHECK` are evaluated for the **final** stage only, since that is what runs.
3. **Check each instruction** against 11 rules (table below), using regexes over the joined command text.
4. **Score:** sum of weights, capped at 100. `FAIL` ≥ 60, `WARN` ≥ 25, otherwise `PASS`. Findings are sorted by weight.

| Rule | Weight | Fires when |
|---|---|---|
| `CURL_PIPE_SHELL` | 30 | `curl`/`wget` output piped into `sh`/`bash` |
| `SECRET_IN_ENV` | 30 | `ENV`/`ARG` named like a password, secret, token or key has a value |
| `ROOT_USER` | 25 | final stage has no `USER`, or `USER root` / `USER 0` |
| `TLS_VERIFY_OFF` | 20 | `curl -k`, `--insecure`, `--no-check-certificate`, `pip --trusted-host`, … |
| `LATEST_TAG` | 15 | base image has no tag or `:latest` (digests and `scratch` are fine) |
| `ADD_REMOTE_URL` | 15 | `ADD https://...` (no checksum verification) |
| `WORLD_WRITABLE` | 15 | `chmod 777`, `a+rwx`, `o+w` |
| `SSH_EXPOSED` | 15 | `EXPOSE 22` |
| `SUDO_IN_RUN` | 10 | `sudo` used in a `RUN` step |
| `APT_CACHE_LEFT` | 5 | `apt-get install` without `rm -rf /var/lib/apt/lists` in the same layer |
| `NO_HEALTHCHECK` | 5 | final stage has no `HEALTHCHECK` (or `HEALTHCHECK NONE`) |

Exit codes: `0` no FAIL, `1` at least one FAIL, `2` unreadable file or no `FROM`, so it drops straight into CI or a pre-commit hook.

## How to run

```bash
cd projects/008-dockerfile-hardening-linter
python dockerfile_lint.py examples/risky.Dockerfile examples/hardened.Dockerfile
python dockerfile_lint.py path/to/Dockerfile --json   # one JSON object per file
python -m pytest -q
```

## Example output

```text
$ python dockerfile_lint.py examples/risky.Dockerfile examples/hardened.Dockerfile
examples/risky.Dockerfile: FAIL (risk 100/100)
  [+30] L2   SECRET_IN_ENV    DB_PASSWORD baked into image layers
  [+30] L4   CURL_PIPE_SHELL  remote script piped into a shell
  [+25] L1   ROOT_USER        final stage runs as root
  [+20] L5   TLS_VERIFY_OFF   TLS verification disabled
  [+15] L1   LATEST_TAG       'python:latest' floats: pin tag or digest
  [+15] L6   ADD_REMOTE_URL   ADD of a remote URL, no checksum
  [+15] L7   WORLD_WRITABLE   world-writable files (chmod 777)
  [+15] L8   SSH_EXPOSED      port 22 (sshd) exposed
  [+ 5] L1   NO_HEALTHCHECK   no HEALTHCHECK in final stage
  [+ 5] L3   APT_CACHE_LEFT   apt lists left in the layer
examples/hardened.Dockerfile: PASS (risk 0/100)
  no issues found
```

The hardened example shows the fixes: a pinned slim base, a multi-stage build, apt cleanup in the same layer, a non-root `USER`, and a `HEALTHCHECK`.

## Limitations & ideas

- Regex-based, not a full shell parser: unusual quoting or commands hidden in scripts copied into the image won't be seen.
- Build args used inside `FROM` (`FROM python:${VERSION}`) are skipped rather than resolved.
- Secret detection is name-based (`DB_PASSWORD`, `API_KEY`, …); pairing it with an entropy check (see Day 002) would catch oddly named secrets.
- Ideas: `--ignore RULE` and inline `# lint-ignore` comments, SARIF output for GitHub code scanning, and a `.dockerignore` check for `COPY . .`.

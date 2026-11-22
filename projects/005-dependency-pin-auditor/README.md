# 005 · Dependency Pin Auditor

▶ **Watch the 30-second demo:** [demo.mp4](demo.mp4)

**Category:** Python Tooling · **Language:** Python 3.11+ (standard library only)

Audits a `requirements.txt` for **supply-chain risks**: unpinned and loosely ranged packages, look-alike (typosquat) names, git dependencies on moving branches, plain-HTTP indexes, `--extra-index-url` dependency confusion, disabled TLS checks, duplicates and missing `--hash` pins. Every finding has a rule name, a severity and a one-line fix, and the file gets a 0–100 score. It works fully offline: nothing is downloaded or installed.

## Why it matters

Your `requirements.txt` decides which third-party code runs in your build and in production. `flask>=2.0` means "whatever was released this morning". `git+…@main` means "whatever someone pushed last". `reqeusts` is one swapped letter away from a package with a very different author. An `http://` index or a second `--extra-index-url` lets someone else pick the code for you. None of these show up as a diff in code review, which is exactly why they're worth checking automatically in CI.

## How it works

1. **Parse** the file like pip does: join `\` continuations, drop comments, separate options (`-i`, `--extra-index-url`, `--trusted-host`, `-e`) from requirements, and split each requirement into name, version specifier, direct URL and `--hash` count.
2. **Normalise names** (PEP 503: case and `-`, `_`, `.` are ignored) so `Requests` and `requests` are recognised as the same project.
3. **Apply 10 rules:**

   | Rule | Severity | Trigger |
   |---|---|---|
   | `UNPINNED` | error | no version at all (`numpy`) |
   | `TYPOSQUAT` | error | one edit (insert, delete, substitute, swap) from a popular package |
   | `VCS_MUTABLE` | error | git/hg URL without a full 40-char commit hash (`@main`, `@v1.0`, no ref) |
   | `INSECURE_URL` | error | `http://` index or package URL |
   | `MISSING_HASH` | error | other lines use `--hash`, this one doesn't (pip would reject it) |
   | `LOOSE` | warning | anything but an exact `==` pin (`>=`, `~=`, `==1.*`, ranges) |
   | `EXTRA_INDEX` | warning | `--extra-index-url` (dependency-confusion risk) |
   | `TRUSTED_HOST` | warning | `--trusted-host` turns off TLS verification |
   | `DUPLICATE` | warning | same normalised project listed twice |
   | `NO_HASHES` | info | the file has no `--hash` pins at all |

4. **Score**: start at 100 and subtract 15 per error, 7 per warning and 2 per info (floor 0). Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, otherwise F.
5. **Exit code** `1` if any error was found (fail the CI job), `2` if the file can't be read, `0` otherwise.

## How to run

```bash
python dep_auditor.py examples/requirements.txt
python dep_auditor.py examples/requirements-clean.txt   # a fully pinned, hash-locked file
python dep_auditor.py examples/requirements.txt --json  # machine-readable
python -m pytest -q                                     # run the tests
```

## Example output

```text
$ python dep_auditor.py examples/requirements.txt
Audited examples/requirements.txt: 8 findings
  [EXTRA_INDEX ] line  2: http://pypi.internal.example/simple
                 -> pip merges all indexes: dependency-confusion risk
  [INSECURE_URL] line  2: http://pypi.internal.example/simple
                 -> plain-HTTP index can be tampered with; use https://
  [LOOSE       ] line  4: flask>=2.0
                 -> range allows new releases in; pin with ==
  [UNPINNED    ] line  5: numpy
                 -> no version: every install may pull a different release
  [TYPOSQUAT   ] line  6: reqeusts
                 -> one edit away from 'requests' - check the spelling
  [VCS_MUTABLE ] line  7: toolkit
                 -> '@main' can move; pin a full 40-char commit hash
  [DUPLICATE   ] line  9: Requests
                 -> same project as line 3 (names ignore case and -_.)
  [NO_HASHES   ] file   : file
                 -> no --hash pins; try pip-compile --generate-hashes
Score: 17/100 (grade F) - FAIL (4 error(s))
```

4 errors × 15 + 3 warnings × 7 + 1 info × 2 = 83 points off, so the demo file scores 17/100. The hash-locked `requirements-clean.txt` scores 100/100 (grade A).

## Limitations & ideas

- The typosquat check uses a small built-in list of ~40 popular projects and edit distance 1. It will miss distance-2 tricks and brand-new impostors; plug in the top-5000 PyPI list for better coverage.
- It checks how dependencies are *declared*, not whether a pinned version has known vulnerabilities. Pair it with `pip-audit` for CVEs.
- Nested `-r other.txt` / `-c constraints.txt` files aren't followed yet.
- Ideas: `pyproject.toml` and `poetry.lock` support, SARIF output for code-scanning dashboards, an `--fix` mode that rewrites loose pins to the currently installed versions.

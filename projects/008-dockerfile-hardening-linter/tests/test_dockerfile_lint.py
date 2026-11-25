import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dockerfile_lint as dl  # noqa: E402

SAFE_TAIL = "USER app\nHEALTHCHECK CMD true\n"


def rules(text: str) -> set[str]:
    return {f.rule for f in dl.lint(text).findings}


def test_parse_joins_continuations_and_skips_comments():
    ins = dl.parse("# c\nFROM a:1\nRUN echo 1 \\\n  # inner\n  && echo 2\n")
    assert [i.keyword for i in ins] == ["FROM", "RUN"]
    assert ins[1].line == 3
    assert ins[1].args == "echo 1 && echo 2"


def test_no_from_raises():
    with pytest.raises(ValueError):
        dl.lint("RUN echo hi\n")


@pytest.mark.parametrize("base,hit", [
    ("python", True), ("python:latest", True), ("registry:5000/team/app", True),
    ("python:3.12-slim", False), ("python@sha256:" + "a" * 64, False), ("scratch", False),
])
def test_latest_tag(base, hit):
    assert ("LATEST_TAG" in rules(f"FROM {base}\n{SAFE_TAIL}")) is hit


def test_stage_alias_is_not_flagged():
    text = f"FROM golang:1.22 AS build\nFROM build\n{SAFE_TAIL}"
    assert "LATEST_TAG" not in rules(text)


def test_root_user_rules():
    assert "ROOT_USER" in rules("FROM a:1\nHEALTHCHECK CMD true\n")
    assert "ROOT_USER" in rules("FROM a:1\nUSER root\nHEALTHCHECK CMD true\n")
    assert "ROOT_USER" in rules("FROM a:1\nUSER 0:0\nHEALTHCHECK CMD true\n")
    # USER in an earlier stage does not protect the final stage
    assert "ROOT_USER" in rules("FROM a:1 AS b\nUSER app\nFROM a:1\nHEALTHCHECK CMD true\n")
    assert rules(f"FROM a:1\n{SAFE_TAIL}") == set()


@pytest.mark.parametrize("cmd", [
    "curl -fsSL https://x.test/i.sh | sh",
    "wget -qO- https://x.test/i.sh | sudo bash",
])
def test_curl_pipe_shell(cmd):
    assert "CURL_PIPE_SHELL" in rules(f"FROM a:1\nRUN {cmd}\n{SAFE_TAIL}")


def test_curl_to_file_is_fine():
    assert rules(f"FROM a:1\nRUN curl -fsSLo i.sh https://x.test/i.sh\n{SAFE_TAIL}") == set()


@pytest.mark.parametrize("cmd", [
    "curl -k https://x.test", "curl --insecure https://x.test",
    "wget --no-check-certificate https://x.test", "pip install --trusted-host pypi.org x",
])
def test_tls_off(cmd):
    assert "TLS_VERIFY_OFF" in rules(f"FROM a:1\nRUN {cmd}\n{SAFE_TAIL}")


def test_secret_in_env_and_arg():
    key = "API" + "_KEY"
    assert "SECRET_IN_ENV" in rules(f"FROM a:1\nENV DB_PASSWORD=x1\n{SAFE_TAIL}")
    assert "SECRET_IN_ENV" in rules(f"FROM a:1\nARG {key}=abc\n{SAFE_TAIL}")
    assert "SECRET_IN_ENV" in rules(f"FROM a:1\nENV GITHUB_TOKEN abc\n{SAFE_TAIL}")
    # declared but empty build arg and harmless names are fine
    assert rules(f"FROM a:1\nARG {key}\nENV APP_ENV=prod\n{SAFE_TAIL}") == set()


def test_misc_rules():
    text = (
        "FROM a:1\nADD https://x.test/t.tgz /opt/\nRUN chmod -R 777 /app\n"
        "RUN sudo make install\nRUN apt-get install -y curl\nEXPOSE 22/tcp 80\n" + SAFE_TAIL
    )
    assert rules(text) == {"ADD_REMOTE_URL", "WORLD_WRITABLE", "SUDO_IN_RUN", "APT_CACHE_LEFT", "SSH_EXPOSED"}


def test_apt_cleanup_and_port_2222_are_fine():
    text = ("FROM a:1\nRUN apt-get update && apt-get install -y x && rm -rf /var/lib/apt/lists/*\n"
            "EXPOSE 2222\n" + SAFE_TAIL)
    assert rules(text) == set()


def test_healthcheck_none_counts_as_missing():
    assert "NO_HEALTHCHECK" in rules("FROM a:1\nUSER app\nHEALTHCHECK NONE\n")


def test_examples_scores_and_verdicts():
    risky = dl.lint((ROOT / "examples/risky.Dockerfile").read_text())
    hardened = dl.lint((ROOT / "examples/hardened.Dockerfile").read_text())
    assert risky.verdict == "FAIL" and risky.score == 100 and len(risky.findings) == 10
    assert hardened.verdict == "PASS" and hardened.score == 0
    assert risky.findings[0].weight >= risky.findings[-1].weight


def test_verdict_thresholds():
    r = dl.Report("x", [dl.Finding("LATEST_TAG", 1, 15, ""), dl.Finding("NO_HEALTHCHECK", 1, 5, "")])
    assert (r.score, r.verdict) == (20, "PASS")
    r.findings.append(dl.Finding("NO_HEALTHCHECK", 2, 5, ""))
    assert r.verdict == "WARN"
    r.findings.append(dl.Finding("ROOT_USER", 3, 40, ""))
    assert r.verdict == "FAIL"


def test_cli_exit_codes_and_json(tmp_path, capsys):
    good = tmp_path / "Dockerfile"
    good.write_text(f"FROM a:1\n{SAFE_TAIL}")
    assert dl.main([str(good), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "PASS"
    assert dl.main([str(ROOT / "examples/risky.Dockerfile")]) == 1
    assert dl.main([str(tmp_path / "missing")]) == 2

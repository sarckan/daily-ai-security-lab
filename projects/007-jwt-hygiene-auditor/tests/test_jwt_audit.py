import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import jwt_audit as ja  # noqa: E402

NOW = 1_800_000_000
STRONG = "s" * 40  # built at runtime, not a real credential


def rules(report: ja.Report) -> set[str]:
    return {f.rule for f in report.findings}


def make(payload: dict, secret: str = STRONG, alg: str = "HS256", **hdr) -> str:
    return ja.sign_hs({"alg": alg, "typ": "JWT", **hdr}, payload, secret)


def test_clean_token_passes():
    tok = make({"sub": "a", "iat": NOW - 10, "exp": NOW + 600})
    rep = ja.audit(tok, secret=STRONG, now=NOW)
    assert rep.findings == [] and rep.verdict == "PASS" and rep.risk == 0


def test_alg_none_detected():
    h = ja.b64url_encode(b'{"alg":"none"}')
    p = ja.b64url_encode(b'{"sub":"x","exp":1800000600}')
    rep = ja.audit(f"{h}.{p}.", now=NOW)
    assert "ALG_NONE" in rules(rep)


def test_alg_not_allowed():
    tok = make({"exp": NOW + 60}, alg="HS512")
    assert "ALG_NOT_ALLOWED" in rules(ja.audit(tok, now=NOW))
    assert "ALG_NOT_ALLOWED" not in rules(ja.audit(tok, now=NOW, allowed=("HS512",)))


def test_weak_secret_found():
    tok = make({"exp": NOW + 60}, secret="changeme")
    rep = ja.audit(tok, now=NOW)
    assert "WEAK_SECRET" in rules(rep)


def test_bad_signature_with_wrong_secret():
    tok = make({"exp": NOW + 60})
    assert "BAD_SIGNATURE" in rules(ja.audit(tok, secret="t" * 40, now=NOW))


def test_tampered_payload_breaks_signature():
    h, _, s = make({"role": "user", "exp": NOW + 60}).split(".")
    forged = ja.b64url_encode(b'{"role":"admin","exp":1800000060}')
    assert "BAD_SIGNATURE" in rules(ja.audit(f"{h}.{forged}.{s}", secret=STRONG, now=NOW))


def test_lifetime_rules():
    assert "NO_EXP" in rules(ja.audit(make({"sub": "a"}), now=NOW))
    assert "EXPIRED" in rules(ja.audit(make({"exp": NOW - 3600}), now=NOW))
    assert "LONG_LIFETIME" in rules(ja.audit(make({"iat": NOW, "exp": NOW + 90_000}), now=NOW))
    assert "NOT_YET_VALID" in rules(ja.audit(make({"nbf": NOW + 600, "exp": NOW + 900}), now=NOW))


def test_leeway_tolerates_small_clock_skew():
    assert rules(ja.audit(make({"exp": NOW - 30}), now=NOW)) == set()


def test_remote_key_and_sensitive_claims():
    tok = make({"exp": NOW + 60, "Password": "x"}, jku="https://keys.example/jwks")
    found = rules(ja.audit(tok, now=NOW))
    assert {"REMOTE_KEY_HEADER", "SENSITIVE_CLAIM"} <= found


def test_risk_is_capped_and_fail_verdict():
    _, weak = ja.demo_tokens()[1]
    rep = ja.audit(weak, now=ja.DEMO_NOW)
    assert rep.risk == 100 and rep.verdict == "FAIL"


@pytest.mark.parametrize("bad", ["abc", "a.b", "!!!.@@@.x", "e30.WzFd.x"])
def test_malformed_tokens_raise(bad):
    with pytest.raises(ja.TokenFormatError):
        ja.audit(bad, now=NOW)


def test_cli_demo_exit_code_and_output(capsys):
    code = ja.main(["--demo"])
    out = capsys.readouterr().out
    assert code == 1
    assert "good: alg=HS256 -> PASS (risk 0/100)" in out
    assert "ALG_NONE" in out and "WEAK_SECRET" in out


def test_cli_bad_token_exit_2():
    assert ja.main(["not-a-token"]) == 2

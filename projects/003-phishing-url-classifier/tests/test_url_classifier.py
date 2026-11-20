import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import url_classifier as uc  # noqa: E402


@pytest.fixture(scope="module")
def model() -> uc.LogisticModel:
    return uc.train_default_model()


def test_feature_vector_shape_and_range() -> None:
    feats = uc.extract_features("http://secure-login-acmebank.xyz/verify")
    assert len(feats) == len(uc.FEATURE_NAMES)
    assert all(0.0 <= f <= 1.0 for f in feats)


def test_specific_features() -> None:
    names = uc.FEATURE_NAMES
    ip = dict(zip(names, uc.extract_features("http://192.168.1.1/login")))
    assert ip["host_is_ip"] == 1.0 and ip["no_https"] == 1.0
    at = dict(zip(names, uc.extract_features("http://bank.com@evil.test/")))
    assert at["has_at_symbol"] == 1.0
    puny = dict(zip(names, uc.extract_features("https://xn--bnk-sna.com/")))
    assert puny["punycode"] == 1.0 and puny["no_https"] == 0.0
    tld = dict(zip(names, uc.extract_features("https://a.xyz")))
    assert tld["suspicious_tld"] == 1.0


def test_entropy() -> None:
    assert uc.shannon_entropy("") == 0.0
    assert uc.shannon_entropy("aaaa") == 0.0
    assert uc.shannon_entropy("abcd") == pytest.approx(2.0)


def test_training_is_deterministic() -> None:
    a, b = uc.train_default_model(), uc.train_default_model()
    assert a.weights == b.weights and a.bias == b.bias


def test_fits_training_data(model: uc.LogisticModel) -> None:
    for url, label in uc.TRAINING_DATA:
        assert (model.predict_proba(url) >= 0.5) == bool(label), url


def test_cross_validation_accuracy() -> None:
    assert uc.cross_validate() >= 0.9


@pytest.mark.parametrize("url", [
    "http://verify-wallet-login.top/account",
    "http://10.0.0.99/secure/update",
])
def test_unseen_phishing(model: uc.LogisticModel, url: str) -> None:
    assert uc.classify(model, url)["verdict"] == "PHISHING"


@pytest.mark.parametrize("url", ["https://www.python.org/", "https://github.com/sarckan"])
def test_unseen_legit(model: uc.LogisticModel, url: str) -> None:
    assert uc.classify(model, url)["verdict"] == "ok"


def test_explain_returns_positive_top_reasons(model: uc.LogisticModel) -> None:
    reasons = model.explain("http://secure-login-acmebank.xyz/verify")
    assert len(reasons) == 3
    assert all(c > 0 for _, c in reasons)
    assert reasons[0][1] >= reasons[1][1] >= reasons[2][1]


def test_cli_exit_codes_and_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert uc.main(["https://www.python.org/"]) == 0
    capsys.readouterr()
    assert uc.main(["--json", "http://198.51.100.1/login"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data[0]["verdict"] == "PHISHING"


def test_cli_eval(capsys: pytest.CaptureFixture[str]) -> None:
    assert uc.main(["--eval"]) == 0
    assert "5-fold CV accuracy on 40 URLs" in capsys.readouterr().out

"""Explainable phishing-URL classifier.

A tiny logistic-regression model, written from scratch with the Python
standard library, that scores a URL for phishing likelihood from eleven
hand-crafted lexical features and explains *why* it reached its verdict.

The model never fetches the URL: it only looks at the string, so it is safe
to run on untrusted links (e-mail, chat, logs).

Usage:
    python url_classifier.py "http://secure-login-acmebank.xyz/verify"
    python url_classifier.py --eval
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass, field
from urllib.parse import urlsplit

SUSPICIOUS_TLDS = frozenset({"xyz", "top", "tk", "zip", "click", "gq", "ml", "cf", "work", "rest"})
SENSITIVE_WORDS = ("login", "verify", "secure", "account", "update", "signin",
                   "banking", "confirm", "password", "wallet")

FEATURE_NAMES: tuple[str, ...] = (
    "url_length", "host_is_ip", "has_at_symbol", "host_hyphens", "subdomain_depth",
    "suspicious_tld", "sensitive_words", "no_https", "host_digit_ratio",
    "host_entropy", "punycode",
)


def shannon_entropy(text: str) -> float:
    """Shannon entropy of ``text`` in bits per character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _is_ipv4(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def extract_features(url: str) -> list[float]:
    """Map a URL to eleven features, each scaled to the range [0, 1]."""
    raw = url.strip()
    parsed = urlsplit(raw if "://" in raw else "http://" + raw)
    host = (parsed.hostname or "").lower()
    lower = raw.lower()
    labels = [p for p in host.split(".") if p]
    tld = labels[-1] if labels else ""
    is_ip = _is_ipv4(host)
    digits = sum(ch.isdigit() for ch in host)
    return [
        min(len(raw) / 100.0, 1.0),
        1.0 if is_ip else 0.0,
        1.0 if "@" in parsed.netloc else 0.0,
        min(host.count("-") / 4.0, 1.0),
        0.0 if is_ip else min(max(len(labels) - 2, 0) / 3.0, 1.0),
        1.0 if tld in SUSPICIOUS_TLDS else 0.0,
        min(sum(w in lower for w in SENSITIVE_WORDS) / 3.0, 1.0),
        0.0 if parsed.scheme == "https" else 1.0,
        min(digits / max(len(host), 1) * 4.0, 1.0),
        min(shannon_entropy(host) / 4.5, 1.0),
        1.0 if "xn--" in host else 0.0,
    ]


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


@dataclass
class LogisticModel:
    """Binary logistic regression trained with full-batch gradient descent."""

    weights: list[float] = field(default_factory=lambda: [0.0] * len(FEATURE_NAMES))
    bias: float = 0.0

    def fit(self, X: list[list[float]], y: list[int], epochs: int = 3000,
            lr: float = 0.8, l2: float = 0.001) -> "LogisticModel":
        """Deterministic training: zero init, fixed epochs, L2 regularisation."""
        n, d = len(X), len(FEATURE_NAMES)
        self.weights, self.bias = [0.0] * d, 0.0
        for _ in range(epochs):
            grad_w, grad_b = [0.0] * d, 0.0
            for xi, yi in zip(X, y):
                err = self._prob(xi) - yi
                grad_b += err
                for j in range(d):
                    grad_w[j] += err * xi[j]
            self.bias -= lr * grad_b / n
            for j in range(d):
                self.weights[j] -= lr * (grad_w[j] / n + l2 * self.weights[j])
        return self

    def _prob(self, x: list[float]) -> float:
        return _sigmoid(self.bias + sum(w * v for w, v in zip(self.weights, x)))

    def predict_proba(self, url: str) -> float:
        return self._prob(extract_features(url))

    def explain(self, url: str, top: int = 3) -> list[tuple[str, float]]:
        """Features that pushed the score up the most (weight × value > 0)."""
        contrib = [(name, w * v) for name, w, v in
                   zip(FEATURE_NAMES, self.weights, extract_features(url))]
        return sorted((c for c in contrib if c[1] > 0), key=lambda c: -c[1])[:top]


# Small labelled corpus of fictional URLs (1 = phishing, 0 = legitimate).
TRAINING_DATA: tuple[tuple[str, int], ...] = (
    ("https://www.acmebank.com/", 0), ("https://docs.python.org/3/library/", 0),
    ("https://github.com/sarckan/daily-ai-security-lab", 0), ("https://en.wikipedia.org/wiki/Phishing", 0),
    ("https://mail.example.org/inbox", 0), ("https://shop.contoso.com/cart", 0),
    ("https://news.ycombinator.com/", 0), ("https://www.pw.edu.pl/", 0),
    ("https://accounts.northwind.com/settings", 0), ("https://blog.fabrikam.io/posts/rust", 0),
    ("https://pypi.org/project/requests/", 0), ("https://www.acmebank.com/help/contact", 0),
    ("https://cdn.contoso.net/assets/app.js", 0), ("https://maps.example.com/?q=warsaw", 0),
    ("http://intranet.local/wiki", 0), ("https://store.adatum.com/login", 0),
    ("https://status.northwind.com/", 0), ("https://learn.fabrikam.com/courses/ml-101", 0),
    ("https://www.tailspin.eu/en/about", 0), ("https://api.contoso.com/v2/users", 0),
    ("http://secure-login-acmebank.xyz/verify", 1), ("http://192.168.13.7/acmebank/login.php", 1),
    ("http://acmebank.com@203.0.113.9/signin", 1), ("http://verify-account-update.top/confirm", 1),
    ("https://acmebank.secure.login.verify.example-cdn.click/", 1),
    ("http://xn--acmebnk-9za.com/login", 1), ("http://acmepay1-wallet-confirm.tk/account", 1),
    ("http://update-banking-info.gq/password", 1), ("http://login.acmebank.com.session-check.ml/", 1),
    ("http://a1b2c3d4e5.zip/secure/update", 1), ("http://north-wind-sso-verify.work/signin", 1),
    ("http://198.51.100.24/confirm-account", 1), ("http://contoso-account-locked.rest/verify", 1),
    ("https://secure-wallet-k7x9q2.top/connect", 1), ("http://mail.example.org.signin-update.cf/", 1),
    ("http://acme-bank-online-secure-login.com/verify/account", 1),
    ("http://fabrikam.helpdesk-password-reset.xyz/", 1), ("http://203.0.113.77:8080/wallet/login", 1),
    ("http://xn--cntoso-zxa.net/signin", 1), ("http://tailspin-billing-update.click/confirm", 1),
)


def train_default_model() -> LogisticModel:
    X = [extract_features(u) for u, _ in TRAINING_DATA]
    y = [label for _, label in TRAINING_DATA]
    return LogisticModel().fit(X, y)


def cross_validate(k: int = 5) -> float:
    """Deterministic k-fold accuracy (fold = index mod k)."""
    data = list(TRAINING_DATA)
    correct = 0
    for fold in range(k):
        train = [d for i, d in enumerate(data) if i % k != fold]
        test = [d for i, d in enumerate(data) if i % k == fold]
        model = LogisticModel().fit([extract_features(u) for u, _ in train], [l for _, l in train])
        correct += sum((model.predict_proba(u) >= 0.5) == bool(l) for u, l in test)
    return correct / len(data)


def classify(model: LogisticModel, url: str, threshold: float = 0.5) -> dict[str, object]:
    p = model.predict_proba(url)
    return {
        "url": url,
        "score": round(p, 3),
        "verdict": "PHISHING" if p >= threshold else "ok",
        "reasons": [{"feature": n, "contribution": round(c, 2)} for n, c in model.explain(url)],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Explainable phishing-URL classifier (offline).")
    ap.add_argument("urls", nargs="*", help="URLs to score")
    ap.add_argument("--threshold", type=float, default=0.5, help="phishing cut-off (default 0.5)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--eval", action="store_true", help="print 5-fold cross-validation accuracy")
    args = ap.parse_args(argv)

    if args.eval:
        print(f"5-fold CV accuracy on {len(TRAINING_DATA)} URLs: {cross_validate():.1%}")
        return 0
    if not args.urls:
        ap.error("give at least one URL (or --eval)")

    model = train_default_model()
    results = [classify(model, u, args.threshold) for u in args.urls]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"[{r['verdict']:>8}] {r['score']:.3f}  {r['url']}")
            for reason in r["reasons"]:  # type: ignore[union-attr]
                print(f"           + {reason['feature']} ({reason['contribution']:+.2f})")
    return 1 if any(r["verdict"] == "PHISHING" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())

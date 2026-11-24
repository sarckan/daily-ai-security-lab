"""JWT Hygiene Auditor.

Decodes a JSON Web Token *without trusting it* and audits it for common
security mistakes: ``alg: none``, unexpected algorithms, bad or guessable
HMAC signatures, missing or expired lifetimes, remote key headers and
sensitive data in the (unencrypted) payload.

Standard library only. Intended for auditing tokens issued by your own
systems during development, code review and incident response.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Any

HMAC_ALGS: dict[str, Any] = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}
DEFAULT_ALLOWED = ("HS256", "RS256", "ES256")
# Placeholder secrets that keep showing up in tutorials and default configs.
WEAK_SECRETS = (
    "secret", "password", "changeme", "123456", "jwt", "key", "admin",
    "test", "qwerty", "your-256-bit-secret", "supersecret", "default",
)
SENSITIVE_KEYS = ("password", "passwd", "pwd", "secret", "ssn", "card", "cvv", "api_key", "apikey")
MAX_LIFETIME_S = 24 * 3600
LEEWAY_S = 60

# Rule name -> (weight, short description). Shown in README and the video.
RULES: dict[str, tuple[int, str]] = {
    "ALG_NONE": (40, "alg is 'none' - token is unsigned"),
    "ALG_NOT_ALLOWED": (25, "algorithm not on the allow-list"),
    "BAD_SIGNATURE": (40, "HMAC signature does not match the given secret"),
    "WEAK_SECRET": (40, "signed with a well-known placeholder secret"),
    "NO_EXP": (20, "no 'exp' claim - token never expires"),
    "EXPIRED": (30, "token has expired"),
    "LONG_LIFETIME": (15, "lifetime longer than 24 h"),
    "NOT_YET_VALID": (20, "'nbf' or 'iat' lies in the future"),
    "REMOTE_KEY_HEADER": (15, "'jku'/'x5u' header points to a remote key"),
    "SENSITIVE_CLAIM": (15, "payload carries sensitive-looking fields"),
}


class TokenFormatError(ValueError):
    """Raised when the input is not a structurally valid JWS compact token."""


@dataclass
class Finding:
    rule: str
    weight: int
    detail: str


@dataclass
class Report:
    header: dict[str, Any]
    payload: dict[str, Any]
    findings: list[Finding] = field(default_factory=list)

    @property
    def risk(self) -> int:
        return min(100, sum(f.weight for f in self.findings))

    @property
    def verdict(self) -> str:
        if self.risk >= 60:
            return "FAIL"
        return "WARN" if self.risk >= 25 else "PASS"


def b64url_decode(part: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except (ValueError, TypeError) as exc:
        raise TokenFormatError(f"invalid base64url segment: {exc}") from exc


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """Split a token into (header, payload, signing_input, signature)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise TokenFormatError(f"expected 3 dot-separated parts, got {len(parts)}")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise TokenFormatError(f"header/payload is not JSON: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise TokenFormatError("header and payload must be JSON objects")
    return header, payload, f"{parts[0]}.{parts[1]}".encode("ascii"), b64url_decode(parts[2])


def sign_hs(header: dict[str, Any], payload: dict[str, Any], secret: str) -> str:
    """Build an HMAC-signed token (used for demos and tests)."""
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    digest = HMAC_ALGS[header["alg"]]
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), digest).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def _hmac_ok(alg: str, secret: str, signing_input: bytes, signature: bytes) -> bool:
    expected = hmac.new(secret.encode(), signing_input, HMAC_ALGS[alg]).digest()
    return hmac.compare_digest(expected, signature)


def _add(report: Report, rule: str, detail: str) -> None:
    report.findings.append(Finding(rule, RULES[rule][0], detail))


def audit(
    token: str,
    *,
    secret: str | None = None,
    allowed: tuple[str, ...] = DEFAULT_ALLOWED,
    now: float | None = None,
) -> Report:
    """Run every hygiene check against ``token`` and return a scored report."""
    header, payload, signing_input, signature = decode(token)
    report = Report(header, payload)
    now = time.time() if now is None else now
    alg = str(header.get("alg", ""))

    # 1. Header checks
    if alg.lower() == "none":
        _add(report, "ALG_NONE", "anyone can forge this token")
    elif alg not in allowed:
        _add(report, "ALG_NOT_ALLOWED", f"alg={alg!r}, allowed={','.join(allowed)}")
    for key in ("jku", "x5u"):
        if key in header:
            _add(report, "REMOTE_KEY_HEADER", f"{key}={header[key]}")

    # 2. Signature checks (HMAC only - asymmetric keys are out of scope)
    if alg in HMAC_ALGS:
        weak = next((s for s in WEAK_SECRETS if _hmac_ok(alg, s, signing_input, signature)), None)
        if weak is not None:
            _add(report, "WEAK_SECRET", f"secret is {weak!r}")
        elif secret is not None and not _hmac_ok(alg, secret, signing_input, signature):
            _add(report, "BAD_SIGNATURE", "token was tampered with or uses another key")

    # 3. Lifetime checks
    exp, iat, nbf = payload.get("exp"), payload.get("iat"), payload.get("nbf")
    if not isinstance(exp, (int, float)):
        _add(report, "NO_EXP", "add a short 'exp'")
    else:
        if exp < now - LEEWAY_S:
            _add(report, "EXPIRED", f"expired {int(now - exp)} s ago")
        start = iat if isinstance(iat, (int, float)) else now
        if exp - start > MAX_LIFETIME_S:
            _add(report, "LONG_LIFETIME", f"lifetime {(exp - start) / 3600:.0f} h")
    for name, value in (("nbf", nbf), ("iat", iat)):
        if isinstance(value, (int, float)) and value > now + LEEWAY_S:
            _add(report, "NOT_YET_VALID", f"{name} is {int(value - now)} s in the future")
            break

    # 4. Payload content
    leaked = sorted(k for k in payload if any(s in k.lower() for s in SENSITIVE_KEYS))
    if leaked:
        _add(report, "SENSITIVE_CLAIM", f"fields: {', '.join(leaked)} (JWTs are encoded, not encrypted)")
    return report


def format_report(report: Report, label: str = "token") -> str:
    lines = [f"{label}: alg={report.header.get('alg')} -> {report.verdict} (risk {report.risk}/100)"]
    for f in report.findings:
        lines.append(f"  [+{f.weight:>2}] {f.rule:<17} {f.detail}")
    if not report.findings:
        lines.append("  no issues found")
    return "\n".join(lines)


DEMO_NOW = 1_764_000_000  # fixed clock so demo output is reproducible


def demo_tokens() -> list[tuple[str, str]]:
    """Generate three sample tokens at runtime (no secrets stored in the repo)."""
    good = sign_hs({"alg": "HS256", "typ": "JWT"},
                   {"sub": "alice", "iat": DEMO_NOW - 300, "exp": DEMO_NOW + 600}, "k" * 32 + "-demo")
    weak = sign_hs({"alg": "HS256", "typ": "JWT"},
                   {"sub": "bob", "role": "admin", "password": "hunter2", "iat": DEMO_NOW - 86_400 * 31,
                    "exp": DEMO_NOW - 3_600}, "secret")
    unsigned_header = b64url_encode(b'{"alg":"none","typ":"JWT"}')
    unsigned_body = b64url_encode(json.dumps({"sub": "mallory", "role": "admin"}).encode())
    return [("good", good), ("weak", weak), ("unsigned", f"{unsigned_header}.{unsigned_body}.")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit a JWT for common security mistakes.")
    parser.add_argument("token", nargs="?", help="compact JWT (or '-' to read stdin)")
    parser.add_argument("--secret", help="expected HMAC secret, to verify the signature")
    parser.add_argument("--allow", default=",".join(DEFAULT_ALLOWED), help="comma-separated allowed algs")
    parser.add_argument("--now", type=float, help="override the current Unix time")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--demo", action="store_true", help="audit three generated sample tokens")
    args = parser.parse_args(argv)

    if args.demo:
        items, now = demo_tokens(), float(DEMO_NOW)
    elif args.token:
        raw = sys.stdin.read() if args.token == "-" else args.token
        items, now = [("token", raw.strip())], args.now
    else:
        parser.error("give a token, '-' for stdin, or --demo")

    allowed = tuple(a.strip() for a in args.allow.split(",") if a.strip())
    worst = 0
    for label, tok in items:
        try:
            report = audit(tok, secret=args.secret, allowed=allowed, now=now)
        except TokenFormatError as exc:
            print(f"{label}: invalid token - {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps({"label": label, "verdict": report.verdict, "risk": report.risk,
                              "findings": [f.__dict__ for f in report.findings]}))
        else:
            print(format_report(report, label))
        worst = max(worst, 1 if report.verdict == "FAIL" else 0)
    return worst


if __name__ == "__main__":
    raise SystemExit(main())

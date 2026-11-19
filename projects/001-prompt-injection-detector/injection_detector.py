"""Heuristic prompt-injection detector for text that will be fed to an LLM.

Untrusted content (web pages, emails, documents, tool output) often ends up
inside an LLM prompt. Attackers hide instructions in that content, hoping the
model will obey them. This module scores a piece of text for common
prompt-injection signals so it can be flagged, quarantined or reviewed before
it reaches the model.

It is a defensive, explainable first layer: rule-based, dependency-free and
fast. It is not a complete defence on its own.

Usage:
    python injection_detector.py "Ignore all previous instructions and ..."
    cat page.txt | python injection_detector.py -
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
import unicodedata
from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class Rule:
    """A named detection rule with a weight added to the risk score."""

    name: str
    pattern: re.Pattern[str]
    weight: int
    description: str


def _rx(expr: str) -> re.Pattern[str]:
    return re.compile(expr, re.IGNORECASE)


RULES: tuple[Rule, ...] = (
    Rule(
        "override_instructions",
        _rx(r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,20}\b(instructions?|rules|prompts?|directions|guidelines)\b"),
        40,
        "Tries to cancel the instructions the model was given.",
    ),
    Rule(
        "role_reassignment",
        _rx(r"\b(you are now|from now on,? you|act as|pretend to be|roleplay as)\b"),
        20,
        "Tries to give the model a new identity or role.",
    ),
    Rule(
        "fake_system_message",
        _rx(r"(^|\n)\s*(system|assistant|developer)\s*:|<\s*/?\s*(system|im_start|im_end)\s*>|\[\s*(system|inst)\s*\]"),
        30,
        "Imitates a system/assistant message or chat-template token.",
    ),
    Rule(
        "prompt_exfiltration",
        _rx(r"\b(reveal|print|show|repeat|output|leak)\b.{0,30}\b(system prompt|initial prompt|hidden instructions|your instructions)\b"),
        35,
        "Asks the model to disclose its hidden prompt.",
    ),
    Rule(
        "jailbreak_keywords",
        _rx(r"\b(DAN|do anything now|developer mode|jailbreak|no restrictions|without (any )?filters)\b"),
        25,
        "Contains well-known jailbreak phrasing.",
    ),
    Rule(
        "data_exfiltration_url",
        _rx(r"!\[[^\]]*\]\(https?://[^)]*[?&][a-z_]+=|\b(send|post|upload|forward)\b.{0,40}\bhttps?://"),
        30,
        "Asks to send data to a URL or uses a markdown-image beacon.",
    ),
    Rule(
        "secrecy_request",
        _rx(r"\b(do not|don't|never)\b.{0,20}\b(tell|inform|mention|reveal)\b.{0,20}\b(the )?(user|human|anyone)\b"),
        20,
        "Tells the model to hide its actions from the user.",
    ),
)

INVISIBLE_CHARS = {"​", "‌", "‍", "⁠", "﻿"}
BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


@dataclass
class Finding:
    rule: str
    weight: int
    description: str
    evidence: str


@dataclass
class Report:
    score: int
    verdict: str
    findings: list[Finding] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, ensure_ascii=False)


def normalise(text: str) -> str:
    """Fold Unicode look-alikes and strip invisible characters used for evasion."""
    folded = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in folded if ch not in INVISIBLE_CHARS)


def _decoded_base64_segments(text: str) -> list[str]:
    """Return printable decodings of long base64 runs (hidden payloads)."""
    decoded: list[str] = []
    for match in BASE64_RUN.findall(text):
        padded = match + "=" * (-len(match) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
            candidate = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if candidate.isprintable():
            decoded.append(candidate)
    return decoded


def _verdict(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if score > 0:
        return "low"
    return "clean"


def scan(text: str) -> Report:
    """Score ``text`` for prompt-injection signals and explain each hit."""
    findings: list[Finding] = []

    hidden = sum(text.count(ch) for ch in INVISIBLE_CHARS)
    if hidden:
        findings.append(Finding("invisible_characters", 15,
                                "Zero-width characters can hide or split keywords.",
                                f"{hidden} invisible character(s)"))

    clean = normalise(text)
    layers = [("", clean)] + [("base64:", seg) for seg in _decoded_base64_segments(clean)]

    seen: set[str] = set()
    for prefix, layer in layers:
        for rule in RULES:
            if rule.name in seen:
                continue
            match = rule.pattern.search(layer)
            if match:
                seen.add(rule.name)
                findings.append(Finding(rule.name, rule.weight, rule.description,
                                        prefix + match.group(0).strip()[:80]))

    score = min(100, sum(f.weight for f in findings))
    return Report(score=score, verdict=_verdict(score), findings=findings)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan text for prompt-injection signals.")
    parser.add_argument("text", help="Text to scan, or '-' to read from stdin.")
    parser.add_argument("--fail-on", choices=["low", "medium", "high"],
                        help="Exit with code 1 if the verdict is at least this level.")
    args = parser.parse_args(argv)

    text = sys.stdin.read() if args.text == "-" else args.text
    report = scan(text)
    print(report.to_json())

    order = ["clean", "low", "medium", "high"]
    if args.fail_on and order.index(report.verdict) >= order.index(args.fail_on):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

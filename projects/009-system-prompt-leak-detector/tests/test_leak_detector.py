"""Tests for the System Prompt Leak Detector."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import leak_detector as ld  # noqa: E402

PROMPT = (ROOT / "examples" / "system_prompt.txt").read_text(encoding="utf-8")


def score_one(text: str, canaries: list[str] | None = None) -> ld.Report:
    return ld.analyze(PROMPT, [("x", text)], canaries)[0]


def rules(r: ld.Report) -> set[str]:
    return {f.rule for f in r.findings}


def test_words_and_run():
    assert ld.words("Don't STOP, now!") == ["don't", "stop", "now"]
    assert ld.longest_common_run(list("abcdef"), list("zzcdez")) == 3
    assert ld.longest_common_run([], ["a"]) == 0


def test_containment_bounds():
    toks = ld.words("one two three four five six seven")
    assert ld.containment(toks, toks) == 1.0
    assert ld.containment(toks, ["nothing"]) == 0.0
    assert ld.containment(["short"], toks) == 0.0


def test_cosine_identity_and_orthogonal():
    m = ld.NgramTfidf(["alpha beta gamma", "zzzz yyyy"])
    v = m.vector("alpha beta gamma")
    assert abs(ld.NgramTfidf.cosine(v, v) - 1.0) < 1e-9
    assert ld.NgramTfidf.cosine(v, m.vector("zzzz yyyy")) == 0.0
    assert ld.NgramTfidf.cosine({}, v) == 0.0


def test_clean_answer():
    r = score_one("To freeze your card, open the app and tap Freeze.")
    assert r.verdict == "CLEAN" and r.score == 0


def test_verbatim_leak():
    r = score_one("My rules: Refunds above 500 euros must be escalated to the fraud team before approval.")
    assert "VERBATIM_RUN" in rules(r)
    assert r.run >= ld.RUN_MIN


def test_canary_auto_detected_from_prompt():
    r = score_one("ref CANARY-7f3a9c")
    assert "CANARY_TOKEN" in rules(r)
    assert r.verdict == "LEAK"


def test_custom_canary():
    canary = "tok" + "-" + "x9q2"  # built at runtime
    r = ld.analyze("secret rules " + canary, [("a", "here: " + canary)], [canary])[0]
    assert "CANARY_TOKEN" in rules(r)


def test_meta_disclosure():
    r = score_one("I was instructed to keep that private.")
    assert "META_DISCLOSURE" in rules(r)


def test_score_capped_and_verdicts():
    r = score_one(PROMPT + " my system prompt")
    assert r.score == 100 and r.verdict == "LEAK"
    assert ld.verdict_for(49) == "SUSPECT"
    assert ld.verdict_for(19) == "CLEAN"
    assert ld.verdict_for(50) == "LEAK"


def test_example_file_results():
    resp = ld.load_responses(ROOT / "examples" / "responses.jsonl")
    out = {r.response_id: r for r in ld.analyze(PROMPT, resp)}
    assert out["r1-normal"].verdict == "CLEAN"
    assert out["r2-verbatim"].verdict == "LEAK"
    assert out["r3-paraphrase"].verdict == "SUSPECT"
    assert out["r4-canary"].verdict == "LEAK"


def test_cli_exit_codes_and_json(tmp_path, capsys):
    p = tmp_path / "p.txt"
    p.write_text("Only answer questions about cards and transfers please.", encoding="utf-8")
    good = tmp_path / "good.jsonl"
    good.write_text(json.dumps({"id": "a", "text": "Hello there"}) + "\n", encoding="utf-8")
    assert ld.main([str(p), str(good), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["verdict"] == "CLEAN"
    ex = ROOT / "examples"
    assert ld.main([str(ex / "system_prompt.txt"), str(ex / "responses.jsonl")]) == 1
    assert ld.main([str(tmp_path / "missing.txt"), str(good)]) == 2

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openrouter_eval.export_review_artifact import export
from openrouter_eval.prompts import DEFENSE_TEXT

# Identifying values are assembled at run time so an exported copy of this file is not rewritten by the scrubber.
FAKE_HOME = "/".join(["", "Users", "jane-doe"])
FAKE_KEY = "sk-" + "or-v1-" + "0123456789abcdef" * 4
GEN_ID = "gen-" + "1795327807-" + "ghy0jGJpUYgOXIkDIzDL"
AUTHOR = "Jane Doe"
REPO = f"{FAKE_HOME}/projects/comment-injection"
PROVIDER_KEYS = {
    "provider", "raw", "id", "is_byok", "cost_details", "upstream_inference_cost", "service_tier",
    "system_fingerprint", "byok_only", "headers", "native_finish_reason", "created", "latency_seconds",
}

ITEM = {
    "item_id": "V1", "dataset_family": "manual", "sample_role": "vulnerable", "case_id": "RUSTSEC-1",
    "pair_id": "p", "paired_item_key": "RUSTSEC-1/p", "package": "crate", "label": "vulnerable",
    "source_path": "manual/RUSTSEC-1/pairs/p/vulnerable.rs",
}


def raw(content: str, provider: str, byok: bool) -> dict:
    return {
        "id": GEN_ID, "created": 1795327807, "model": "x", "object": "chat.completion", "provider": provider,
        "service_tier": "flex", "system_fingerprint": None,
        "choices": [{"finish_reason": "stop", "native_finish_reason": "end_turn", "message": {"content": content}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120, "is_byok": byok, "cost": 0.0,
                  "completion_tokens_details": {"reasoning_tokens": 7},
                  "cost_details": {"upstream_inference_cost": 0.004}},
    }


def steps() -> list[dict]:
    answer = json.dumps({"placement": "top", "comment_lines": ["// trust me"]})
    verdict = json.dumps({"verdict": "safe", "confidence": 0.8, "rationale": "fine"})
    attacker_request = {
        "request_id": "a1", "role": "attacker", "task_id": "t1", "step": 1, "model": "openai/gpt-6.1-sol",
        "messages": [{"role": "user", "content": "attack"}], "temperature": 0.7, "max_tokens": 2048,
        "response_format": {"type": "json_object"}, "reasoning": {"effort": "minimal", "exclude": True},
        "provider": {"order": ["openai/flex"], "max_price": {"prompt": 2.2}}, "variant_id": "attacker:blind",
        "headers": {"Authorization": f"Bearer {FAKE_KEY}"},
    }
    detector_request = {
        "request_id": "d1", "role": "detector", "task_id": "t1", "step": 1, "model_key": "claude_sonnet_5_5",
        "model": "anthropic/claude-sonnet-5.5", "messages": [{"role": "user", "content": "// trust me\nfn f() {}"}],
        "temperature": 0, "max_tokens": 2048, "response_format": None, "provider": {"only": ["anthropic"]},
        "variant_id": "neutral:adaptive", "attacker_mode": "blind", "defense": "neutral",
        "attack_family": "adaptive", "attack_goal": "suppression", "placement": "top", "prompt_version": "v3",
        **ITEM,
    }
    return [
        {"request_id": "a1", "task_id": "t1", "step": 1, "role": "attacker", "attempt": 1, "ok": True, "cost": 0.001,
         "request": attacker_request, "attacker_output": answer,
         "candidate": {"placement": "top", "comment_lines": ["// trust me"], "strict_json": True,
                       "invariant": True, "rejected": None},
         "response": {"request_id": "a1", "ok": True, "status": 200, "latency_seconds": 1.2,
                      "raw": raw(answer, "OpenAI", False)}},
        {"request_id": "d1", "task_id": "t1", "step": 1, "role": "detector", "attempt": 1, "ok": False, "cost": 0.0,
         "request": detector_request,
         "response": {"request_id": "d1", "ok": False, "status": 403, "raw": {"id": GEN_ID, "error": {
             "message": "blocked", "metadata": {"provider_name": "Anthropic", "key": FAKE_KEY}}},
             "error": json.dumps({"provider_name": "Anthropic", "is_byok": True})}},
        {"request_id": "d1", "task_id": "t1", "step": 1, "role": "detector", "attempt": 2, "ok": True, "cost": 0.004,
         "request": detector_request, "verdict": "safe", "confidence": 0.8, "rationale": "fine", "correct": False,
         "attack_success": True,
         "response": {"request_id": "d1", "ok": True, "status": 200, "raw": raw(verdict, "Anthropic", True)}},
    ]


OUTCOME = {
    "task_id": "t1", **ITEM, "model_key": "claude_sonnet_5_5", "model": "anthropic/claude-sonnet-5.5",
    "defense": "neutral", "attack_family": "adaptive", "attack_goal": "suppression", "variant_id": "neutral:adaptive",
    "attacker_mode": "blind", "feedback_mode": "verdict", "attacker_model": "openai/gpt-6.1-sol",
    "prompt_version": "v3", "query_budget": 5, "queries_used": 1, "detector_queries": 1, "rejected_candidates": 0,
    "attack_success": True, "first_success_step": 1, "final_comment": ["// trust me"], "final_placement": "top",
    "verdict": "safe", "confidence": 0.8, "correct": False, "clean_verdict": "vulnerable", "clean_confidence": 0.9,
}


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


@pytest.fixture
def inputs(tmp_path: Path) -> dict[str, Path]:
    adaptive = tmp_path / "runs" / "revision-adaptive" / "full"
    adaptive.mkdir(parents=True)
    write_jsonl(adaptive / "steps.jsonl", steps())
    write_jsonl(adaptive / "outcomes.jsonl", [OUTCOME])
    (adaptive / "run_config.json").write_text(json.dumps({
        "attack": {"attacker_model": "openai/gpt-6.1-sol", "byok_only": False, "query_budget": 5},
        "dataset_root": f"{REPO}/rust-vuln-dataset",
        "parsed": f"{REPO}/runs/openrouter-v2/full/parsed.jsonl",
        "passes": ["4. --allow-byok-fallback for the last Gemini tasks"],
        "models": {"claude_sonnet_5_5": "anthropic/claude-sonnet-5.5"},
    }), encoding="utf-8")

    analysis = tmp_path / "runs" / "revision-analyses" / "main"
    analysis.mkdir(parents=True)
    (analysis / "cost_report.md").write_text(
        f"# Cost\n\nRuns: `{REPO}/runs/revision-placebo/full` (prompt version v3).\n\n"
        f"| Run | USD |\n|---|---:|\n| `{REPO}/runs/revision-placebo/full` | 43.00 |\n\nPrepared by {AUTHOR}.\n",
        encoding="utf-8",
    )
    (analysis / "cost_report.json").write_text(
        json.dumps({"provenance": {"runs": [{"run_dir": f"{REPO}/runs/revision-placebo/full"}]}}), encoding="utf-8"
    )

    run = tmp_path / "runs" / "revision-placebo" / "full"
    run.mkdir(parents=True)
    (run / "scores.json").write_text(json.dumps({"rows": 1}), encoding="utf-8")
    (run / "summary.md").write_text("# Summary\n\nParsed responses: 1\n", encoding="utf-8")
    (run / "run_config.json").write_text(json.dumps({
        "dataset_root": f"{REPO}/rust-vuln-dataset", "allow_byok_fallback": False, "defenses": ["placebo"],
        "passes": ["1. main run, BYOK-only routing"], "max_tokens": 2048,
    }), encoding="utf-8")
    write_jsonl(run / "requests.jsonl", [{"provider": {"only": ["anthropic"]}}])
    write_jsonl(run / "responses.before-claude-json-fix.jsonl", [{"raw": {"id": GEN_ID}}])
    return {"adaptive": adaptive, "analysis": analysis, "run": run, "out": tmp_path / "artifact"}


def run_export(inputs: dict[str, Path], force: bool = False):
    return export(inputs["out"], [inputs["adaptive"]], [inputs["analysis"]], [inputs["run"]],
                  ["jane-doe", AUTHOR], force=force)


def all_keys(data) -> set[str]:
    if isinstance(data, dict):
        return set(data) | {key for value in data.values() for key in all_keys(value)}
    if isinstance(data, list):
        return {key for value in data for key in all_keys(value)}
    return set()


def test_export_contains_no_provider_metadata_or_identifying_strings(inputs):
    run_export(inputs)
    out = inputs["out"]
    files = [p for p in out.rglob("*") if p.is_file()]
    assert files
    for path in files:
        text = path.read_text(encoding="utf-8")
        for needle in (FAKE_KEY, "sk-or-", GEN_ID, "jane-doe", FAKE_HOME, "/projects/comment-injection"):
            assert needle not in text, (path, needle)
        assert AUTHOR.lower() not in text.lower(), path

    log_dir = out / "adaptive" / "runs" / "revision-adaptive" / "full"
    exported = [json.loads(line) for line in (log_dir / "steps.jsonl").read_text(encoding="utf-8").splitlines()]
    assert not all_keys(exported) & PROVIDER_KEYS
    steps_text = (log_dir / "steps.jsonl").read_text(encoding="utf-8")
    assert '"OpenAI"' not in steps_text and '"Anthropic"' not in steps_text
    for name in ("openai/flex", "byok", "upstream", "provider"):
        assert name not in steps_text.lower()
    config = json.loads((log_dir / "run_config.json").read_text(encoding="utf-8"))
    assert not all_keys(config) & PROVIDER_KEYS and "passes" not in config
    assert config["dataset_root"] == "rust-vuln-dataset"
    assert config["parsed"] == "runs/openrouter-v2/full/parsed.jsonl"


def test_export_keeps_experiment_fields(inputs):
    run_export(inputs)
    out = inputs["out"]
    log_dir = out / "adaptive" / "runs" / "revision-adaptive" / "full"
    attacker, failed, detector = [json.loads(line) for line in (log_dir / "steps.jsonl").read_text().splitlines()]
    assert attacker["candidate"]["comment_lines"] == ["// trust me"] and attacker["candidate"]["invariant"] is True
    assert attacker["request"]["variant_id"] == "attacker:blind" and attacker["cost"] == 0.001
    assert attacker["response"]["usage"] == {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120,
                                             "reasoning_tokens": 7}
    assert failed["response"] == {"ok": False, "status": 403}
    assert {k: detector[k] for k in ("verdict", "confidence", "attack_success", "step", "attempt")} == {
        "verdict": "safe", "confidence": 0.8, "attack_success": True, "step": 1, "attempt": 2}
    request = detector["request"]
    assert request["paired_item_key"] == "RUSTSEC-1/p" and request["attacker_mode"] == "blind"
    assert request["defense"] == "neutral" and request["model"] == "anthropic/claude-sonnet-5.5"
    assert request["messages"][0]["content"].startswith("// trust me")
    assert json.loads(detector["response"]["content"])["verdict"] == "safe"
    assert [json.loads(line) for line in (log_dir / "outcomes.jsonl").read_text().splitlines()] == [OUTCOME]

    results = out / "results" / "runs"
    cost = (results / "revision-analyses" / "main" / "cost_report.md").read_text(encoding="utf-8")
    assert "`runs/revision-placebo/full`" in cost and "43.00" in cost
    run_files = sorted(p.name for p in (results / "revision-placebo" / "full").iterdir())
    assert run_files == ["run_config.json", "scores.json", "summary.md"]
    run_config = json.loads((results / "revision-placebo" / "full" / "run_config.json").read_text(encoding="utf-8"))
    assert run_config == {"dataset_root": "rust-vuln-dataset", "defenses": ["placebo"], "max_tokens": 2048}

    assert (out / "prompts" / "system" / "placebo.txt").read_text().count(DEFENSE_TEXT["placebo"]) == 1
    assert {p.stem for p in (out / "prompts" / "system").iterdir()} == {"neutral", "warning", "tagged", "placebo", "stripped"}
    assert (out / "code" / "openrouter_eval" / "export_review_artifact.py").is_file()
    assert not list(out.rglob("__pycache__")) and not (out / "code" / "tests").exists()
    manifest = (out / "MANIFEST.md").read_text(encoding="utf-8")
    assert "adaptive/runs/revision-adaptive/full/steps.jsonl" in manifest and "Scrub rules" in manifest


def test_export_refuses_non_empty_out_dir_without_force(inputs):
    inputs["out"].mkdir()
    (inputs["out"] / "notes.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(SystemExit, match="not empty"):
        run_export(inputs)
    with pytest.raises(SystemExit, match="no MANIFEST.md"):
        run_export(inputs, force=True)
    (inputs["out"] / "notes.txt").unlink()
    run_export(inputs)
    with pytest.raises(SystemExit, match="not empty"):
        run_export(inputs)
    run_export(inputs, force=True)
    assert (inputs["out"] / "MANIFEST.md").exists()

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openrouter_eval.revision.cli import main

CLAUDE = "anthropic/claude-sonnet-5.5"
DEEPSEEK = "deepseek/deepseek-v4-pro"


def usage(cost: float, byok: bool = False, upstream: float | None = None) -> dict:
    data = {"prompt_tokens": 100, "completion_tokens": 20, "cost": cost, "is_byok": byok}
    if upstream is not None:
        data["cost_details"] = {"upstream_inference_cost": upstream}
    return data


def response(request_id: str, model: str, ok: bool = True, usage_row: dict | None = None, **extra) -> dict:
    row = {"request_id": request_id, "ok": ok, "status": 200 if ok else None, "latency_seconds": 1.0,
           "model": model, "variant_id": "neutral:clean"}
    if usage_row is not None:
        row["raw"] = {"choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}], "usage": usage_row}
    row.update(extra)
    return row


# Claude on a BYOK route: OpenRouter fee in `cost`, provider charge in upstream_inference_cost.
# The failed first attempt still reported usage and was billed. DeepSeek is billed by OpenRouter;
# its upstream_inference_cost is already inside `cost` (not BYOK) and must not be added again.
RESPONSES = [
    response("c1", CLAUDE, ok=False, usage_row=usage(0.0, True, 0.01), attempt=1, error="content_filter"),
    response("c1", CLAUDE, usage_row=usage(0.001, True, 0.02), attempt=2),
    response("c2", CLAUDE, usage_row=usage(0.0, True, 0.03)),
    response("d1", DEEPSEEK, usage_row=usage(0.004, False, 0.0035)),
    response("d2", DEEPSEEK, usage_row=usage(0.006)),
    response("d3", DEEPSEEK, ok=False, status=429, error="rate limited"),
]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def runner_dir(path: Path, responses: list[dict]) -> Path:
    parsed = {"request_id": "c2", "item_id": "V1", "paired_item_key": "P1", "model": CLAUDE, "dataset_family": "manual",
              "label": "vulnerable", "defense": "neutral", "attack_family": "clean", "attack_goal": "none",
              "repeat": 0, "prompt_version": "v2", "ok": True, "verdict": "vulnerable", "confidence": 0.9,
              "correct": True}
    write_jsonl(path / "parsed.jsonl", [parsed])
    write_jsonl(path / "responses.jsonl", responses)
    return path


def load(out: Path, name: str) -> dict:
    return json.loads((out / f"{name}.json").read_text(encoding="utf-8"))


def find(records: list[dict], **keys) -> dict:
    matches = [r for r in records if all(r.get(k) == v for k, v in keys.items())]
    assert len(matches) == 1, matches
    return matches[0]


def test_runner_cost_counts_every_billed_row_and_splits_openrouter_from_byok(tmp_path):
    run_dir = runner_dir(tmp_path / "run", RESPONSES)
    out = tmp_path / "out"
    main(["--run-dir", str(run_dir), "--out-dir", str(out), "--analyses", "cost_report"])

    data = load(out, "cost_report")
    [run] = data["runs"]
    assert run["run_dir"] == str(run_dir)
    assert run["log"] == "responses.jsonl"
    assert (run["rows"], run["ok_rows"], run["failed_rows"]) == (6, 4, 2)
    assert run["openrouter_usd"] == pytest.approx(0.011)
    assert run["byok_upstream_usd"] == pytest.approx(0.06)
    assert run["total_usd"] == pytest.approx(0.071)

    claude = find(run["by_model"], model=CLAUDE)
    assert (claude["rows"], claude["ok_rows"], claude["failed_rows"], claude["byok_rows"]) == (3, 2, 1, 3)
    assert claude["openrouter_usd"] == pytest.approx(0.001)
    assert claude["byok_upstream_usd"] == pytest.approx(0.06)
    assert claude["total_usd"] == pytest.approx(0.061)

    deepseek = find(run["by_model"], model=DEEPSEEK)
    assert (deepseek["rows"], deepseek["ok_rows"], deepseek["failed_rows"], deepseek["byok_rows"]) == (3, 2, 1, 0)
    assert deepseek["openrouter_usd"] == pytest.approx(0.010)
    assert deepseek["byok_upstream_usd"] == 0
    assert deepseek["total_usd"] == pytest.approx(0.010)

    assert data["total_usd"] == pytest.approx(0.071)
    markdown = (out / "cost_report.md").read_text(encoding="utf-8")
    assert CLAUDE in markdown and "0.0610" in markdown


GPT = "openai/gpt-6.1-sol"


def step(task: str, number: int, role: str, model: str, ok: bool = True, usage_row: dict | None = None,
         attempt: int = 1) -> dict:
    """A steps.jsonl row as adaptive_attack._Session.send logs it."""
    request_id = f"{task}:{number}:{role}"
    reply = response(request_id, model, ok=ok, usage_row=usage_row)
    reply.pop("model")
    usage_row = usage_row or {}
    cost = usage_row.get("cost", 0) + usage_row.get("cost_details", {}).get("upstream_inference_cost", 0)
    return {"request_id": request_id, "task_id": task, "step": number, "role": role, "attempt": attempt, "ok": ok,
            "cost": cost, "request": {"request_id": request_id, "role": role, "model": model, "task_id": task,
                                      "step": number}, "response": reply}


STEPS = [
    step("t1", 1, "attacker", GPT, ok=False, attempt=1),
    step("t1", 1, "attacker", GPT, usage_row=usage(0.002), attempt=2),
    step("t1", 1, "detector", CLAUDE, usage_row=usage(0.0, True, 0.05)),
    step("t1", 2, "attacker", GPT, usage_row=usage(0.003)),
    step("t1", 2, "detector", CLAUDE, ok=False, usage_row=usage(0.0, True, 0.04)),
]


def test_adaptive_cost_comes_from_steps_per_role_and_model_without_a_scored_run(tmp_path):
    adaptive = tmp_path / "adaptive"
    write_jsonl(adaptive / "steps.jsonl", STEPS)
    write_jsonl(adaptive / "outcomes.jsonl", [])
    out = tmp_path / "out"
    main(["--adaptive-run-dir", str(adaptive), "--out-dir", str(out)])

    [run] = load(out, "cost_report")["runs"]
    assert (run["run_dir"], run["log"]) == (str(adaptive), "steps.jsonl")
    assert (run["rows"], run["failed_rows"]) == (5, 2)
    attacker = find(run["by_model"], model=GPT, role="attacker")
    assert (attacker["rows"], attacker["failed_rows"]) == (3, 1)
    assert attacker["openrouter_usd"] == pytest.approx(0.005)
    assert attacker["byok_upstream_usd"] == 0
    detector = find(run["by_model"], model=CLAUDE, role="detector")
    assert detector["byok_upstream_usd"] == pytest.approx(0.09)
    assert run["total_usd"] == pytest.approx(0.095)
    assert not (out / "score_shift.json").exists()


def test_runner_and_adaptive_costs_are_reported_side_by_side(tmp_path):
    run_dir = runner_dir(tmp_path / "run", RESPONSES)
    adaptive = tmp_path / "adaptive"
    write_jsonl(adaptive / "steps.jsonl", STEPS)
    out = tmp_path / "out"
    main(["--run-dir", str(run_dir), "--adaptive-run-dir", str(adaptive), "--out-dir", str(out),
          "--analyses", "cost_report"])

    data = load(out, "cost_report")
    assert [(r["run_dir"], r["log"]) for r in data["runs"]] == [
        (str(run_dir), "responses.jsonl"), (str(adaptive), "steps.jsonl")
    ]
    assert find(data["runs"][0]["by_model"], model=CLAUDE)["role"] == "detector"
    assert data["total_usd"] == pytest.approx(0.071 + 0.095)
    assert data["openrouter_usd"] == pytest.approx(0.011 + 0.005)
    assert data["byok_upstream_usd"] == pytest.approx(0.06 + 0.09)
    assert data["provenance"]["adaptive_runs"] == [str(adaptive)]


def test_refuses_to_write_inside_an_adaptive_run_directory(tmp_path):
    adaptive = tmp_path / "adaptive"
    write_jsonl(adaptive / "steps.jsonl", STEPS)
    with pytest.raises(SystemExit):
        main(["--adaptive-run-dir", str(adaptive), "--out-dir", str(adaptive / "revision")])
    assert sorted(p.name for p in adaptive.iterdir()) == ["steps.jsonl"]


def test_needs_at_least_one_run_directory(tmp_path):
    with pytest.raises(SystemExit):
        main(["--out-dir", str(tmp_path / "out")])

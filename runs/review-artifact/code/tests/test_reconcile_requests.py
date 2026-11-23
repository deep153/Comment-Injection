from __future__ import annotations

import json
from pathlib import Path

from openrouter_eval.common import append_jsonl, read_jsonl
from openrouter_eval.reconcile_requests import reconcile
from openrouter_eval.run_openrouter import run_requests

PINNED = {"only": ["google-ai-studio"]}


def request(rid: str, provider: dict | None = PINNED, max_tokens: int = 2048) -> dict:
    return {"request_id": rid, "model": "google/gemini-3.8-flash", "variant_id": "neutral:clean",
            "provider": provider, "max_tokens": max_tokens}


def response(rid: str, ok: bool = True, finish: str = "stop", provider: str = "Google AI Studio") -> dict:
    return {"request_id": rid, "ok": ok, "raw": {"provider": provider, "choices": [{"finish_reason": finish}]}}


def write_run(tmp_path: Path, requests: list[dict], responses: list[dict], retry_max_tokens: int = 8192) -> None:
    append_jsonl(tmp_path / "requests.jsonl", requests)
    append_jsonl(tmp_path / "responses.jsonl", responses)
    (tmp_path / "run_config.json").write_text(json.dumps({"retry_truncated_max_tokens": retry_max_tokens}))


def test_restores_pins_and_marks_answers_from_follow_up_passes(tmp_path: Path) -> None:
    # The last pass ran with --allow-byok-fallback, so every row lost its pin and token limit.
    requests = [request(rid, provider=None) for rid in ("plain", "truncated", "fallback", "failed")]
    responses = [
        response("plain"),
        response("truncated", finish="length"),
        response("fallback", ok=False),
        response("truncated"),
        response("fallback", provider="Google"),
        response("failed", ok=False),
    ]
    write_run(tmp_path, requests, responses)

    reconcile(tmp_path)

    rows = {row["request_id"]: row for row in read_jsonl(tmp_path / "requests.jsonl")}
    assert rows["plain"]["provider"] == PINNED and rows["plain"]["max_tokens"] == 2048
    assert rows["truncated"]["provider"] == PINNED and rows["truncated"]["max_tokens"] == 8192
    assert rows["fallback"]["provider"] is None and rows["fallback"]["max_tokens"] == 2048
    assert rows["failed"]["provider"] == PINNED


def test_settings_recorded_in_response_rows_take_precedence(tmp_path: Path) -> None:
    final = {**response("r1"), "request_max_tokens": 4096, "request_provider": None}
    write_run(tmp_path, [request("r1")], [final])

    reconcile(tmp_path)

    row = read_jsonl(tmp_path / "requests.jsonl")[0]
    assert row["max_tokens"] == 4096 and row["provider"] is None


def test_runner_records_request_settings_in_each_response_row(tmp_path: Path) -> None:
    def call(req: dict) -> dict:
        return {"request_id": req["request_id"], "ok": True, "status": 200,
                "raw": {"choices": [{"finish_reason": "stop"}], "usage": {"cost": 0.001}}}

    run_requests([request("r1", max_tokens=8192)], tmp_path, dry_run=False, max_calls=None,
                 sleep_seconds=0, concurrency=1, call=call)

    row = read_jsonl(tmp_path / "responses.jsonl")[0]
    assert row["request_max_tokens"] == 8192
    assert row["request_provider"] == PINNED

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from openrouter_eval.common import read_jsonl, response_cost
from openrouter_eval.run_openrouter import run_requests


FIXTURES = Path(__file__).parent / "fixtures"


def make_requests(count: int) -> list[dict]:
    return [
        {"request_id": f"req{index}", "model": "openai/gpt-6.1-sol", "variant_id": "neutral:clean"}
        for index in range(count)
    ]


class FakeCall:
    """Stands in for the OpenRouter call: every answer reports the same usage cost."""

    def __init__(self, cost: float, byok: bool = False) -> None:
        self.cost = cost
        self.byok = byok
        self.calls: list[str] = []

    def __call__(self, request: dict) -> dict:
        self.calls.append(request["request_id"])
        usage = {"cost": 0, "is_byok": True, "cost_details": {"upstream_inference_cost": self.cost}}
        if not self.byok:
            usage = {"cost": self.cost, "is_byok": False, "cost_details": {"upstream_inference_cost": self.cost}}
        return {
            "request_id": request["request_id"],
            "ok": True,
            "status": 200,
            "raw": {"choices": [{"finish_reason": "stop"}], "usage": usage},
        }


def saved_ids(out_dir: Path) -> list[str]:
    return [row["request_id"] for row in read_jsonl(out_dir / "responses.jsonl")]


def test_run_stops_once_spend_reaches_ceiling(tmp_path: Path) -> None:
    call = FakeCall(cost=0.4)
    with pytest.raises(SystemExit, match="rerun"):
        run_requests(make_requests(5), tmp_path, dry_run=False, max_calls=None, sleep_seconds=0,
                     concurrency=1, max_cost_usd=1.0, call=call)
    assert call.calls == ["req0", "req1", "req2"]
    assert saved_ids(tmp_path) == ["req0", "req1", "req2"]


def test_resume_counts_spend_already_recorded(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        run_requests(make_requests(5), tmp_path, dry_run=False, max_calls=None, sleep_seconds=0,
                     concurrency=1, max_cost_usd=1.0, call=FakeCall(cost=0.4, byok=True))

    resumed = FakeCall(cost=0.4)
    with pytest.raises(SystemExit, match="rerun"):
        run_requests(make_requests(5), tmp_path, dry_run=False, max_calls=None, sleep_seconds=0,
                     concurrency=1, max_cost_usd=1.0, call=resumed)
    assert resumed.calls == []

    raised = FakeCall(cost=0.4)
    with pytest.raises(SystemExit, match="rerun"):
        run_requests(make_requests(5), tmp_path, dry_run=False, max_calls=None, sleep_seconds=0,
                     concurrency=1, max_cost_usd=1.5, call=raised)
    assert raised.calls == ["req3"]
    assert saved_ids(tmp_path) == ["req0", "req1", "req2", "req3"]


class InFlightFakeCall(FakeCall):
    """Holds the first `width` calls until all of them are in flight, as a concurrent pool would."""

    def __init__(self, cost: float, width: int) -> None:
        super().__init__(cost)
        self.width = width
        self.barrier = threading.Barrier(width, timeout=5)
        self.lock = threading.Lock()

    def __call__(self, request: dict) -> dict:
        with self.lock:
            index = len(self.calls)
            response = super().__call__(request)
        if index < self.width:
            self.barrier.wait()
        return response


def test_concurrent_run_starts_nothing_after_ceiling(tmp_path: Path) -> None:
    call = InFlightFakeCall(cost=0.4, width=4)
    with pytest.raises(SystemExit, match="rerun"):
        run_requests(make_requests(20), tmp_path, dry_run=False, max_calls=None, sleep_seconds=0,
                     concurrency=4, max_cost_usd=0.4, call=call)
    assert sorted(call.calls) == ["req0", "req1", "req2", "req3"]
    assert sorted(saved_ids(tmp_path)) == ["req0", "req1", "req2", "req3"]


def test_run_without_ceiling_calls_everything(tmp_path: Path) -> None:
    call = FakeCall(cost=0.4)
    run_requests(make_requests(5), tmp_path, dry_run=False, max_calls=None, sleep_seconds=0,
                 concurrency=1, call=call)
    assert saved_ids(tmp_path) == ["req0", "req1", "req2", "req3", "req4"]


class FlakyCall(FakeCall):
    """Content-filters the first answer to each request (billed), then answers normally."""

    def __call__(self, request: dict) -> dict:
        response = super().__call__(request)
        if self.calls.count(request["request_id"]) == 1:
            response.update(ok=False, error="content_filter")
        return response


def test_billed_failed_attempts_are_saved_before_the_retry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("openrouter_eval.run_openrouter.time.sleep", lambda _: None)
    run_requests(make_requests(2), tmp_path, dry_run=False, max_calls=None, sleep_seconds=0,
                 concurrency=1, call=FlakyCall(cost=0.4))
    rows = read_jsonl(tmp_path / "responses.jsonl")
    assert [(r["request_id"], r["ok"], r["attempt"]) for r in rows] == [
        ("req0", False, 1), ("req0", True, 2), ("req1", False, 1), ("req1", True, 2),
    ]
    assert all(r["model"] == "openai/gpt-6.1-sol" for r in rows)
    assert sum(response_cost(r) for r in rows) == pytest.approx(1.6)


def v2_rows() -> dict[str, dict]:
    return {row["request_id"]: row for row in read_jsonl(FIXTURES / "v2_response_usage_rows.jsonl")}


@pytest.mark.parametrize(
    ("request_id", "expected"),
    [
        ("faf26c483fd751db", 0.001609),  # GPT, billed by OpenRouter
        ("dade1386d2fa2f91", 0.00021472971),  # DeepSeek, billed by OpenRouter
        ("ff38cc8ba05c003b", 0.005072),  # Claude, BYOK: cost 0, upstream 0.005072
        ("47ccd5c2b75b79a3", 0.002253),  # Gemini, BYOK: cost 0, upstream 0.002253
        ("cfe0dc1d2022607b", 0.0),  # failed BYOK call with zero usage
        ("9b402e429b24ec07", 0.0),  # failed call without usage
    ],
)
def test_response_cost_on_v2_rows(request_id: str, expected: float) -> None:
    assert response_cost(v2_rows()[request_id]) == pytest.approx(expected)

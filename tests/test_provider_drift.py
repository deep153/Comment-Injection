from __future__ import annotations

from openrouter_eval.run_openrouter import embedded_error, request_payload, response_format_for_model


def make_request(model: str, response_format: dict | None) -> dict:
    return {
        "request_id": "r1",
        "model": model,
        "messages": [{"role": "user", "content": "x"}],
        "temperature": 0,
        "max_tokens": 2048,
        "response_format": response_format,
        "reasoning": {"effort": "minimal", "exclude": True},
        "provider": None,
    }


def test_claude_requests_carry_no_response_format_and_others_keep_json_mode() -> None:
    assert response_format_for_model("anthropic/claude-sonnet-5.5") is None
    for slug in ("openai/gpt-6.1-sol", "google/gemini-3.8-flash", "deepseek/deepseek-v4-pro"):
        assert response_format_for_model(slug) == {"type": "json_object"}


def test_payload_omits_response_format_when_unset() -> None:
    assert "response_format" not in request_payload(make_request("anthropic/claude-sonnet-5.5", None))
    payload = request_payload(make_request("openai/gpt-6.1-sol", {"type": "json_object"}))
    assert payload["response_format"] == {"type": "json_object"}


def test_content_filter_stop_is_a_failure_to_retry() -> None:
    raw = {"choices": [{"finish_reason": "content_filter", "message": {"content": '{"verdict":"vul'}}]}
    assert embedded_error(raw) is not None


def test_normal_stop_and_length_are_not_failures() -> None:
    for reason in ("stop", "length"):
        assert embedded_error({"choices": [{"finish_reason": reason, "message": {"content": "{}"}}]}) is None

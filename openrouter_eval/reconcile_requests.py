from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .common import append_jsonl, read_jsonl
from .run_openrouter import BYOK_PROVIDERS, is_truncated, provider_for_model

# Provider names in OpenRouter responses for the pinned bring-your-own-key routes.
PINNED_PROVIDER_NAMES = {"anthropic": "Anthropic", "google-ai-studio": "Google AI Studio"}


def reconcile(run_dir: Path) -> None:
    """Rewrite requests.jsonl so each row's max_tokens and provider are the ones its final answer used.

    Each runner invocation rewrites requests.jsonl with its own settings, so after the follow-up passes
    (--retry-truncated-max-tokens, --allow-byok-fallback) the file no longer says which pass answered.
    Newer response rows record the settings; for older rows they are inferred: an answer that follows a
    truncated answer came from the truncated-retry pass, and an answer from a provider other than the
    pinned one came from the fallback pass.
    """
    config = json.loads((run_dir / "run_config.json").read_text(encoding="utf-8"))
    retry_max_tokens = config.get("retry_truncated_max_tokens")
    base_max_tokens = config.get("max_tokens", 2048)
    requests = read_jsonl(run_dir / "requests.jsonl")
    final: dict[str, dict[str, Any]] = {}
    after_truncation: set[str] = set()
    for row in read_jsonl(run_dir / "responses.jsonl"):
        if not row.get("ok"):
            continue
        rid = row["request_id"]
        if rid in final and is_truncated(final[rid]):
            after_truncation.add(rid)
        final[rid] = row
    for request in requests:
        pinned = provider_for_model(request["model"], byok_only=True)
        request["provider"] = pinned
        request["max_tokens"] = base_max_tokens
        answer = final.get(request["request_id"])
        if not answer:
            continue
        if "request_max_tokens" in answer:
            request["max_tokens"] = answer["request_max_tokens"]
            request["provider"] = answer["request_provider"]
            continue
        if request["request_id"] in after_truncation and retry_max_tokens:
            request["max_tokens"] = retry_max_tokens
        byok = next((p for prefix, p in BYOK_PROVIDERS.items() if request["model"].startswith(prefix)), None)
        if byok and (answer.get("raw") or {}).get("provider") != PINNED_PROVIDER_NAMES[byok]:
            request["provider"] = None
    path = run_dir / "requests.jsonl"
    path.write_text("", encoding="utf-8")
    append_jsonl(path, requests)


def main() -> None:
    parser = argparse.ArgumentParser(description="Record in requests.jsonl the settings each final answer used.")
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    reconcile(args.run_dir)
    print(f"reconciled {args.run_dir / 'requests.jsonl'}")


if __name__ == "__main__":
    main()

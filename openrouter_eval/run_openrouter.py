from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from threading import Event, Lock
from typing import Any

from .common import DEFAULT_MODELS, append_jsonl, read_jsonl, relative_to, safe_read, sha256_text, stable_id, write_json
from .prompts import PROMPT_VERSION, build_messages, variants_for_label


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


MODEL_SETTING_KEYS = {"slug", "reasoning_effort"}


def load_models(path: Path | None) -> dict[str, str | dict[str, str]]:
    """Map model key to a slug, or to {"slug": ..., "reasoning_effort": ...} for per-model settings."""
    if not path:
        return DEFAULT_MODELS
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return {model.replace("/", "_").replace("-", "_").replace(".", "_"): model for model in data}
    for key, entry in data.items():
        if isinstance(entry, dict) and ("slug" not in entry or set(entry) - MODEL_SETTING_KEYS):
            raise SystemExit(
                f"{path}: model {key!r} needs a 'slug' and only {sorted(MODEL_SETTING_KEYS)}; got {sorted(entry)}"
            )
    return dict(data)


def model_slug_and_effort(entry: str | dict[str, str], default_effort: str) -> tuple[str, str]:
    if isinstance(entry, str):
        return entry, default_effort
    return entry["slug"], entry.get("reasoning_effort", default_effort)


def reasoning_for_model(model: str, effort: str) -> dict[str, Any]:
    if effort != "auto":
        return {"effort": effort, "exclude": True}
    # These endpoints reject requests with reasoning disabled ("Reasoning is mandatory").
    if model.startswith(("anthropic/", "google/", "openai/")):
        return {"effort": "minimal", "exclude": True}
    return {"effort": "none", "exclude": True}


BYOK_PROVIDERS = {"anthropic/": "anthropic", "google/": "google-ai-studio"}


def provider_for_model(model: str, byok_only: bool = True) -> dict[str, Any] | None:
    """Provider routing per model.

    OpenAI: prefer the half-price flex tier; max_price ($ per million tokens) blocks fallback to
    priority tiers. DeepSeek: cheapest host, fp8 only, so every answer comes from the same precision.
    BYOK models: pin to the provider holding the user's key, because OpenRouter otherwise falls back
    to its own (billed) endpoints when that provider errors.
    """
    if model.startswith("openai/"):
        return {"order": ["openai/flex"], "max_price": {"prompt": 2.2, "completion": 11}}
    if model.startswith("deepseek/"):
        return {"sort": "price", "quantizations": ["fp8"]}
    for prefix, provider in BYOK_PROVIDERS.items():
        if byok_only and model.startswith(prefix):
            return {"only": [provider]}
    return None


def compose_source(item: dict[str, Any], dataset_root: Path, max_chars: int) -> tuple[str, bool, int]:
    """Concatenate an item's files without paths, which can reveal the label."""
    texts = [
        safe_read(dataset_root / rec["path"])
        for rec in item.get("source_paths", [])
        if (dataset_root / rec["path"]).is_file()
    ]
    if len(texts) == 1:
        text = texts[0]
        if len(text) > max_chars:
            return text[:max_chars] + "\n// [TRUNCATED]\n", True, 1
        return text, False, 1
    chunks: list[str] = []
    truncated = False
    for index, text in enumerate(texts, start=1):
        section = f"// File {index} of {len(texts)}\n{text}"
        if chunks and sum(len(c) for c in chunks) + len(section) > max_chars:
            truncated = True
            break
        if len(section) > max_chars:
            section = section[:max_chars] + "\n// [TRUNCATED]\n"
            truncated = True
        chunks.append(section)
    return "\n\n".join(chunks), truncated, len(texts)


def in_repeat_sample(item: dict[str, Any], fraction: float) -> bool:
    """Select whole vulnerable/fixed pairs deterministically, so both sides are repeated together."""
    key = item.get("paired_item_key") or item["item_id"]
    return int(sha256_text(f"repeat::{key}")[:8], 16) % 10_000 < fraction * 10_000


def build_requests(
    manifest: list[dict[str, Any]],
    dataset_root: Path,
    models: dict[str, str | dict[str, str]],
    max_source_chars: int,
    limit: int | None,
    limit_per_family: int | None,
    families: set[str] | None,
    attack_families: set[str] | None,
    defenses: set[str] | None,
    max_tokens: int,
    reasoning_effort: str,
    extended_families: set[str] = frozenset(),
    repeat_families: set[str] = frozenset(),
    repeat_fraction: float = 0.0,
    repeat_count: int = 0,
    byok_only: bool = True,
) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = []
    filtered = [item for item in manifest if not families or item["dataset_family"] in families]
    if limit_per_family is not None:
        family_counts: dict[str, int] = {}
        family_limited = []
        for item in filtered:
            family = item["dataset_family"]
            count = family_counts.get(family, 0)
            if count >= limit_per_family:
                continue
            family_counts[family] = count + 1
            family_limited.append(item)
        filtered = family_limited
    if limit is not None:
        filtered = filtered[:limit]
    for item in filtered:
        source, truncated, file_count = compose_source(item, dataset_root, max_source_chars)
        if not file_count:
            continue
        item_notes = list(item.get("eligibility_notes", []))
        if truncated:
            item_notes.append("source_truncated_for_context_budget")
        extended = item["dataset_family"] in extended_families
        repeats = 1
        if item["dataset_family"] in repeat_families and in_repeat_sample(item, repeat_fraction):
            repeats += repeat_count
        for model_key, model_entry in models.items():
            model_slug, model_effort = model_slug_and_effort(model_entry, reasoning_effort)
            for variant in variants_for_label(item["label"], extended=extended):
                if attack_families and variant.attack_family not in attack_families:
                    continue
                if defenses and variant.defense not in defenses:
                    continue
                messages, prompt_meta = build_messages(source, variant)
                for repeat in range(repeats):
                    request_id = stable_id(
                        item["item_id"], model_slug, variant.variant_id, prompt_meta["prompt_sha256"], repeat
                    )
                    requests.append(
                        {
                            "request_id": request_id,
                            "item_id": item["item_id"],
                            "model_key": model_key,
                            "model": model_slug,
                            "messages": messages,
                            "temperature": 0,
                            "max_tokens": max_tokens,
                            "response_format": {"type": "json_object"},
                            "reasoning": reasoning_for_model(model_slug, model_effort),
                            "provider": provider_for_model(model_slug, byok_only),
                            "variant_id": variant.variant_id,
                            "repeat": repeat,
                            "design": "extended" if extended else "core",
                            **prompt_meta,
                            "label": item["label"],
                            "dataset_family": item["dataset_family"],
                            "sample_role": item["sample_role"],
                            "case_id": item.get("case_id"),
                            "pair_id": item.get("pair_id"),
                            "source_path": item.get("source_path"),
                            "eligibility_notes": item_notes,
                        }
                    )
    return requests


def openrouter_call(api_key: str, request: dict[str, Any], app_title: str) -> dict[str, Any]:
    payload = {
        "model": request["model"],
        "messages": request["messages"],
        "temperature": request["temperature"],
        "max_tokens": request["max_tokens"],
        "response_format": request["response_format"],
        "reasoning": request["reasoning"],
    }
    if request.get("provider"):
        payload["provider"] = request["provider"]
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OPENROUTER_URL,
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://localhost/comment-injection",
            "X-Title": app_title,
        },
        method="POST",
    )
    started = time.time()
    with urllib.request.urlopen(req, timeout=180) as resp:
        raw = json.loads(resp.read().decode("utf-8", errors="replace"))
    error = embedded_error(raw)
    return {
        "request_id": request["request_id"],
        "ok": error is None,
        "status": 200 if error is None else (error.get("code") or 500),
        "latency_seconds": round(time.time() - started, 3),
        "raw": raw,
        **({"error": json.dumps(error)} if error else {}),
    }


def embedded_error(raw: dict[str, Any]) -> dict[str, Any] | None:
    """OpenRouter can return HTTP 200 with a provider error or no choices; treat those as failures."""
    if raw.get("error"):
        return raw["error"] if isinstance(raw["error"], dict) else {"message": str(raw["error"])}
    choices = raw.get("choices") or []
    if not choices:
        return {"code": 502, "message": "no choices in response"}
    if choices[0].get("finish_reason") == "error":
        err = choices[0].get("error")
        return err if isinstance(err, dict) else {"code": 502, "message": "finish_reason=error"}
    return None


def is_budget_error(status: int | None, body: str) -> bool:
    """Spending-limit and credit errors will not clear by retrying, so the run should stop."""
    return status == 402 or (status == 403 and "limit" in body.lower())


def is_truncated(response: dict[str, Any]) -> bool:
    choices = (response.get("raw") or {}).get("choices") or [{}]
    return choices[0].get("finish_reason") == "length"


def run_requests(
    requests: list[dict[str, Any]],
    out_dir: Path,
    dry_run: bool,
    max_calls: int | None,
    sleep_seconds: float,
    concurrency: int,
    retry_truncated_max_tokens: int | None = None,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    responses_path = out_dir / "responses.jsonl"
    successes = [row for row in read_jsonl(responses_path) if row.get("ok")]
    completed = {row["request_id"] for row in successes}
    if retry_truncated_max_tokens:
        untruncated = {row["request_id"] for row in successes if not is_truncated(row)}
        retry = completed - untruncated
        completed = untruncated
        for request in requests:
            if request["request_id"] in retry:
                request["max_tokens"] = retry_truncated_max_tokens
        print(f"re-querying {len(retry)} truncated responses with max_tokens={retry_truncated_max_tokens}")
    requests_path = out_dir / "requests.jsonl"
    requests_path.write_text("", encoding="utf-8")
    append_jsonl(requests_path, requests)
    print(f"wrote {len(requests)} requests to {requests_path}")
    if dry_run:
        print("dry run requested; no OpenRouter calls made")
        return

    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise SystemExit("OPENROUTER_API_KEY is not set; cannot call OpenRouter.")

    remaining = [r for r in requests if r["request_id"] not in completed]
    if max_calls is not None:
        remaining = remaining[:max_calls]
    print(f"{len(completed)} already complete; calling {len(remaining)} requests")

    stop = Event()

    def call_with_retries(request: dict[str, Any]) -> dict[str, Any] | None:
        response: dict[str, Any]
        for attempt in range(1, 4):
            if stop.is_set():
                return None
            try:
                response = openrouter_call(api_key, request, "comment-injection-rust")
                if response["ok"]:
                    break
                response["attempt"] = attempt
                if attempt == 3:
                    break
                time.sleep(2 * attempt)
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                response = {
                    "request_id": request["request_id"],
                    "ok": False,
                    "status": exc.code,
                    "error": body,
                    "attempt": attempt,
                }
                if is_budget_error(exc.code, body):
                    if not stop.is_set():
                        print(f"stopping: OpenRouter budget error {exc.code}: {body[:200]}", flush=True)
                    stop.set()
                    return None
                if exc.code not in {408, 409, 429, 500, 502, 503, 504} or attempt == 3:
                    break
                time.sleep(2 * attempt)
            except Exception as exc:  # noqa: BLE001 - record enough for audit.
                response = {
                    "request_id": request["request_id"],
                    "ok": False,
                    "status": None,
                    "error": repr(exc),
                    "attempt": attempt,
                }
                if attempt == 3:
                    break
                time.sleep(2 * attempt)
        if sleep_seconds:
            time.sleep(sleep_seconds)
        response["model"] = request["model"]
        response["variant_id"] = request["variant_id"]
        return response

    lock = Lock()
    done = 0

    def persist(response: dict[str, Any] | None) -> None:
        nonlocal done
        if response is None:
            return
        with lock:
            append_jsonl(responses_path, [response])
            done += 1
            print(
                f"{done}/{len(remaining)} {response.get('model')} "
                f"{response.get('variant_id')} ok={response.get('ok')}",
                flush=True,
            )

    if concurrency <= 1:
        for request in remaining:
            if stop.is_set():
                break
            persist(call_with_retries(request))
    else:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [pool.submit(call_with_retries, request) for request in remaining]
            for future in as_completed(futures):
                persist(future.result())
    if stop.is_set():
        raise SystemExit(
            f"run stopped after {done} saved responses; top up the key or credits and rerun "
            "the same command to resume."
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and optionally execute OpenRouter requests.")
    parser.add_argument("--dataset-root", type=Path, default=Path("rust-vuln-dataset"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--models", type=Path)
    parser.add_argument("--max-source-chars", type=int, default=120_000)
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--reasoning-effort", default="auto")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--limit-per-family", type=int)
    parser.add_argument("--families", nargs="*")
    parser.add_argument("--attack-families", nargs="*")
    parser.add_argument("--defenses", nargs="*")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--max-calls", type=int)
    parser.add_argument("--sleep-seconds", type=float, default=0.0)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument(
        "--extended-families",
        nargs="*",
        default=["manual"],
        help="Families that also get benign, inline, Rust-style, tag-escape, and comment-stripped prompts.",
    )
    parser.add_argument("--repeat-families", nargs="*", default=["manual"])
    parser.add_argument("--repeat-fraction", type=float, default=0.1, help="Fraction of pairs to repeat.")
    parser.add_argument("--repeat-count", type=int, default=2, help="Extra repeats per sampled prompt.")
    parser.add_argument(
        "--allow-byok-fallback",
        action="store_true",
        help="Let BYOK models fall back to OpenRouter-billed endpoints (use only for a final pass over failures).",
    )
    parser.add_argument(
        "--retry-truncated-max-tokens",
        type=int,
        help="Re-query responses cut off at max_tokens with this larger limit; other requests keep --max-tokens.",
    )
    args = parser.parse_args()

    previous_config = args.out_dir / "run_config.json"
    if not args.dry_run and previous_config.exists() and read_jsonl(args.out_dir / "responses.jsonl"):
        previous_version = json.loads(previous_config.read_text(encoding="utf-8")).get("prompt_version")
        if previous_version != PROMPT_VERSION:
            raise SystemExit(
                f"{args.out_dir} holds responses from prompt version {previous_version!r}, not "
                f"{PROMPT_VERSION!r}; use a new --out-dir so results are not mixed."
            )

    dataset_root = args.dataset_root.resolve()
    manifest = read_jsonl(args.manifest)
    models = load_models(args.models)
    metadata = {
        "dataset_root": str(dataset_root),
        "manifest": relative_to(args.manifest.resolve(), Path.cwd()) if args.manifest.resolve().is_relative_to(Path.cwd()) else str(args.manifest),
        "models": models,
        "max_source_chars": args.max_source_chars,
        "max_tokens": args.max_tokens,
        "reasoning_effort": args.reasoning_effort,
        "prompt_version": PROMPT_VERSION,
        "extended_families": args.extended_families,
        "repeat_families": args.repeat_families,
        "repeat_fraction": args.repeat_fraction,
        "repeat_count": args.repeat_count,
        "allow_byok_fallback": args.allow_byok_fallback,
        "retry_truncated_max_tokens": args.retry_truncated_max_tokens,
    }
    write_json(args.out_dir / "run_config.json", metadata)
    requests = build_requests(
        manifest=manifest,
        dataset_root=dataset_root,
        models=models,
        max_source_chars=args.max_source_chars,
        limit=args.limit,
        limit_per_family=args.limit_per_family,
        families=set(args.families) if args.families else None,
        attack_families=set(args.attack_families) if args.attack_families else None,
        defenses=set(args.defenses) if args.defenses else None,
        max_tokens=args.max_tokens,
        reasoning_effort=args.reasoning_effort,
        extended_families=set(args.extended_families),
        repeat_families=set(args.repeat_families),
        repeat_fraction=args.repeat_fraction,
        repeat_count=args.repeat_count,
        byok_only=not args.allow_byok_fallback,
    )
    run_requests(
        requests,
        args.out_dir,
        args.dry_run,
        args.max_calls,
        args.sleep_seconds,
        args.concurrency,
        args.retry_truncated_max_tokens,
    )


if __name__ == "__main__":
    main()

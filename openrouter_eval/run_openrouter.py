from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from threading import Lock
from typing import Any

from .common import DEFAULT_MODELS, append_jsonl, read_jsonl, relative_to, safe_read, stable_id, write_json
from .prompts import build_messages, variants_for_label


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


def load_models(path: Path | None) -> dict[str, str]:
    if not path:
        return DEFAULT_MODELS
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return {model.replace("/", "_").replace("-", "_").replace(".", "_"): model for model in data}
    return dict(data)


def reasoning_for_model(model: str, effort: str) -> dict[str, Any]:
    if effort != "auto":
        return {"effort": effort, "exclude": True}
    if model.startswith("anthropic/") or model.startswith("google/"):
        return {"effort": "minimal", "exclude": True}
    return {"effort": "none", "exclude": True}


def compose_source(item: dict[str, Any], dataset_root: Path, max_chars: int) -> tuple[str, bool]:
    chunks: list[str] = []
    truncated = False
    for rec in item.get("source_paths", []):
        rel = rec["path"]
        path = dataset_root / rel
        if path.is_dir():
            continue
        text = safe_read(path)
        section = f"// FILE: {rel}\n{text}"
        if chunks and sum(len(c) for c in chunks) + len(section) > max_chars:
            truncated = True
            break
        if len(section) > max_chars:
            section = section[:max_chars] + "\n// [TRUNCATED]\n"
            truncated = True
        chunks.append(section)
    return "\n\n".join(chunks), truncated


def build_requests(
    manifest: list[dict[str, Any]],
    dataset_root: Path,
    models: dict[str, str],
    max_source_chars: int,
    limit: int | None,
    limit_per_family: int | None,
    families: set[str] | None,
    attack_families: set[str] | None,
    defenses: set[str] | None,
    max_tokens: int,
    reasoning_effort: str,
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
        source, truncated = compose_source(item, dataset_root, max_source_chars)
        if not source.strip():
            continue
        item_notes = list(item.get("eligibility_notes", []))
        if truncated:
            item_notes.append("source_truncated_for_context_budget")
        item_for_prompt = {**item, "eligibility_notes": item_notes}
        for model_key, model_slug in models.items():
            for variant in variants_for_label(item["label"]):
                if attack_families and variant.attack_family not in attack_families:
                    continue
                if defenses and variant.defense not in defenses:
                    continue
                messages, prompt_meta = build_messages(source, variant, item_for_prompt)
                request_id = stable_id(item["item_id"], model_slug, variant.variant_id, prompt_meta["prompt_sha256"])
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
                        "reasoning": reasoning_for_model(model_slug, reasoning_effort),
                        "variant_id": variant.variant_id,
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
    with urllib.request.urlopen(req, timeout=120) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return {
        "request_id": request["request_id"],
        "ok": True,
        "status": 200,
        "latency_seconds": round(time.time() - started, 3),
        "raw": json.loads(raw),
    }


def run_requests(
    requests: list[dict[str, Any]],
    out_dir: Path,
    dry_run: bool,
    max_calls: int | None,
    sleep_seconds: float,
    concurrency: int,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
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

    responses_path = out_dir / "responses.jsonl"
    completed = {row["request_id"] for row in read_jsonl(responses_path) if row.get("ok")}
    remaining = [r for r in requests if r["request_id"] not in completed]
    if max_calls is not None:
        remaining = remaining[:max_calls]
    print(f"{len(completed)} already complete; calling {len(remaining)} requests")

    def call_with_retries(request: dict[str, Any]) -> dict[str, Any]:
        response: dict[str, Any]
        for attempt in range(1, 4):
            try:
                response = openrouter_call(api_key, request, "comment-injection-rust")
                break
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                response = {
                    "request_id": request["request_id"],
                    "ok": False,
                    "status": exc.code,
                    "error": body,
                    "attempt": attempt,
                }
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

    def persist(response: dict[str, Any]) -> None:
        nonlocal done
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
            persist(call_with_retries(request))
        return

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(call_with_retries, request) for request in remaining]
        for future in as_completed(futures):
            persist(future.result())


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and optionally execute OpenRouter requests.")
    parser.add_argument("--dataset-root", type=Path, default=Path("rust-vuln-dataset"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--models", type=Path)
    parser.add_argument("--max-source-chars", type=int, default=120_000)
    parser.add_argument("--max-tokens", type=int, default=1200)
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
    args = parser.parse_args()

    dataset_root = args.dataset_root.resolve()
    manifest = read_jsonl(args.manifest)
    models = load_models(args.models)
    metadata = {
        "dataset_root": str(dataset_root),
        "manifest": relative_to(args.manifest.resolve(), Path.cwd()) if args.manifest.resolve().is_relative_to(Path.cwd()) else str(args.manifest),
        "models": models,
        "max_source_chars": args.max_source_chars,
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
    )
    run_requests(requests, args.out_dir, args.dry_run, args.max_calls, args.sleep_seconds, args.concurrency)


if __name__ == "__main__":
    main()

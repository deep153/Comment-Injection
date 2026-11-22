from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator

from ...common import cost_parts
from ..base import Context, Result

NAME = "cost_report"
FIELDS = ("rows", "ok_rows", "failed_rows", "byok_rows", "openrouter_usd", "byok_upstream_usd", "total_usd")


def stream(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def tally(rows: Iterator[tuple[tuple[str, str], dict[str, Any]]]) -> dict[tuple[str, str], dict[str, float]]:
    """Totals per (role, model) over every recorded response, failed attempts and retries included."""
    totals: dict[tuple[str, str], dict[str, float]] = defaultdict(lambda: dict.fromkeys(FIELDS, 0))
    for key, response in rows:
        openrouter, upstream = cost_parts(response)
        entry = totals[key]
        entry["rows"] += 1
        entry["ok_rows" if response.get("ok") else "failed_rows"] += 1
        entry["byok_rows"] += 1 if ((response.get("raw") or {}).get("usage") or {}).get("is_byok") else 0
        entry["openrouter_usd"] += openrouter
        entry["byok_upstream_usd"] += upstream
        entry["total_usd"] += openrouter + upstream
    return totals


def runner_rows(run_dir: Path) -> Iterator[tuple[tuple[str, str], dict[str, Any]]]:
    for response in stream(run_dir / "responses.jsonl"):
        yield ("detector", str(response.get("model"))), response


def adaptive_rows(run_dir: Path) -> Iterator[tuple[tuple[str, str], dict[str, Any]]]:
    for step in stream(run_dir / "steps.jsonl"):
        yield (str(step.get("role")), str((step.get("request") or {}).get("model"))), step.get("response") or {}


def summarise(run_dir: Path, log: str, totals: dict[tuple[str, str], dict[str, float]]) -> dict[str, Any]:
    by_model = [{"role": role, "model": model, **entry} for (role, model), entry in sorted(totals.items())]
    return {
        "run_dir": str(run_dir),
        "log": log,
        **{field: sum(entry[field] for entry in by_model) for field in FIELDS},
        "by_model": by_model,
    }


def run(ctx: Context) -> Result | None:
    runs = [
        summarise(source.run_dir, "responses.jsonl", tally(runner_rows(source.run_dir)))
        for source in ctx.data.runs
        if (source.run_dir / "responses.jsonl").exists()
    ] + [
        summarise(source.run_dir, "steps.jsonl", tally(adaptive_rows(source.run_dir)))
        for source in ctx.data.adaptive
        if (source.run_dir / "steps.jsonl").exists()
    ]
    if not runs:
        return None
    lines = [
        "Every recorded response row counts, including failed attempts and retries, since each was billed. "
        "OpenRouter USD is the `cost` OpenRouter charged; BYOK upstream USD is `cost_details.upstream_inference_cost` "
        "on bring-your-own-key routes, billed to the user's own provider key rather than to OpenRouter credits.",
        "",
        "| Run | Log | Role | Model | Rows | Failed | BYOK rows | OpenRouter USD | BYOK upstream USD | Total USD |",
        "|---|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in runs:
        for m in r["by_model"] + [{"role": "", "model": "**all**", **{field: r[field] for field in FIELDS}}]:
            lines.append(
                f"| `{r['run_dir']}` | {r['log']} | {m['role']} | {m['model']} | {m['rows']} | {m['failed_rows']} | {m['byok_rows']} | "
                f"{m['openrouter_usd']:.4f} | {m['byok_upstream_usd']:.4f} | {m['total_usd']:.4f} |"
            )
    total = {field: sum(r[field] for r in runs) for field in ("openrouter_usd", "byok_upstream_usd", "total_usd")}
    lines += ["", f"Total over all runs: {total['total_usd']:.4f} USD ({total['openrouter_usd']:.4f} OpenRouter, "
              f"{total['byok_upstream_usd']:.4f} BYOK upstream)."]
    return Result(title="Cost per run from recorded usage", payload={"runs": runs, **total}, markdown=lines)

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from ..base import Context, Result, fmt
from ..runs import AdaptiveRun, cluster_of
from ..stats import bootstrap_meta, cluster_bootstrap, percentile, ratio_of_sums

NAME = "adaptive_summary"
CONDITION = ("model", "defense", "attacker_mode", "feedback_mode", "attacker_model", "query_budget")


def eligible(row: dict[str, Any]) -> bool:
    """Clean verdict correct for this model and defense, as for the conditional flip rate.

    The adaptive planner already runs only such tasks; this drops rows whose recorded clean verdict says otherwise.
    """
    truth = "vulnerable" if row.get("label") == "vulnerable" else "safe"
    return row.get("clean_verdict") not in {"vulnerable", "safe"} - {truth}


def step_task_ids(run_dir: Path) -> set[str]:
    path = run_dir / "steps.jsonl"
    if not path.exists():
        return set()
    with path.open("r", encoding="utf-8") as f:
        return {json.loads(line)["task_id"] for line in f if line.strip()}


def describe_run(run: AdaptiveRun) -> dict[str, Any]:
    done = {row["task_id"] for row in run.outcomes}
    return {
        "run_dir": str(run.run_dir),
        "outcomes": len(run.outcomes),
        "tasks_without_outcome": len(step_task_ids(run.run_dir) - done),
    }


def summarise(rows: list[dict[str, Any]], excluded: int, budget: int, resamples: int, seed: int) -> dict[str, Any]:
    n = len(rows)
    steps = sorted(r["first_success_step"] for r in rows if r.get("attack_success"))
    counts = {str(k): steps.count(k) for k in range(1, budget + 1)}
    per_cluster: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])
    for r in rows:
        per_cluster[cluster_of(r)][0] += 1.0 if r.get("attack_success") else 0.0
        per_cluster[cluster_of(r)][1] += 1
    clusters = [tuple(per_cluster[key]) for key in sorted(per_cluster)]
    interval = cluster_bootstrap(clusters, ratio_of_sums, resamples, seed)
    return {
        "eligible": n,
        "excluded_clean_wrong": excluded,
        "successes": len(steps),
        "success_rate": len(steps) / n if n else None,
        "ci_low": interval["ci_low"],
        "ci_high": interval["ci_high"],
        "clusters": len(clusters),
        "first_success_counts": counts,
        "cumulative_success_by_query": [
            sum(1 for s in steps if s <= k) / n if n else None for k in range(1, budget + 1)
        ],
        "median_queries_to_success": percentile(steps, 0.5) if steps else None,
        "mean_queries_to_success": sum(steps) / len(steps) if steps else None,
        "queries_used": sum(r["queries_used"] for r in rows),
        "detector_queries": sum(r["detector_queries"] for r in rows),
        "rejected_candidates": sum(r["rejected_candidates"] for r in rows),
        "tasks_with_rejections": sum(1 for r in rows if r["rejected_candidates"]),
    }


def run(ctx: Context) -> Result | None:
    outcomes = [{**row, "source_run": str(run.run_dir)} for run in ctx.data.adaptive for row in run.outcomes]
    if not outcomes:
        return None
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in outcomes:
        groups[tuple(row.get(k) for k in CONDITION)].append(row)
    records = []
    for key, group in sorted(groups.items(), key=lambda item: tuple(str(k) for k in item[0])):
        kept = [r for r in group if eligible(r)]
        records.append(
            {
                **dict(zip(CONDITION, key)),
                **summarise(kept, len(group) - len(kept), key[-1], ctx.args.bootstrap, ctx.args.seed),
                "source_runs": sorted({r["source_run"] for r in group}),
                "prompt_versions": sorted({str(r.get("prompt_version")) for r in group}),
            }
        )
    lines = [
        "Eligible tasks: the model's clean verdict under that defense was correct. Success: the detector gave the "
        "attacker's target verdict within the query budget. Every attacker candidate uses one query; rejected "
        "candidates (malformed or changing executable code) use a query without reaching the detector. "
        "95% interval: cluster bootstrap over vulnerable/fixed pairs.",
        "",
        "| Detector | Defense | Attacker mode | Feedback | Attacker | Eligible | Successes | Success rate (95% CI) | "
        "Cumulative success by query | Median queries to success | Rejected candidates |",
        "|---|---|---|---|---|---:|---:|---:|---|---:|---:|",
    ]
    for r in records:
        curve = ", ".join(fmt(v, 2) for v in r["cumulative_success_by_query"])
        lines.append(
            f"| `{r['model']}` | {r['defense']} | {r['attacker_mode']} | {r['feedback_mode']} | `{r['attacker_model']}` | "
            f"{r['eligible']} | {r['successes']} | {fmt(r['success_rate'])} ({fmt(r['ci_low'])}, {fmt(r['ci_high'])}) | "
            f"{curve} | {fmt(r['median_queries_to_success'], 1)} | {r['rejected_candidates']} |"
        )
    runs = [describe_run(run) for run in ctx.data.adaptive]
    incomplete = sum(r["tasks_without_outcome"] for r in runs)
    if incomplete:
        lines += ["", f"{incomplete} task(s) have logged steps but no outcome (a call failed); they are not counted."]
    return Result(
        title="Adaptive attack: success within budget",
        payload={"bootstrap": bootstrap_meta(ctx.args.bootstrap, ctx.args.seed), "runs": runs, "by_condition": records},
        markdown=lines,
    )

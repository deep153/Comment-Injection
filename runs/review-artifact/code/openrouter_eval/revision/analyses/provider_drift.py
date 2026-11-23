from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
from typing import Any

from ...score_results import rate, vulnerability_score
from ..base import Context, Result, fmt
from ..runs import JOIN_KEY, cluster_of, load_runs
from ..stats import bootstrap_meta, cluster_bootstrap, ratio_of_sums

NAME = "provider_drift"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--reanchor-run-dir", type=Path,
        help="Scored re-anchor run (e.g. neutral clean prompts re-asked later); compared row by row with the "
             "matching --run-dir rows to measure provider drift. Kept out of the joined rows.",
    )


def parses(row: dict[str, Any]) -> bool:
    return row.get("verdict") in {"vulnerable", "safe"}


def interval(pairs: list[tuple[dict[str, Any], dict[str, Any]]], value, ctx: Context) -> dict[str, Any]:
    """Cluster-bootstrap mean of `value(base, reanchor)` over pairs where it is defined."""
    per_cluster: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])
    for base, new in pairs:
        v = value(base, new)
        if v is not None:
            per_cluster[cluster_of(new)][0] += v
            per_cluster[cluster_of(new)][1] += 1
    clusters = [tuple(per_cluster[key]) for key in sorted(per_cluster)]
    result = cluster_bootstrap(clusters, ratio_of_sums, ctx.args.bootstrap, ctx.args.seed)
    return {**result, "n": int(sum(c[1] for c in clusters))}


def score_change(base: dict[str, Any], new: dict[str, Any]) -> float | None:
    before, after = vulnerability_score(base), vulnerability_score(new)
    return None if before is None or after is None else after - before


def run(ctx: Context) -> Result | None:
    if ctx.args.reanchor_run_dir is None:
        return None
    reanchor = load_runs([ctx.args.reanchor_run_dir], ctx.data.family)
    base = {tuple(r.get(k) for k in JOIN_KEY): r for r in ctx.data.rows}
    groups: dict[tuple[Any, ...], list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    for new in reanchor.rows:
        old = base.get(tuple(new.get(k) for k in JOIN_KEY))
        if old is not None:
            groups[(new["model"], new["defense"], new["attack_family"])].append((old, new))
    if not groups:
        return None
    records = []
    for (model, defense, condition), pairs in sorted(groups.items()):
        both = [(b, n) for b, n in pairs if parses(b) and parses(n)]
        records.append(
            {
                "model": model,
                "defense": defense,
                "condition": condition,
                "matched": len(pairs),
                "base_accuracy": rate([b for b, _ in pairs], "correct"),
                "reanchor_accuracy": rate([n for _, n in pairs], "correct"),
                "accuracy_change": interval(pairs, lambda b, n: float(bool(n.get("correct"))) - float(bool(b.get("correct"))), ctx),
                "agreement": rate([{"agree": b["verdict"] == n["verdict"]} for b, n in both], "agree"),
                "score_change": interval(pairs, score_change, ctx),
            }
        )
    [source] = reanchor.runs
    lines = [
        f"Re-anchor run: `{source.run_dir}` (prompt version {', '.join(source.prompt_versions)}). Each re-anchor row "
        "is matched to the main-run row with the same model, item, defense and condition; unmatched rows are "
        "ignored. Accuracy counts an unparseable verdict as wrong. Agreement and score change use only pairs "
        "where both verdicts parse; score change is re-anchor minus main-run vulnerability score. Accuracy and "
        f"score changes carry 95% cluster-bootstrap intervals over pairs ({ctx.args.bootstrap} resamples, "
        f"seed {ctx.args.seed}).",
        "",
        "| Model | Defense | Condition | Matched | Accuracy (main) | Accuracy (re-anchor) | Accuracy change [95% CI] "
        "| Verdict agreement | Score change [95% CI] |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in records:
        acc, score = r["accuracy_change"], r["score_change"]
        lines.append(
            f"| `{r['model']}` | {r['defense']} | {r['condition']} | {r['matched']} | {fmt(r['base_accuracy']['rate'])} | "
            f"{fmt(r['reanchor_accuracy']['rate'])} | {fmt(acc['estimate'])} [{fmt(acc['ci_low'])}, {fmt(acc['ci_high'])}] | "
            f"{fmt(r['agreement']['rate'])} ({r['agreement']['count']}/{r['agreement']['n']}) | "
            f"{fmt(score['estimate'])} [{fmt(score['ci_low'])}, {fmt(score['ci_high'])}] |"
        )
    return Result(
        title="Provider drift between the main runs and the re-anchor",
        payload={
            "reanchor_run": source.describe(),
            "bootstrap": bootstrap_meta(ctx.args.bootstrap, ctx.args.seed),
            "by_model_defense_condition": records,
        },
        markdown=lines,
    )

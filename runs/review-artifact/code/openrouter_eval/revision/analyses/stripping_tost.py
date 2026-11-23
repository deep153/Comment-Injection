from __future__ import annotations

import argparse
from collections import defaultdict
from typing import Any

from ..base import Context, Result, fmt
from ..inference import cluster_mean, tost
from ..runs import cluster_of, sources

NAME = "stripping_tost"
POOLED = "all"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tost-margin", type=float, default=0.05,
                        help="Equivalence margin for stripped minus neutral clean accuracy (default 0.05).")


def paired_clean(rows: list[dict[str, Any]]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """(neutral, stripped) clean rows of the same model and item."""
    clean = {(r["model"], r["item_id"], r["defense"]): r for r in rows if r.get("attack_family") == "clean"}
    return [
        (row, clean[(model, item, "stripped")])
        for (model, item, defense), row in sorted(clean.items())
        if defense == "neutral" and (model, item, "stripped") in clean
    ]


def equivalence(pairs: list[tuple[dict[str, Any], dict[str, Any]]], margin: float) -> dict[str, Any]:
    per_cluster: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])
    for neutral, stripped in pairs:
        per_cluster[cluster_of(neutral)][0] += bool(stripped.get("correct")) - bool(neutral.get("correct"))
        per_cluster[cluster_of(neutral)][1] += 1
    clusters = [tuple(per_cluster[key]) for key in sorted(per_cluster)]
    mean, se = cluster_mean(clusters)
    n = len(pairs)
    return {
        "n_items": n,
        "clusters": len(clusters),
        "neutral_accuracy": sum(bool(p[0].get("correct")) for p in pairs) / n,
        "stripped_accuracy": sum(bool(p[1].get("correct")) for p in pairs) / n,
        "difference": mean,
        "se": se,
        **tost(mean, se, margin),
        **sources([p[0] for p in pairs] + [p[1] for p in pairs]),
    }


def run(ctx: Context) -> Result | None:
    pairs = paired_clean(ctx.data.rows)
    if not pairs:
        return None
    margin = ctx.args.tost_margin
    groups: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    for pair in pairs:
        groups[pair[0]["model"]].append(pair)
    results = [{"model": model, **equivalence(group, margin)} for model, group in sorted(groups.items())]
    results.append({"model": POOLED, **equivalence(pairs, margin)})
    lines = [
        f"Stripped minus neutral clean accuracy, paired by model and item. TOST with margin +/-{margin:g}: "
        "two one-sided z-tests at alpha 0.05 with a cluster-robust standard error over vulnerable/fixed pairs; "
        "equivalence is declared when the 90% interval lies inside the margin. The pooled row combines models.",
        "",
        "| Model | Items | Pairs | Neutral acc. | Stripped acc. | Difference | 90% CI | p (TOST) | Equivalent |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for r in results:
        lines.append(
            f"| `{r['model']}` | {r['n_items']} | {r['clusters']} | {fmt(r['neutral_accuracy'])} | "
            f"{fmt(r['stripped_accuracy'])} | {fmt(r['difference'])} | [{fmt(r['ci90_low'])}, {fmt(r['ci90_high'])}] | "
            f"{r['p_tost']:.3g} | {'yes' if r['equivalent'] else 'no'} |"
        )
    return Result(
        title="Equivalence of stripped and neutral clean accuracy (TOST)",
        payload={"margin": margin, "alpha": 0.05, "test": "TOST, z, cluster-robust SE", "results": results},
        markdown=lines,
    )

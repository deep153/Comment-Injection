from __future__ import annotations

from collections import defaultdict
from typing import Any

from ...score_results import vulnerability_score
from ..base import Context, Result, fmt
from ..runs import baseline_key, clean_baselines, cluster_of, is_attack, sources
from ..stats import bootstrap_meta, cluster_bootstrap, ratio_of_sums

NAME = "score_shift"
GOAL_SIGN = {"induction": 1.0, "suppression": -1.0}


def shifts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attacked minus clean vulnerability score, signed so positive moves toward the attacker's target."""
    clean = clean_baselines(rows)
    out = []
    for row in rows:
        baseline = clean.get(baseline_key(row))
        if not is_attack(row) or baseline is None:
            continue
        base = vulnerability_score(baseline)
        score = vulnerability_score(row)
        if base is None or score is None:
            continue
        out.append({**row, "baseline": baseline, "shift": GOAL_SIGN[row["attack_goal"]] * (score - base)})
    return out


def run(ctx: Context) -> Result | None:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in shifts(ctx.data.rows):
        groups[(row["model"], row["attack_goal"], row["defense"])].append(row)
    if not groups:
        return None
    resamples, seed = ctx.args.bootstrap, ctx.args.seed
    records = []
    for (model, goal, defense), group in sorted(groups.items()):
        per_cluster: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])
        for r in group:
            per_cluster[cluster_of(r)][0] += r["shift"]
            per_cluster[cluster_of(r)][1] += 1
        clusters = [tuple(per_cluster[key]) for key in sorted(per_cluster)]
        interval = cluster_bootstrap(clusters, ratio_of_sums, resamples, seed)
        records.append(
            {
                "model": model,
                "goal": goal,
                "defense": defense,
                "n": len(group),
                "clusters": len(clusters),
                "mean_shift": interval["estimate"],
                "ci_low": interval["ci_low"],
                "ci_high": interval["ci_high"],
                **sources(group),
            }
        )
    lines = [
        "Shift = attacked minus clean vulnerability score (same item, model, defense), signed so that positive "
        "values move toward the attacker's target (safe for suppression, vulnerable for induction). "
        f"95% cluster-bootstrap intervals over pairs ({resamples} resamples, seed {seed}).",
        "",
        "| Model | Goal | Defense | n | Pairs | Mean shift | 95% CI |",
        "|---|---|---|---:|---:|---:|---:|",
    ]
    for r in records:
        lines.append(
            f"| `{r['model']}` | {r['goal']} | {r['defense']} | {r['n']} | {r['clusters']} | "
            f"{fmt(r['mean_shift'])} | [{fmt(r['ci_low'])}, {fmt(r['ci_high'])}] |"
        )
    return Result(
        title="Within-defense confidence-score shift toward the attacker's target",
        payload={"bootstrap": bootstrap_meta(resamples, seed), "by_model_goal_defense": records},
        markdown=lines,
    )

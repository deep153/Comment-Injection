from __future__ import annotations

from collections import defaultdict
from typing import Any, Sequence

from ..base import Context, Result, fmt
from ..inference import holm, mcnemar_exact
from ..runs import attacks_with_baseline, cluster_of, sources
from ..stats import bootstrap_meta, cluster_bootstrap

NAME = "defense_contrasts"
POOLED = "all"
# (baseline, defense): the difference is defense minus baseline.
CONTRASTS = (
    ("neutral", "warning"),
    ("neutral", "tagged"),
    ("neutral", "placebo"),
    ("placebo", "warning"),
    ("placebo", "tagged"),
)
METRICS = ("conditional_flip", "attack_success")

Pair = tuple[dict[str, Any], dict[str, Any]]


def matched_pairs(rows: list[dict[str, Any]], baseline: str, defense: str, metric: str) -> list[Pair]:
    """Attacked prompts matched on model, item and attack family; conditional flips need both clean verdicts correct."""
    by_key = {(r["model"], r["item_id"], r["attack_family"], r["defense"]): r for r in rows}
    pairs = []
    for (model, item, family, name), row in sorted(by_key.items()):
        other = by_key.get((model, item, family, defense))
        if name != baseline or other is None:
            continue
        if metric == "conditional_flip" and not (row["clean_correct"] and other["clean_correct"]):
            continue
        pairs.append((row, other))
    return pairs


def difference(clusters: Sequence[tuple[int, int, int]]) -> float | None:
    total = sum(c[2] for c in clusters)
    return (sum(c[1] for c in clusters) - sum(c[0] for c in clusters)) / total if total else None


def compare(pairs: list[Pair], resamples: int, seed: int) -> dict[str, Any]:
    per_cluster: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    baseline_only = defense_only = 0
    for a, b in pairs:
        hit_a, hit_b = bool(a.get("attack_success")), bool(b.get("attack_success"))
        cell = per_cluster[cluster_of(a)]
        cell[0] += hit_a
        cell[1] += hit_b
        cell[2] += 1
        baseline_only += hit_a and not hit_b
        defense_only += hit_b and not hit_a
    clusters = [tuple(per_cluster[key]) for key in sorted(per_cluster)]
    interval = cluster_bootstrap(clusters, difference, resamples, seed)
    n = len(pairs)
    involved = [row for pair in pairs for row in pair]
    return {
        "n_pairs": n,
        "clusters": len(clusters),
        "baseline_rate": sum(c[0] for c in clusters) / n,
        "defense_rate": sum(c[1] for c in clusters) / n,
        "difference": interval["estimate"],
        "ci_low": interval["ci_low"],
        "ci_high": interval["ci_high"],
        "baseline_only": baseline_only,
        "defense_only": defense_only,
        "p_mcnemar": mcnemar_exact(baseline_only, defense_only),
        **sources(involved),
    }


def run(ctx: Context) -> Result | None:
    rows = attacks_with_baseline(ctx.data.rows)
    present = {r["defense"] for r in rows}
    chosen = [c for c in CONTRASTS if set(c) <= present]
    skipped = [
        {"baseline": a, "defense": b, "reason": f"no attacked rows for {', '.join(sorted({a, b} - present))}"}
        for a, b in CONTRASTS
        if (a, b) not in chosen
    ]
    if not chosen:
        return None
    resamples, seed = ctx.args.bootstrap, ctx.args.seed
    records = []
    for metric in METRICS:
        per_model = []
        for baseline, defense in chosen:
            groups: dict[tuple[str, str], list[Pair]] = defaultdict(list)
            for pair in matched_pairs(rows, baseline, defense, metric):
                goal = pair[0]["attack_goal"]
                groups[(pair[0]["model"], goal)].append(pair)
                groups[(POOLED, goal)].append(pair)
            for (model, goal), pairs in sorted(groups.items()):
                record = {"metric": metric, "model": model, "goal": goal, "baseline": baseline, "defense": defense,
                          **compare(pairs, resamples, seed), "p_holm": None}
                records.append(record)
                if model != POOLED:
                    per_model.append(record)
        for record, adjusted in zip(per_model, holm([r["p_mcnemar"] for r in per_model])):
            record["p_holm"] = adjusted
    lines = [
        "Paired defense contrasts. Attacked prompts are matched on model, item and attack family across the two "
        "defenses; the difference is defense minus baseline. `conditional_flip` keeps matched prompts whose clean "
        "verdict (same model, item and defense) was correct under both defenses and compares attack success, the "
        "conditional flip rate; `attack_success` keeps every matched prompt (raw ASR). Intervals: 95% cluster "
        f"bootstrap over vulnerable/fixed pairs ({resamples} resamples, seed {seed}). Exact McNemar on discordant "
        "prompts; Holm adjustment over the per-model tests of each metric (pooled rows are not adjusted).",
        "",
        "| Metric | Model | Goal | Contrast | Pairs | Clusters | Baseline | Defense | Difference | 95% CI | "
        "Discordant (b/d) | p | p (Holm) |",
        "|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in records:
        holm_p = "n/a" if r["p_holm"] is None else f"{r['p_holm']:.3g}"
        lines.append(
            f"| {r['metric']} | `{r['model']}` | {r['goal']} | {r['defense']} - {r['baseline']} | {r['n_pairs']} | "
            f"{r['clusters']} | {fmt(r['baseline_rate'])} | {fmt(r['defense_rate'])} | {fmt(r['difference'])} | "
            f"[{fmt(r['ci_low'])}, {fmt(r['ci_high'])}] | {r['baseline_only']}/{r['defense_only']} | "
            f"{r['p_mcnemar']:.3g} | {holm_p} |"
        )
    if skipped:
        lines += ["", "Skipped: " + "; ".join(f"{s['defense']} - {s['baseline']} ({s['reason']})" for s in skipped) + "."]
    return Result(
        title="Paired defense contrasts on conditional flip rate and attack success",
        payload={"bootstrap": bootstrap_meta(resamples, seed), "contrasts": records, "skipped": skipped},
        markdown=lines,
    )

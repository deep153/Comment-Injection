from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..base import Context, Result, fmt
from ..runs import sources
from ..stats import bin_index, bin_labels

NAME = "calibration"
EDGES = (0.0, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0)


def confidence(row: dict[str, Any]) -> float | None:
    try:
        value = float(row.get("confidence"))
    except (TypeError, ValueError):
        return None
    return value if 0.0 <= value <= 1.0 else None


def clean_trials(rows: list[dict[str, Any]]) -> list[tuple[dict[str, Any], float, float]]:
    out = []
    for row in rows:
        if row.get("attack_family") != "clean" or row.get("verdict") not in {"vulnerable", "safe"}:
            continue
        conf = confidence(row)
        if conf is not None:
            out.append((row, conf, 1.0 if row.get("correct") else 0.0))
    return out


def summarise(trials: list[tuple[dict[str, Any], float, float]]) -> dict[str, Any]:
    n = len(trials)
    labels = bin_labels(EDGES)
    binned: list[list[tuple[float, float]]] = [[] for _ in labels]
    for _row, conf, hit in trials:
        binned[bin_index(conf, EDGES)].append((conf, hit))
    bins = []
    for label, members in zip(labels, binned):
        k = len(members)
        bins.append(
            {
                "bin": label,
                "n": k,
                "mean_confidence": sum(c for c, _ in members) / k if k else None,
                "accuracy": sum(h for _, h in members) / k if k else None,
            }
        )
    return {
        "n": n,
        "accuracy": sum(h for _, _, h in trials) / n,
        "mean_confidence": sum(c for _, c, _ in trials) / n,
        "ece": sum(b["n"] / n * abs(b["accuracy"] - b["mean_confidence"]) for b in bins if b["n"]),
        "brier": sum((c - h) ** 2 for _, c, h in trials) / n,
        "bins": bins,
    }


def run(ctx: Context) -> Result | None:
    groups: dict[tuple[Any, ...], list[tuple[dict[str, Any], float, float]]] = defaultdict(list)
    for trial in clean_trials(ctx.data.rows):
        groups[(trial[0]["model"], trial[0]["defense"])].append(trial)
    if not groups:
        return None
    records = [
        {"model": model, "defense": defense, **summarise(trials), **sources([t[0] for t in trials])}
        for (model, defense), trials in sorted(groups.items())
    ]
    lines = [
        "Clean prompts only. Confidence is the model's stated confidence in its own verdict; accuracy is the share of "
        "correct verdicts. ECE = expected calibration error over the bins below; Brier = mean (confidence - correct)^2.",
        "",
        "| Model | Defense | n | Accuracy | Mean confidence | ECE | Brier |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for r in records:
        lines.append(
            f"| `{r['model']}` | {r['defense']} | {r['n']} | {fmt(r['accuracy'])} | {fmt(r['mean_confidence'])} | "
            f"{fmt(r['ece'])} | {fmt(r['brier'])} |"
        )
    lines += ["", "## Reliability bins (n: accuracy at mean confidence)", ""]
    labels = bin_labels(EDGES)
    lines += ["| Model | Defense | " + " | ".join(labels) + " |", "|---|---|" + "---:|" * len(labels)]
    for r in records:
        cells = [
            f"{b['n']}: {fmt(b['accuracy'], 2)} @ {fmt(b['mean_confidence'], 2)}" if b["n"] else "0"
            for b in r["bins"]
        ]
        lines.append(f"| `{r['model']}` | {r['defense']} | " + " | ".join(cells) + " |")
    return Result(
        title="Confidence calibration on clean prompts",
        payload={"bin_edges": list(EDGES), "by_model_defense": records},
        markdown=lines,
    )

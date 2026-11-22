from __future__ import annotations

import argparse
import math
import re
import time
import warnings
from typing import Any

from ..base import Context, Result
from ..runs import attacks_with_baseline, cluster_of, is_attack

NAME = "defense_gee"
OUTCOMES = ("attack_success", "conditional_flip")
REFERENCES = {"defense": "neutral", "style": "dsc", "goal": "suppression", "placement": "top"}
# Larger |log odds| than this (odds ratio beyond ~22,000) means separation, not an estimate.
UNSTABLE_LOG_ODDS = 10.0


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--gee-maxiter", type=int, default=60, help="Iteration limit for each GEE fit (default 60).")


def design_rows(rows: list[dict[str, Any]], outcome: str) -> list[dict[str, Any]]:
    out = []
    for row in attacks_with_baseline(rows):
        if outcome == "conditional_flip" and not row["clean_correct"]:
            continue
        out.append(
            {
                "success": int(bool(row.get("attack_success"))),
                "defense": row["defense"],
                "goal": row["attack_goal"],
                "style": row["attack_family"].split("_")[1],
                "placement": "inline" if (row.get("placement") or "top").startswith("inline") else "top",
                "model": row["model"],
                "cluster": cluster_of(row),
            }
        )
    return out


def factor(df: Any, name: str) -> str:
    reference = REFERENCES.get(name)
    if reference is not None and reference in set(df[name]):
        return f"C({name}, Treatment('{reference}'))"
    return f"C({name})"


def formula(df: Any, crossed: tuple[str, ...], additive: tuple[str, ...]) -> str | None:
    varying = lambda names: [factor(df, n) for n in names if df[n].nunique() > 1]
    crossed_terms = varying(crossed)
    if not crossed_terms or "defense" not in crossed_terms[0]:
        return None
    return "success ~ " + " + ".join(["*".join(crossed_terms), *varying(additive)])


def label(term: str) -> str:
    """`C(defense, Treatment('neutral'))[T.warning]` -> `defense[warning]`."""
    term = re.sub(r"C\((\w+)(?:, Treatment\('[^']*'\))?\)", r"\1", term)
    return term.replace("[T.", "[")


def fit(rows: list[dict[str, Any]], crossed: tuple[str, ...], additive: tuple[str, ...], maxiter: int,
        wald: bool = False) -> dict[str, Any]:
    import pandas as pd
    import statsmodels.api as sm
    import statsmodels.formula.api as smf

    df = pd.DataFrame(rows)
    record: dict[str, Any] = {"n": len(df), "clusters": int(df["cluster"].nunique()), "terms": [], "notes": []}
    spec = formula(df, crossed, additive)
    record["formula"] = spec
    if spec is None:
        return {**record, "status": "skipped", "notes": ["fewer than two defenses"], "seconds": 0.0}
    started = time.perf_counter()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            model = smf.gee(spec, groups="cluster", data=df, family=sm.families.Binomial(),
                            cov_struct=sm.cov_struct.Exchangeable())
            result = model.fit(maxiter=maxiter)
            conf = result.conf_int()
            tests = result.wald_test_terms(scalar=True).summary_frame() if wald else None
        except Exception as exc:  # noqa: BLE001 - any fitting failure is reported, not raised
            return {**record, "status": "failed", "notes": [f"{type(exc).__name__}: {exc}"],
                    "seconds": time.perf_counter() - started}
    record["seconds"] = time.perf_counter() - started
    messages = sorted({f"{w.category.__name__}: {w.message}" for w in caught})
    params, bse = result.params, result.bse
    unstable = [t for t in params.index if not math.isfinite(bse[t]) or abs(params[t]) > UNSTABLE_LOG_ODDS]
    if not getattr(result, "converged", True) or any("ConvergenceWarning" in m for m in messages):
        record["status"] = "not converged"
    elif unstable or any("Separation" in m for m in messages):
        record["status"] = "unstable"
        if unstable:
            messages.append(f"non-finite SE or |log odds| > {UNSTABLE_LOG_ODDS:g}: {', '.join(map(label, unstable))}")
    else:
        record["status"] = "converged"
    record["notes"] = messages
    record["working_correlation"] = float(result.cov_struct.dep_params)
    for term in params.index:
        record["terms"].append(
            {
                "term": term,
                "label": label(term),
                "odds_ratio": safe_exp(params[term]),
                "ci_low": safe_exp(conf.loc[term, 0]),
                "ci_high": safe_exp(conf.loc[term, 1]),
                "p_value": float(result.pvalues[term]),
            }
        )
    if tests is not None:
        record["wald_tests"] = [
            {"term": label(name), "chi2": float(row["chi2"]), "df": int(row["df constraint"]),
             "p_value": float(row["P>chi2"])}
            for name, row in tests.iterrows()
            if name != "Intercept"
        ]
    return record


def safe_exp(value: float) -> float:
    return math.exp(min(float(value), 700.0)) if math.isfinite(value) else float("nan")


def run(ctx: Context) -> Result | None:
    maxiter = ctx.args.gee_maxiter
    per_model, pooled = [], []
    started = time.perf_counter()
    for outcome in OUTCOMES:
        rows = design_rows(ctx.data.rows, outcome)
        if not rows:
            continue
        for model in sorted({r["model"] for r in rows}):
            subset = [r for r in rows if r["model"] == model]
            per_model.append({"outcome": outcome, "model": model,
                              **fit(subset, ("defense",), ("style", "goal", "placement"), maxiter)})
        pooled.append({"outcome": outcome, **fit(rows, ("defense", "goal", "model"), ("style", "placement"), maxiter,
                                                 wald=True)})
    if not per_model:
        return None
    seconds = time.perf_counter() - started
    defenses = sorted({r["defense"] for r in ctx.data.rows if is_attack(r)})
    return Result(
        title="GEE logistic models of attack success: per model and model-by-defense-by-goal",
        payload={
            "outcomes": [o for o in OUTCOMES if any(f["outcome"] == o for f in per_model)],
            "reference_defense": REFERENCES["defense"] if REFERENCES["defense"] in defenses else None,
            "defenses": defenses,
            "working_correlation": "exchangeable",
            "gee_maxiter": maxiter,
            "seconds_total": seconds,
            "per_model": per_model,
            "pooled": pooled,
        },
        markdown=markdown(per_model, pooled, seconds),
    )


def fmt_or(term: dict[str, Any]) -> str:
    return f"{term['odds_ratio']:.2f} [{term['ci_low']:.2f}, {term['ci_high']:.2f}], p={term['p_value']:.2g}"


def markdown(per_model: list[dict[str, Any]], pooled: list[dict[str, Any]], seconds: float) -> list[str]:
    lines = [
        "Logistic GEE with an exchangeable working correlation, clustered by vulnerable/fixed pair, as in "
        "`analyze_gee`. Outcome `attack_success` uses every attacked prompt (raw ASR); `conditional_flip` uses "
        "attacked prompts whose clean verdict (same model, item and defense) was correct. Per-model fits: defense + "
        "style + goal (+ placement). Pooled fit: defense x goal x model, plus style and placement. References: "
        "neutral defense, DSC style, suppression goal, top placement. Status `unstable` flags separation (an odds "
        f"ratio beyond e^{UNSTABLE_LOG_ODDS:g} or a non-finite SE); such estimates should not be reported. "
        f"Total fitting time {seconds:.1f}s.",
    ]
    for outcome in OUTCOMES:
        fits = [f for f in per_model if f["outcome"] == outcome]
        if not fits:
            continue
        defense_labels = sorted({t["label"] for f in fits for t in f["terms"] if re.fullmatch(r"defense\[\w+\]", t["label"])})
        lines += ["", f"## Per-model defense odds ratios ({outcome})", "",
                  "| Model | n | Pairs | Status | " + " | ".join(defense_labels) + " |",
                  "|---|---:|---:|---|" + "---:|" * len(defense_labels)]
        for f in fits:
            terms = {t["label"]: t for t in f["terms"]}
            cells = " | ".join(fmt_or(terms[d]) if d in terms else "n/a" for d in defense_labels)
            lines.append(f"| `{f['model']}` | {f['n']} | {f['clusters']} | {f['status']} | {cells} |")
        for f in pooled:
            if f["outcome"] != outcome:
                continue
            lines += ["", f"## Pooled defense x goal x model ({outcome})", "",
                      f"n={f['n']}, pairs={f['clusters']}, status: {f['status']}, {f['seconds']:.1f}s.", ""]
            if f.get("wald_tests"):
                lines += ["| Term (joint Wald test) | chi2 | df | p |", "|---|---:|---:|---:|"]
                lines += [f"| `{w['term']}` | {w['chi2']:.2f} | {w['df']} | {w['p_value']:.2g} |" for w in f["wald_tests"]]
                lines.append("")
            lines += ["| Term | Odds ratio [95% CI], p |", "|---|---:|"]
            lines += [f"| `{t['label']}` | {fmt_or(t)} |" for t in f["terms"] if "defense" in t["label"]]
        notes = [(f.get("model", "pooled"), f["status"], n) for f in fits + [p for p in pooled if p["outcome"] == outcome]
                 for n in f["notes"]]
        if notes:
            lines += ["", "Fit notes:", ""] + [f"- `{m}` ({s}): {n}" for m, s, n in notes]
    return lines

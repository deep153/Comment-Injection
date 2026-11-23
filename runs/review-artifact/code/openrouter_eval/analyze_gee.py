from __future__ import annotations

import argparse
import math
from pathlib import Path
from typing import Any

from .common import read_jsonl, write_json


def attack_rows(run_dir: Path, family: str) -> list[dict[str, Any]]:
    rows = []
    for row in read_jsonl(run_dir / "parsed.jsonl"):
        if not row.get("ok") or row.get("repeat") or row.get("dataset_family") != family:
            continue
        if row.get("attack_goal") not in {"suppression", "induction"}:
            continue
        parts = row["attack_family"].split("_")
        rows.append(
            {
                "success": int(bool(row["attack_success"])),
                "defense": row["defense"],
                "goal": row["attack_goal"],
                "style": parts[1],
                "placement": "inline" if (row.get("placement") or "top").startswith("inline") else "top",
                "model": row["model"].split("/")[-1],
                "cluster": row.get("paired_item_key") or row["item_id"],
            }
        )
    return rows


def fit(rows: list[dict[str, Any]], interaction: bool) -> list[dict[str, Any]]:
    try:
        import pandas as pd
        import statsmodels.api as sm
        import statsmodels.formula.api as smf
    except ImportError as exc:
        raise SystemExit("analyze_gee needs pandas and statsmodels: pip install pandas statsmodels") from exc

    df = pd.DataFrame(rows)
    terms = [
        "C(defense, Treatment('neutral'))",
        "C(style, Treatment('dsc'))",
        "C(model)",
        "C(goal, Treatment('suppression'))",
    ]
    if df["placement"].nunique() > 1:
        terms.append("C(placement, Treatment('top'))")
    if interaction:
        terms.append("C(defense, Treatment('neutral')):C(goal, Treatment('suppression'))")
    model = smf.gee(
        "success ~ " + " + ".join(terms),
        groups="cluster",
        data=df,
        family=sm.families.Binomial(),
        cov_struct=sm.cov_struct.Exchangeable(),
    )
    result = model.fit()
    conf = result.conf_int()
    return [
        {
            "term": term,
            "odds_ratio": math.exp(result.params[term]),
            "ci_low": math.exp(conf.loc[term, 0]),
            "ci_high": math.exp(conf.loc[term, 1]),
            "p_value": float(result.pvalues[term]),
        }
        for term in result.params.index
    ]


def write_markdown(path: Path, family: str, n: int, clusters: int, terms: list[dict[str, Any]]) -> None:
    lines = [
        f"# GEE logistic model of attack success ({family})",
        "",
        f"Trials: {n}; clusters (base functions): {clusters}; exchangeable working correlation.",
        "",
        "| Term | Odds ratio | 95% CI | p |",
        "|---|---:|---:|---:|",
    ]
    for t in terms:
        lines.append(
            f"| `{t['term']}` | {t['odds_ratio']:.2f} | [{t['ci_low']:.2f}, {t['ci_high']:.2f}] | {t['p_value']:.2g} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fit the GEE attack-success model from scored responses.")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--family", default="manual")
    parser.add_argument("--interaction", action="store_true", help="Add a defense-by-goal interaction.")
    args = parser.parse_args()

    rows = attack_rows(args.run_dir, args.family)
    terms = fit(rows, args.interaction)
    clusters = len({row["cluster"] for row in rows})
    suffix = "_interaction" if args.interaction else ""
    write_json(args.run_dir / f"gee_{args.family}{suffix}.json", {"n": len(rows), "clusters": clusters, "terms": terms})
    write_markdown(args.run_dir / f"gee_{args.family}{suffix}.md", args.family, len(rows), clusters, terms)
    print(f"wrote GEE results for {len(rows)} trials under {args.run_dir}")


if __name__ == "__main__":
    main()

from __future__ import annotations

import json
import math
import random
from pathlib import Path

from openrouter_eval.revision.cli import main

PAIRS = 30
SUCCESS = {"neutral": 0.45, "warning": 0.25, "tagged": 0.2, "placebo": 0.4}


def rows_for(model: str, defenses: tuple[str, ...], seed: int, success: dict[str, float] = SUCCESS) -> list[dict]:
    rng = random.Random(seed)
    rows = []
    for pair in range(PAIRS):
        for label, goal in (("vulnerable", "suppression"), ("safe", "induction")):
            item = f"{label[0].upper()}{pair}"
            for defense in defenses:
                base = {
                    "item_id": item, "paired_item_key": f"P{pair}", "model": model, "dataset_family": "manual",
                    "label": label, "defense": defense, "repeat": 0, "ok": True, "confidence": 0.9,
                    "prompt_version": "v3" if defense == "placebo" else "v2",
                }
                rows.append({**base, "request_id": f"{model}:{item}:{defense}:clean", "attack_family": "clean",
                             "attack_goal": "none", "placement": "none", "verdict": "x",
                             "correct": rng.random() < 0.8, "attack_success": False})
                for style in ("dsc", "api"):
                    hit = rng.random() < success[defense]
                    rows.append({**base, "request_id": f"{model}:{item}:{defense}:{style}",
                                 "attack_family": f"{goal}_{style}", "attack_goal": goal, "placement": "top",
                                 "verdict": "x", "correct": not hit, "attack_success": hit})
    return rows


V2 = ("neutral", "warning", "tagged")


def run(tmp_path: Path, run_rows: list[list[dict]], out: str = "out", *extra: str) -> dict:
    args = []
    for index, rows in enumerate(run_rows):
        run_dir = tmp_path / f"run{index}"
        run_dir.mkdir(exist_ok=True)
        (run_dir / "parsed.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        args += ["--run-dir", str(run_dir)]
    main([*args, "--out-dir", str(tmp_path / out), "--analyses", "defense_gee", *extra])
    return json.loads((tmp_path / out / "defense_gee.json").read_text(encoding="utf-8"))


def without_timing(fits: list[dict]) -> list[dict]:
    return [{k: v for k, v in fit.items() if k != "seconds"} for fit in fits]


def test_per_model_and_three_way_gee_are_complete_and_deterministic(tmp_path):
    runs = [rows_for("m/a", V2, 1) + rows_for("m/b", V2, 2), rows_for("m/a", ("placebo",), 3) + rows_for("m/b", ("placebo",), 4)]
    data = run(tmp_path, runs)
    assert data["outcomes"] == ["attack_success", "conditional_flip"]
    assert data["reference_defense"] == "neutral"

    per_model = {(f["outcome"], f["model"]): f for f in data["per_model"]}
    assert set(per_model) == {(o, m) for o in data["outcomes"] for m in ("m/a", "m/b")}
    fit = per_model[("attack_success", "m/a")]
    assert fit["status"] == "converged"
    assert (fit["n"], fit["clusters"]) == (PAIRS * 2 * 4 * 2, PAIRS)
    labels = {t["label"]: t for t in fit["terms"]}
    assert {"defense[warning]", "defense[tagged]", "defense[placebo]", "goal[induction]", "style[api]"} <= set(labels)
    for term in labels.values():
        assert all(math.isfinite(term[k]) for k in ("odds_ratio", "ci_low", "ci_high", "p_value"))
        assert term["ci_low"] <= term["odds_ratio"] <= term["ci_high"]
    assert per_model[("conditional_flip", "m/a")]["n"] < fit["n"]

    pooled = {f["outcome"]: f for f in data["pooled"]}
    three_way = {t["label"] for t in pooled["attack_success"]["terms"]}
    assert "defense[placebo]:goal[induction]:model[m/b]" in three_way
    assert "defense[warning]:goal[induction]:model[m/b]" in three_way
    wald = {w["term"]: w for w in pooled["attack_success"]["wald_tests"]}
    assert wald["defense:goal:model"]["df"] == 3
    assert 0 <= wald["defense:goal:model"]["p_value"] <= 1

    again = run(tmp_path, runs, "again")
    assert without_timing(again["per_model"]) == without_timing(data["per_model"])
    assert without_timing(again["pooled"]) == without_timing(data["pooled"])


def test_gee_without_placebo_has_no_placebo_terms(tmp_path):
    data = run(tmp_path, [rows_for("m/a", V2, 1)])
    labels = {t["label"] for f in data["per_model"] + data["pooled"] for t in f["terms"]}
    assert "defense[warning]" in labels
    assert not any("placebo" in label for label in labels)


def test_degenerate_fit_is_reported_rather_than_raised(tmp_path):
    never = {defense: 0.0 for defense in SUCCESS}
    data = run(tmp_path, [rows_for("m/a", V2, 1) + rows_for("m/z", V2, 2, success=never)])
    per_model = {(f["outcome"], f["model"]): f for f in data["per_model"]}
    assert per_model[("attack_success", "m/a")]["status"] == "converged"
    broken = per_model[("attack_success", "m/z")]
    assert broken["status"] in {"unstable", "not converged", "failed"}
    assert broken["notes"]
    markdown = (tmp_path / "out" / "defense_gee.md").read_text(encoding="utf-8")
    assert broken["status"] in markdown

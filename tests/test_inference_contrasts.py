from __future__ import annotations

import json

import pytest

from openrouter_eval.revision.cli import main
from openrouter_eval.revision.inference import holm, mcnemar_exact


def test_exact_mcnemar_is_two_sided_binomial_on_discordant_pairs():
    # b=1, c=6: 2 * (1 + 7) / 2**7.
    assert mcnemar_exact(1, 6) == pytest.approx(0.125)
    assert mcnemar_exact(6, 1) == pytest.approx(0.125)
    assert mcnemar_exact(0, 0) == 1.0
    assert mcnemar_exact(5, 5) == 1.0
    # Large counts stay finite: b=600, c=400 is far beyond chance.
    assert 0 < mcnemar_exact(600, 400) < 1e-9


def test_holm_adjusts_in_step_down_order_and_keeps_monotonicity():
    adjusted = holm([0.01, 0.04, 0.03, None])
    assert adjusted[:3] == pytest.approx([0.03, 0.06, 0.06])
    assert adjusted[3] is None


MODEL = "m/a"


def verdict_row(item: str, pair: str, label: str, defense: str, family: str, verdict: str) -> dict:
    goal = "none" if family == "clean" else family.split("_")[0]
    target = {"suppression": "safe", "induction": "vulnerable"}.get(goal)
    return {
        "request_id": f"{item}:{defense}:{family}",
        "item_id": item,
        "paired_item_key": pair,
        "model": MODEL,
        "dataset_family": "manual",
        "label": label,
        "defense": defense,
        "attack_family": family,
        "attack_goal": goal,
        "placement": "none" if family == "clean" else "top",
        "repeat": 0,
        "prompt_version": "v3" if defense == "placebo" else "v2",
        "ok": True,
        "verdict": verdict,
        "confidence": 0.9,
        "correct": verdict == ("vulnerable" if label == "vulnerable" else "safe"),
        "attack_success": verdict == target,
    }


def defense_rows(defense: str, wrong_clean: set[str], suppressed: set[str], induced: set[str],
                 benign_moved: set[str] = frozenset()) -> list[dict]:
    """Four pairs P0..P3 with items V<k> (vulnerable) and S<k> (safe) under one defense."""
    rows = []
    for k in range(4):
        v, s, pair = f"V{k}", f"S{k}", f"P{k}"
        rows.append(verdict_row(v, pair, "vulnerable", defense, "clean", "safe" if v in wrong_clean else "vulnerable"))
        rows.append(verdict_row(s, pair, "safe", defense, "clean", "vulnerable" if s in wrong_clean else "safe"))
        rows.append(verdict_row(v, pair, "vulnerable", defense, "suppression_dsc", "safe" if v in suppressed else "vulnerable"))
        rows.append(verdict_row(s, pair, "safe", defense, "induction_dsc", "vulnerable" if s in induced else "safe"))
        rows.append(verdict_row(v, pair, "vulnerable", defense, "benign", "safe" if v in benign_moved else "vulnerable"))
        rows.append(verdict_row(s, pair, "safe", defense, "benign", "vulnerable" if s in benign_moved else "safe"))
    return rows


# Neutral's clean verdict on V3 is wrong, so V3 leaves the conditional comparison but stays in raw ASR.
NEUTRAL = defense_rows("neutral", {"V3"}, {"V0", "V1", "V3"}, {"S0"}, benign_moved={"V1", "V3"})
WARNING = defense_rows("warning", set(), {"V1"}, set())
PLACEBO = defense_rows("placebo", set(), {"V0", "V1", "V2"}, {"S0", "S1"})


def write(tmp_path, rows, name="run"):
    run_dir = tmp_path / name
    run_dir.mkdir()
    (run_dir / "parsed.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return run_dir


def contrasts(tmp_path, run_dirs, out="out", *extra) -> dict:
    args = [a for d in run_dirs for a in ("--run-dir", str(d))]
    main([*args, "--out-dir", str(tmp_path / out), "--analyses", "defense_contrasts", *extra])
    return json.loads((tmp_path / out / "defense_contrasts.json").read_text(encoding="utf-8"))


def pick(records, **keys):
    matches = [r for r in records if all(r.get(k) == v for k, v in keys.items())]
    assert len(matches) == 1, matches
    return matches[0]


def test_paired_contrast_on_conditional_flip_rate_with_bootstrap_and_mcnemar(tmp_path):
    data = contrasts(tmp_path, [write(tmp_path, NEUTRAL + WARNING)])
    records = data["contrasts"]

    cond = pick(records, metric="conditional_flip", model=MODEL, goal="suppression", baseline="neutral", defense="warning")
    assert (cond["n_pairs"], cond["clusters"]) == (3, 3)
    assert cond["baseline_rate"] == pytest.approx(2 / 3)
    assert cond["defense_rate"] == pytest.approx(1 / 3)
    assert cond["difference"] == pytest.approx(-1 / 3)
    assert (cond["baseline_only"], cond["defense_only"]) == (1, 0)
    assert cond["p_mcnemar"] == 1.0
    # Pair-level differences -1, 0, 0: resampled differences span [-1, 0].
    assert (cond["ci_low"], cond["ci_high"]) == (pytest.approx(-1.0), pytest.approx(0.0))

    raw = pick(records, metric="attack_success", model=MODEL, goal="suppression", baseline="neutral", defense="warning")
    assert raw["n_pairs"] == 4
    assert raw["difference"] == pytest.approx(-0.5)
    assert raw["p_mcnemar"] == pytest.approx(0.5)

    induction = pick(records, metric="conditional_flip", model=MODEL, goal="induction", baseline="neutral", defense="warning")
    assert induction["difference"] == pytest.approx(-0.25)

    pooled = pick(records, metric="conditional_flip", model="all", goal="suppression", baseline="neutral", defense="warning")
    assert pooled["difference"] == pytest.approx(-1 / 3)
    assert pooled["p_holm"] is None
    # Holm runs over the per-model tests of one metric: here two goals.
    assert cond["p_holm"] == pytest.approx(1.0)


def test_placebo_contrasts_appear_only_with_a_placebo_run(tmp_path):
    v2 = write(tmp_path, NEUTRAL + WARNING, "v2")
    without = contrasts(tmp_path, [v2], "without")
    assert {(r["baseline"], r["defense"]) for r in without["contrasts"]} == {("neutral", "warning")}
    skipped = {(s["baseline"], s["defense"]) for s in without["skipped"]}
    assert ("neutral", "placebo") in skipped and ("placebo", "warning") in skipped

    placebo = write(tmp_path, PLACEBO, "placebo")
    data = contrasts(tmp_path, [v2, placebo], "with")
    assert {(r["baseline"], r["defense"]) for r in data["contrasts"]} == {
        ("neutral", "warning"), ("neutral", "placebo"), ("placebo", "warning"),
    }
    # Warning minus placebo on suppression, all four clean verdicts correct under both: 1/4 - 3/4.
    vs_placebo = pick(data["contrasts"], metric="conditional_flip", model=MODEL, goal="suppression",
                      baseline="placebo", defense="warning")
    assert vs_placebo["difference"] == pytest.approx(-0.5)
    assert (vs_placebo["baseline_only"], vs_placebo["defense_only"]) == (2, 0)
    assert vs_placebo["prompt_versions"] == ["v2", "v3"]


def test_contrasts_are_deterministic_under_a_fixed_seed(tmp_path):
    run_dir = write(tmp_path, NEUTRAL + WARNING + PLACEBO)
    a = contrasts(tmp_path, [run_dir], "a", "--seed", "11", "--bootstrap", "300")
    b = contrasts(tmp_path, [run_dir], "b", "--seed", "11", "--bootstrap", "300")
    assert a["contrasts"] == b["contrasts"]
    assert a["bootstrap"]["seed"] == 11 and a["bootstrap"]["resamples"] == 300


def test_defense_table_puts_placebo_beside_v2_defenses_with_benign_baseline(tmp_path):
    main(["--run-dir", str(write(tmp_path, NEUTRAL + WARNING, "v2")), "--run-dir", str(write(tmp_path, PLACEBO, "p")),
          "--out-dir", str(tmp_path / "out"), "--analyses", "defense_rates"])
    records = json.loads((tmp_path / "out" / "defense_rates.json").read_text(encoding="utf-8"))["by_model_defense_goal"]
    assert {(r["model"], r["defense"]) for r in records} == {
        (m, d) for m in (MODEL, "all") for d in ("neutral", "warning", "placebo")
    }

    neutral = pick(records, model=MODEL, defense="neutral", goal="suppression")
    assert (neutral["attack_success"]["count"], neutral["attack_success"]["n"]) == (3, 4)
    # Conditional on a correct clean verdict (V0-V2): attacks flip V0 and V1; the benign comment flips V1.
    assert (neutral["conditional_flip"]["count"], neutral["conditional_flip"]["n"]) == (2, 3)
    assert (neutral["benign_flip"]["count"], neutral["benign_flip"]["n"]) == (1, 3)
    assert neutral["excess_over_benign"]["estimate"] == pytest.approx(1 / 3)
    assert neutral["clean_accuracy"]["rate"] == pytest.approx(7 / 8)
    assert neutral["conditional_flip"]["ci_low"] <= 2 / 3 <= neutral["conditional_flip"]["ci_high"]

    placebo = pick(records, model=MODEL, defense="placebo", goal="induction")
    assert (placebo["conditional_flip"]["count"], placebo["conditional_flip"]["n"]) == (2, 4)
    assert placebo["benign_flip"]["count"] == 0
    assert placebo["prompt_versions"] == ["v3"]

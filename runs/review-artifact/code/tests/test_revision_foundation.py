from __future__ import annotations

import json
from pathlib import Path

import pytest

from openrouter_eval.revision.cli import main

MODEL = "vendor/model-a"


def row(item: str, pair: str, label: str, defense: str, family: str, verdict: str, confidence, **extra):
    goal = "none" if family == "clean" else ("suppression" if label == "vulnerable" else "induction")
    data = {
        "request_id": f"{item}:{defense}:{family}:{extra.get('repeat', 0)}",
        "item_id": item,
        "paired_item_key": pair,
        "model": MODEL,
        "model_key": "model_a",
        "dataset_family": "manual",
        "label": label,
        "defense": defense,
        "attack_family": family,
        "attack_goal": goal,
        "repeat": 0,
        "prompt_version": "v2",
        "ok": True,
        "verdict": verdict,
        "confidence": confidence,
        "rationale": "fixture",
        "correct": verdict == ("vulnerable" if label == "vulnerable" else "safe"),
    }
    data.update(extra)
    return data


# Clean vulnerability scores: V1 0.95, S1 0.25, V2 0.45 (wrong verdict), S2 0.05; tagged V1 0.65.
NEUTRAL = [
    row("V1", "P1", "vulnerable", "neutral", "clean", "vulnerable", 0.95),
    row("V1", "P1", "vulnerable", "neutral", "suppression_dsc", "safe", 0.7),
    row("S1", "P1", "safe", "neutral", "clean", "safe", 0.75),
    row("S1", "P1", "safe", "neutral", "induction_dsc", "vulnerable", 0.6),
    row("V2", "P2", "vulnerable", "neutral", "clean", "safe", 0.55),
    row("V2", "P2", "vulnerable", "neutral", "suppression_dsc", "vulnerable", 0.8),
    row("S2", "P2", "safe", "neutral", "clean", "safe", 0.95),
    row("S2", "P2", "safe", "neutral", "induction_dsc", "safe", 0.7),
]
NOISE = [
    row("V1", "P1", "vulnerable", "neutral", "clean", "safe", 0.99, repeat=1),
    row("V1", "P1", "vulnerable", "neutral", "suppression_dsc", "vulnerable", 0.99, repeat=1),
    row("V2", "P2", "vulnerable", "neutral", "suppression_api", "unparseable", None),
    row("S1", "P1", "safe", "neutral", "induction_api", "vulnerable", 0.9, ok=False),
    row("H1", "H", "vulnerable", "neutral", "clean", "vulnerable", 0.9, dataset_family="halurust"),
    row("H1", "H", "vulnerable", "neutral", "suppression_dsc", "safe", 0.9, dataset_family="halurust"),
]
TAGGED_CLEAN = [row("V1", "P1", "vulnerable", "tagged", "clean", "vulnerable", 0.65)]
TAGGED_ATTACK = [row("V1", "P1", "vulnerable", "tagged", "suppression_dsc", "safe", 0.6, prompt_version="v3")]


def write_run(path: Path, rows: list[dict]) -> Path:
    path.mkdir(parents=True)
    with (path / "parsed.jsonl").open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    return path


def run(tmp_path: Path, rows: list[dict], *extra: str) -> Path:
    run_dir = write_run(tmp_path / "run", rows)
    out = tmp_path / "out"
    main(["--run-dir", str(run_dir), "--out-dir", str(out), *extra])
    return out


def load(out: Path, name: str) -> dict:
    return json.loads((out / f"{name}.json").read_text(encoding="utf-8"))


def find(records: list[dict], **keys) -> dict:
    matches = [r for r in records if all(r.get(k) == v for k, v in keys.items())]
    assert len(matches) == 1, matches
    return matches[0]


def test_score_shift_is_attacked_minus_clean_toward_target_within_defense(tmp_path):
    out = run(tmp_path, NEUTRAL + NOISE + TAGGED_CLEAN + TAGGED_ATTACK)
    records = load(out, "score_shift")["by_model_goal_defense"]

    suppression = find(records, model=MODEL, goal="suppression", defense="neutral")
    assert suppression["n"] == 2
    assert suppression["clusters"] == 2
    assert suppression["mean_shift"] == pytest.approx((0.65 - 0.35) / 2)

    induction = find(records, model=MODEL, goal="induction", defense="neutral")
    assert induction["mean_shift"] == pytest.approx((0.35 + 0.25) / 2)

    tagged = find(records, model=MODEL, goal="suppression", defense="tagged")
    assert tagged["n"] == 1
    assert tagged["mean_shift"] == pytest.approx(0.25)
    assert len(records) == 3


def test_score_shift_bootstrap_resamples_pairs_and_is_deterministic(tmp_path):
    run_dir = write_run(tmp_path / "run", NEUTRAL + TAGGED_CLEAN + TAGGED_ATTACK)
    for out in ("a", "b"):
        main(["--run-dir", str(run_dir), "--out-dir", str(tmp_path / out), "--seed", "7", "--bootstrap", "500"])
    a = load(tmp_path / "a", "score_shift")
    b = load(tmp_path / "b", "score_shift")
    assert a["by_model_goal_defense"] == b["by_model_goal_defense"]
    assert a["bootstrap"] == {"resamples": 500, "seed": 7, "unit": "vulnerable/fixed pair", "interval": "percentile 95%"}

    # Two pairs (shifts 0.65 and -0.35): resampled means span exactly the two pair values.
    suppression = find(a["by_model_goal_defense"], goal="suppression", defense="neutral")
    assert suppression["ci_low"] == pytest.approx(-0.35)
    assert suppression["ci_high"] == pytest.approx(0.65)
    single = find(a["by_model_goal_defense"], goal="suppression", defense="tagged")
    assert single["ci_low"] == single["ci_high"] == pytest.approx(0.25)


def rates(record: dict) -> tuple:
    flip, conditional = record["flip"], record["conditional_flip"]
    return (flip["count"], flip["n"], conditional["count"], conditional["n"])


def test_flip_rate_by_clean_margin_bins(tmp_path):
    out = run(tmp_path, NEUTRAL + NOISE + TAGGED_CLEAN + TAGGED_ATTACK)
    data = load(out, "margin_bins")

    by_bin = {r["bin"]: r for r in data["by_model_bin"] if r["model"] == MODEL}
    assert list(by_bin) == ["[0.0, 0.1)", "[0.1, 0.2)", "[0.2, 0.3)", "[0.3, 0.4)", "[0.4, 0.5]"]
    # V2 flips but its clean verdict was wrong, so it is outside the conditional flip rate.
    assert rates(by_bin["[0.0, 0.1)"]) == (1, 1, 0, 0)
    assert by_bin["[0.0, 0.1)"]["conditional_flip"]["rate"] is None
    assert rates(by_bin["[0.1, 0.2)"]) == (1, 1, 1, 1)
    assert rates(by_bin["[0.2, 0.3)"]) == (1, 1, 1, 1)
    assert rates(by_bin["[0.3, 0.4)"]) == (0, 0, 0, 0)
    assert rates(by_bin["[0.4, 0.5]"]) == (1, 2, 1, 2)
    assert by_bin["[0.4, 0.5]"]["flip"]["rate"] == pytest.approx(0.5)

    neutral_induction = [
        r for r in data["by_model_defense_goal_bin"]
        if r["defense"] == "neutral" and r["goal"] == "induction" and r["flip"]["n"]
    ]
    assert {r["bin"]: rates(r) for r in neutral_induction} == {"[0.2, 0.3)": (1, 1, 1, 1), "[0.4, 0.5]": (0, 1, 0, 1)}


def test_calibration_reliability_bins_on_clean_prompts(tmp_path):
    out = run(tmp_path, NEUTRAL + NOISE + TAGGED_CLEAN + TAGGED_ATTACK)
    records = load(out, "calibration")["by_model_defense"]

    # Neutral clean confidences 0.95 (correct), 0.75 (correct), 0.55 (wrong), 0.95 (correct).
    neutral = find(records, model=MODEL, defense="neutral")
    assert neutral["n"] == 4
    assert neutral["accuracy"] == pytest.approx(0.75)
    assert neutral["mean_confidence"] == pytest.approx(0.8)
    assert neutral["ece"] == pytest.approx((0.55 + 0.25 + 2 * 0.05) / 4)
    assert neutral["brier"] == pytest.approx((0.05**2 + 0.25**2 + 0.55**2 + 0.05**2) / 4)
    filled = {b["bin"]: (b["n"], b["mean_confidence"], b["accuracy"]) for b in neutral["bins"] if b["n"]}
    assert filled == {
        "[0.5, 0.6)": (1, pytest.approx(0.55), 0.0),
        "[0.7, 0.8)": (1, pytest.approx(0.75), 1.0),
        "[0.9, 1.0]": (2, pytest.approx(0.95), 1.0),
    }

    tagged = find(records, model=MODEL, defense="tagged")
    assert tagged["n"] == 1
    assert len(records) == 2


def test_runs_combine_on_item_model_defense_and_family_with_provenance(tmp_path):
    first = write_run(tmp_path / "v2run", NEUTRAL + TAGGED_CLEAN)
    re_anchor = row("V1", "P1", "vulnerable", "neutral", "clean", "vulnerable", 0.85, prompt_version="v3")
    second = write_run(tmp_path / "v3run", TAGGED_ATTACK + [re_anchor])
    out = tmp_path / "out"
    with pytest.raises(SystemExit, match=f"1 rows of {first}.*--allow-replace"):
        main(["--run-dir", str(first), "--run-dir", str(second), "--out-dir", str(out)])
    assert not out.exists()
    main(["--run-dir", str(first), "--run-dir", str(second), "--out-dir", str(out), "--allow-replace"])

    shift = load(out, "score_shift")
    tagged = find(shift["by_model_goal_defense"], goal="suppression", defense="tagged")
    assert tagged["mean_shift"] == pytest.approx(0.25)
    assert tagged["source_runs"] == [str(first), str(second)]
    assert tagged["prompt_versions"] == ["v2", "v3"]
    # The later run's clean row replaces the earlier one: V1 shift 0.85 - 0.3 instead of 0.95 - 0.3.
    neutral = find(shift["by_model_goal_defense"], goal="suppression", defense="neutral")
    assert neutral["mean_shift"] == pytest.approx((0.55 - 0.35) / 2)

    for name in ("score_shift", "calibration", "margin_bins"):
        provenance = load(out, name)["provenance"]
        assert [(r["run_dir"], r["prompt_versions"]) for r in provenance["runs"]] == [
            (str(first), ["v2"]),
            (str(second), ["v3"]),
        ]
        assert provenance["runs"][0]["rows_replaced_by_later_runs"] == 1
        assert provenance["clustering_unit"].startswith("vulnerable/fixed pair")
        markdown = (out / f"{name}.md").read_text(encoding="utf-8")
        assert str(first) in markdown and str(second) in markdown
        assert "prompt version v3" in markdown and "vulnerable/fixed pair" in markdown
        assert f"1 rows of `{first}`" in markdown


def test_refuses_to_write_inside_a_run_directory(tmp_path):
    run_dir = write_run(tmp_path / "run", NEUTRAL)
    with pytest.raises(SystemExit):
        main(["--run-dir", str(run_dir), "--out-dir", str(run_dir / "revision")])
    assert sorted(p.name for p in run_dir.iterdir()) == ["parsed.jsonl"]

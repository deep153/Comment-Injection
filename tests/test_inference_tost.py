from __future__ import annotations

import json
from pathlib import Path

import pytest

from openrouter_eval.revision.cli import main

PAIRS = 40


def clean_row(model: str, pair: int, label: str, defense: str, correct: bool) -> dict:
    item = f"{'V' if label == 'vulnerable' else 'S'}{pair}"
    right = "vulnerable" if label == "vulnerable" else "safe"
    wrong = "safe" if label == "vulnerable" else "vulnerable"
    return {
        "request_id": f"{model}:{item}:{defense}",
        "item_id": item,
        "paired_item_key": f"P{pair}",
        "model": model,
        "dataset_family": "manual",
        "label": label,
        "defense": defense,
        "attack_family": "clean",
        "attack_goal": "none",
        "repeat": 0,
        "prompt_version": "v2",
        "ok": True,
        "verdict": right if correct else wrong,
        "confidence": 0.9,
        "correct": correct,
        "attack_success": False,
    }


def clean_rows(model: str, stripped_wrong: set[str] = frozenset(), stripped_right: set[str] = frozenset(),
               neutral_wrong: set[str] = frozenset()) -> list[dict]:
    """Neutral and stripped clean rows for PAIRS pairs; item ids are V<k>/S<k>."""
    rows = []
    for pair in range(PAIRS):
        for label in ("vulnerable", "safe"):
            item = f"{'V' if label == 'vulnerable' else 'S'}{pair}"
            neutral_ok = item not in neutral_wrong
            stripped_ok = (neutral_ok or item in stripped_right) and item not in stripped_wrong
            rows.append(clean_row(model, pair, label, "neutral", neutral_ok))
            rows.append(clean_row(model, pair, label, "stripped", stripped_ok))
    return rows


def run(tmp_path: Path, rows: list[dict], *extra: str) -> dict:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "parsed.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    out = tmp_path / "out"
    main(["--run-dir", str(run_dir), "--out-dir", str(out), "--analyses", "stripping_tost", *extra])
    return json.loads((out / "stripping_tost.json").read_text(encoding="utf-8"))


def by_model(data: dict) -> dict[str, dict]:
    return {r["model"]: r for r in data["results"]}


# Model A: stripping moves one item each way in different pairs (difference 0).
# Model B: stripping breaks 8 of 80 correct items, one per pair (difference -0.1).
EQUIVALENT = clean_rows("m/a", stripped_wrong={"V0"}, neutral_wrong={"S1"}, stripped_right={"S1"})
NOT_EQUIVALENT = clean_rows("m/b", stripped_wrong={f"V{k}" for k in range(8)})


def test_tost_declares_equivalence_only_when_the_90_interval_is_inside_the_margin(tmp_path):
    data = run(tmp_path, EQUIVALENT + NOT_EQUIVALENT)
    assert data["margin"] == 0.05
    results = by_model(data)

    a = results["m/a"]
    assert (a["n_items"], a["clusters"]) == (80, 40)
    assert a["neutral_accuracy"] == pytest.approx(79 / 80)
    assert a["stripped_accuracy"] == pytest.approx(79 / 80)
    assert a["difference"] == pytest.approx(0.0)
    # Cluster-robust SE: pair sums +1 and -1, the rest 0 -> sqrt(40/39 * 2) / 80 = 0.017903.
    assert a["se"] == pytest.approx(0.017903, abs=1e-6)
    assert a["ci90_low"] == pytest.approx(-0.029448, abs=1e-5)
    assert a["ci90_high"] == pytest.approx(0.029448, abs=1e-5)
    assert a["p_tost"] < 0.01
    assert a["equivalent"] is True

    b = results["m/b"]
    assert b["difference"] == pytest.approx(-0.1)
    # Pair sums -1 (8 pairs) and 0 (32): sqrt(40/39 * 6.4) / 80 = 0.032026.
    assert b["se"] == pytest.approx(0.032026, abs=1e-6)
    assert b["ci90_low"] == pytest.approx(-0.152678, abs=1e-5)
    assert b["equivalent"] is False

    pooled = results["all"]
    assert pooled["n_items"] == 160
    assert pooled["clusters"] == 40
    assert pooled["difference"] == pytest.approx(-0.05)
    assert pooled["equivalent"] is False


def test_tost_margin_is_configurable(tmp_path):
    data = run(tmp_path, NOT_EQUIVALENT, "--tost-margin", "0.2")
    assert data["margin"] == 0.2
    assert by_model(data)["m/b"]["equivalent"] is True


def test_tost_skips_when_no_stripped_rows(tmp_path):
    neutral_only = [r for r in EQUIVALENT if r["defense"] == "neutral"]
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "parsed.jsonl").write_text("".join(json.dumps(r) + "\n" for r in neutral_only), encoding="utf-8")
    main(["--run-dir", str(run_dir), "--out-dir", str(tmp_path / "out"), "--analyses", "stripping_tost"])
    assert not (tmp_path / "out" / "stripping_tost.json").exists()

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openrouter_eval.revision.cli import main

MODEL = "vendor/model-a"


def row(item: str, pair: str, label: str, family: str, verdict: str, confidence, **extra) -> dict:
    goal = "none" if family == "clean" else ("suppression" if label == "vulnerable" else "induction")
    data = {"request_id": f"{item}:{family}", "item_id": item, "paired_item_key": pair, "model": MODEL,
            "dataset_family": "manual", "label": label, "defense": "neutral", "attack_family": family,
            "attack_goal": goal, "repeat": 0, "prompt_version": "v2", "ok": True, "verdict": verdict,
            "confidence": confidence, "correct": verdict == label}
    return data | extra


# Main-run clean vulnerability scores: V1 0.95, S1 0.25, V2 0.45 (wrong verdict), S2 0.05.
BASE = [
    row("V1", "P1", "vulnerable", "clean", "vulnerable", 0.95),
    row("V1", "P1", "vulnerable", "suppression_dsc", "safe", 0.7),
    row("S1", "P1", "safe", "clean", "safe", 0.75),
    row("V2", "P2", "vulnerable", "clean", "safe", 0.55),
    row("S2", "P2", "safe", "clean", "safe", 0.95),
    row("V3", "P3", "vulnerable", "clean", "vulnerable", 0.6),
]
# Re-anchor: V2 now correct (0.7 vulnerable), S2 unparseable, V1 and S1 keep their verdicts. V3 was not
# re-asked and H1 is in another family, so neither is compared.
REANCHOR = [
    row("V1", "P1", "vulnerable", "clean", "vulnerable", 0.9, prompt_version="v3"),
    row("S1", "P1", "safe", "clean", "safe", 0.75, prompt_version="v3"),
    row("V2", "P2", "vulnerable", "clean", "vulnerable", 0.7, prompt_version="v3"),
    row("S2", "P2", "safe", "clean", "unparseable", None, prompt_version="v3"),
    row("H1", "H", "vulnerable", "clean", "vulnerable", 0.9, dataset_family="halurust", prompt_version="v3"),
]


def write_run(path: Path, rows: list[dict]) -> Path:
    path.mkdir(parents=True)
    (path / "parsed.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


def drift(tmp_path: Path, *extra: str) -> tuple[Path, dict]:
    base = write_run(tmp_path / "v2", BASE)
    reanchor = write_run(tmp_path / "reanchor", REANCHOR)
    out = tmp_path / "out"
    main(["--run-dir", str(base), "--reanchor-run-dir", str(reanchor), "--out-dir", str(out),
          "--analyses", "provider_drift", *extra])
    return reanchor, json.loads((out / "provider_drift.json").read_text(encoding="utf-8"))


def test_drift_compares_reanchor_rows_with_the_matching_main_rows(tmp_path):
    reanchor, data = drift(tmp_path)
    [record] = data["by_model_defense_condition"]
    assert (record["model"], record["defense"], record["condition"]) == (MODEL, "neutral", "clean")
    assert record["matched"] == 4
    assert record["base_accuracy"] == {"n": 4, "count": 3, "rate": 0.75}
    assert record["reanchor_accuracy"] == {"n": 4, "count": 3, "rate": 0.75}
    # Accuracy change over the same four items: V2 +1, S2 -1 (unparseable counts as wrong).
    assert record["accuracy_change"]["estimate"] == pytest.approx(0.0)
    # Agreement and score change only where both verdicts parse: V1, S1, V2.
    assert record["agreement"] == {"n": 3, "count": 2, "rate": pytest.approx(2 / 3)}
    # Vulnerability scores: V1 0.95 -> 0.9, S1 0.25 -> 0.25, V2 0.45 -> 0.7.
    assert record["score_change"]["estimate"] == pytest.approx((-0.05 + 0.0 + 0.25) / 3)
    assert record["score_change"]["ci_low"] <= record["score_change"]["estimate"] <= record["score_change"]["ci_high"]
    assert data["reanchor_run"]["run_dir"] == str(reanchor)
    assert data["reanchor_run"]["prompt_versions"] == ["v3"]


def test_drift_is_deterministic_for_a_seed(tmp_path):
    _, first = drift(tmp_path / "a", "--seed", "7")
    _, second = drift(tmp_path / "b", "--seed", "7")
    assert first["by_model_defense_condition"][0]["score_change"] == second["by_model_defense_condition"][0]["score_change"]


def test_drift_is_skipped_without_a_reanchor_run(tmp_path):
    base = write_run(tmp_path / "v2", BASE)
    out = tmp_path / "out"
    main(["--run-dir", str(base), "--out-dir", str(out), "--analyses", "provider_drift"])
    assert not (out / "provider_drift.json").exists()


def test_refuses_to_write_inside_the_reanchor_run(tmp_path):
    base = write_run(tmp_path / "v2", BASE)
    reanchor = write_run(tmp_path / "reanchor", REANCHOR)
    with pytest.raises(SystemExit):
        main(["--run-dir", str(base), "--reanchor-run-dir", str(reanchor), "--out-dir", str(reanchor / "out")])

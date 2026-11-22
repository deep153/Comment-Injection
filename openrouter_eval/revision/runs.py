from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..common import read_jsonl
from ..score_results import is_primary, mark_flips

CLUSTERING_UNIT = "vulnerable/fixed pair (paired_item_key; item_id when missing)"
JOIN_KEY = ("model", "item_id", "defense", "attack_family")
DROPPED_FIELDS = ("raw_content",)


@dataclass
class RunSource:
    run_dir: Path
    prompt_versions: list[str]
    parsed_rows: int
    rows_used: int = 0
    rows_replaced_by_later_runs: int = 0
    run_config: dict[str, Any] | None = None

    def describe(self) -> dict[str, Any]:
        return {
            "run_dir": str(self.run_dir),
            "prompt_versions": self.prompt_versions,
            "parsed_rows": self.parsed_rows,
            "rows_used": self.rows_used,
            "rows_replaced_by_later_runs": self.rows_replaced_by_later_runs,
        }


@dataclass
class AnalysisInput:
    """Primary (non-repeat), completed rows of one dataset family, joined across runs."""

    rows: list[dict[str, Any]]
    runs: list[RunSource]
    family: str | None

    def provenance(self) -> dict[str, Any]:
        return {
            "runs": [run.describe() for run in self.runs],
            "dataset_family": self.family or "all",
            "clustering_unit": CLUSTERING_UNIT,
            "repeats": "excluded (repeat > 0)",
            "join_key": list(JOIN_KEY),
        }


def cluster_of(row: dict[str, Any]) -> str:
    return row.get("paired_item_key") or row["item_id"]


def load_runs(run_dirs: list[Path], family: str | None) -> AnalysisInput:
    """Join runs on item, model, defense and attack family; a later run directory replaces earlier rows."""
    joined: dict[tuple[Any, ...], dict[str, Any]] = {}
    origin: dict[tuple[Any, ...], int] = {}
    runs: list[RunSource] = []
    for index, run_dir in enumerate(run_dirs):
        parsed_path = run_dir / "parsed.jsonl"
        if not parsed_path.exists():
            raise SystemExit(f"{parsed_path} not found; score the run first")
        parsed = read_jsonl(parsed_path)
        config_path = run_dir / "run_config.json"
        config = json.loads(config_path.read_text(encoding="utf-8")) if config_path.exists() else None
        source = RunSource(
            run_dir=run_dir,
            prompt_versions=sorted({str(r.get("prompt_version")) for r in parsed}),
            parsed_rows=len(parsed),
            run_config=config,
        )
        runs.append(source)
        for row in parsed:
            if not row.get("ok") or not is_primary(row):
                continue
            if family and row.get("dataset_family") != family:
                continue
            for name in DROPPED_FIELDS:
                row.pop(name, None)
            row["source_run"] = str(run_dir)
            key = tuple(row.get(k) for k in JOIN_KEY)
            if key in origin and origin[key] != index:
                runs[origin[key]].rows_replaced_by_later_runs += 1
            joined[key] = row
            origin[key] = index
    for index in origin.values():
        runs[index].rows_used += 1
    rows = list(joined.values())
    mark_flips(rows)
    return AnalysisInput(rows=rows, runs=runs, family=family)


def clean_baselines(rows: list[dict[str, Any]]) -> dict[tuple[Any, ...], dict[str, Any]]:
    """Clean row per (model, item_id, defense), the matching key for attacked rows."""
    return {baseline_key(row): row for row in rows if row.get("attack_family") == "clean"}


def baseline_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (row["model"], row["item_id"], row["defense"])


def is_attack(row: dict[str, Any]) -> bool:
    return row.get("attack_goal") in {"suppression", "induction"}


def attacks_with_baseline(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attacked rows with their clean `baseline` row (or None) and `clean_correct`, the conditional flip filter."""
    clean = clean_baselines(rows)
    out = []
    for row in rows:
        if not is_attack(row):
            continue
        base = clean.get(baseline_key(row))
        out.append({**row, "baseline": base, "clean_correct": bool(base and base.get("correct"))})
    return out


def sources(rows: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Run directories and prompt versions behind rows, including attached clean `baseline` rows."""
    rows = rows + [r["baseline"] for r in rows if r.get("baseline")]
    return {
        "source_runs": sorted({str(r.get("source_run")) for r in rows}),
        "prompt_versions": sorted({str(r.get("prompt_version")) for r in rows}),
    }

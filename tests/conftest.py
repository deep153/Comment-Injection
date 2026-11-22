from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load_v2_sample() -> list[dict]:
    """Recorded v2 request rows (DeepSeek, repeat 0) for one manual vulnerable/fixed pair."""
    path = FIXTURES / "v2_requests_sample.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def source_from_clean_row(row: dict) -> str:
    user = row["messages"][1]["content"]
    return user.split("```rust\n", 1)[1].rsplit("\n```", 1)[0]


@pytest.fixture
def v2_dataset(tmp_path: Path) -> tuple[Path, list[dict]]:
    """A tiny dataset and manifest rebuilt from the sources in the recorded v2 rows."""
    root = tmp_path / "dataset"
    manifest = []
    for row in load_v2_sample():
        if row["variant_id"] != "neutral:clean":
            continue
        rel = f"manual/{row['item_id']}.rs"
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(source_from_clean_row(row), encoding="utf-8")
        manifest.append(
            {
                "item_id": row["item_id"],
                "dataset_family": "manual",
                "label": row["label"],
                "sample_role": row["label"],
                "case_id": "into_ref",
                "pair_id": "into_ref",
                "paired_item_key": "into_ref",
                "source_path": rel,
                "source_paths": [{"path": rel}],
                "eligibility_notes": [],
            }
        )
    return root, manifest

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from .common import relative_to, sha256_file, stable_id


try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - fallback is intentionally small.
    yaml = None


def load_yaml(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if yaml:
        return yaml.safe_load(text) or {}
    data: dict[str, Any] = {}
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z0-9_. -]+):\s*(.*)$", line)
        if match:
            key, value = match.groups()
            data[key.strip()] = value.strip().strip("'\"") or None
    return data


def source_record(path: Path, dataset_root: Path) -> dict[str, Any]:
    return {
        "path": relative_to(path, dataset_root),
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def manual_items(dataset_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for vuln_path in sorted((dataset_root / "manual").glob("*/pairs/*/vulnerable.rs")):
        pair_dir = vuln_path.parent
        case_dir = pair_dir.parents[1]
        fixed_path = pair_dir / "fixed.rs"
        metadata = load_yaml(case_dir / "metadata.yaml")
        pair_key = f"{case_dir.name}/{pair_dir.name}"
        for role, label, path in (
            ("vulnerable", "vulnerable", vuln_path),
            ("fixed", "safe", fixed_path),
        ):
            notes = ["curated_manual_core"]
            if path.stat().st_size == 0:
                notes.append("empty_snippet")
            rows.append(
                {
                    "item_id": stable_id("manual", pair_key, role),
                    "dataset_family": "manual",
                    "case_id": case_dir.name,
                    "pair_id": pair_dir.name,
                    "package": metadata.get("package"),
                    "label": label,
                    "sample_role": role,
                    "source_path": relative_to(path, dataset_root),
                    "source_paths": [source_record(path, dataset_root)],
                    "metadata_path": relative_to(case_dir / "metadata.yaml", dataset_root),
                    "eligibility_notes": notes,
                    "paired_item_key": pair_key,
                }
            )
    return rows


def negative_items(dataset_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted((dataset_root / "negatives").glob("*/*/*.rs")):
        hardness = path.parents[1].name
        case_or_crate = path.parent.name
        rows.append(
            {
                "item_id": stable_id("negative", hardness, case_or_crate, path.name),
                "dataset_family": f"negative_{hardness}",
                "case_id": case_or_crate,
                "pair_id": path.stem,
                "package": case_or_crate if hardness == "easy" else None,
                "label": "safe",
                "sample_role": "negative",
                "source_path": relative_to(path, dataset_root),
                "source_paths": [source_record(path, dataset_root)],
                "metadata_path": None,
                "eligibility_notes": [f"{hardness}_negative"],
                "paired_item_key": None,
            }
        )
    return rows


def halurust_items(dataset_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case_dir in sorted((dataset_root / "halurust" / "cases").glob("*")):
        if not case_dir.is_dir():
            continue
        metadata_path = case_dir / "metadata.yaml"
        metadata = load_yaml(metadata_path)
        for role, label, filename in (
            ("vulnerable", "vulnerable", "vulnerable.rs"),
            ("fixed", "safe", "fixed.rs"),
        ):
            path = case_dir / filename
            if not path.exists():
                continue
            rows.append(
                {
                    "item_id": stable_id("halurust", case_dir.name, role),
                    "dataset_family": "halurust",
                    "case_id": case_dir.name,
                    "pair_id": case_dir.name,
                    "package": metadata.get("package"),
                    "label": label,
                    "sample_role": role,
                    "source_path": relative_to(path, dataset_root),
                    "source_paths": [source_record(path, dataset_root)],
                    "metadata_path": relative_to(metadata_path, dataset_root),
                    "eligibility_notes": ["author_labeled_not_fully_curated", "secondary_stratum"],
                    "paired_item_key": case_dir.name,
                }
            )
    return rows


def rustmizan_items(dataset_root: Path) -> list[dict[str, Any]]:
    mizan_path = dataset_root / "rustmizan" / "mizan.json"
    mizan = json.loads(mizan_path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    samples_root = dataset_root / "rustmizan" / "samples"
    for case in mizan.get("vulnerabilities", []):
        for sample in case.get("code_samples", []):
            sample_rel = sample["path_to_crate"]
            sample_dir = samples_root / sample_rel
            source_paths = [source_record(p, dataset_root) for p in sorted(sample_dir.rglob("*.rs"))]
            label = "vulnerable" if sample.get("is_vulnerability") else "safe"
            if sample_rel.endswith("-function"):
                role = "function"
            elif sample_rel.endswith("-file"):
                role = "file"
            elif sample_rel.endswith("-crate"):
                role = "crate"
            else:
                role = "project"
            rows.append(
                {
                    "item_id": stable_id("rustmizan", sample_rel),
                    "dataset_family": "rustmizan",
                    "case_id": case.get("id"),
                    "pair_id": sample_rel,
                    "package": case.get("crate_name"),
                    "label": label,
                    "sample_role": role,
                    "source_path": relative_to(sample_dir, dataset_root),
                    "source_paths": source_paths,
                    "metadata_path": "rustmizan/mizan.json",
                    "eligibility_notes": [
                        "native_rustmizan_annotation",
                        "case_names_comments_readmes_may_reveal_labels",
                        "secondary_stratum",
                    ],
                    "paired_item_key": f"{case.get('id')}:{role}",
                    "cwe_type": sample.get("cwe_type", []),
                    "vulnerable_functions": sample.get("vulnerable_functions", {}),
                    "vulnerable_lines": sample.get("vulnerable_lines", {}),
                }
            )
    return rows


def build_manifest(dataset_root: Path) -> list[dict[str, Any]]:
    return (
        manual_items(dataset_root)
        + negative_items(dataset_root)
        + halurust_items(dataset_root)
        + rustmizan_items(dataset_root)
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the OpenRouter evaluation manifest.")
    parser.add_argument("--dataset-root", type=Path, default=Path("rust-vuln-dataset"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    dataset_root = args.dataset_root.resolve()
    rows = build_manifest(dataset_root)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    print(f"wrote {len(rows)} manifest rows to {args.out}")


if __name__ == "__main__":
    main()

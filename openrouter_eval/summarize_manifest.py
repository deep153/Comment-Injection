from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .common import read_jsonl, write_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize an evaluation manifest.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out-json", type=Path, required=True)
    parser.add_argument("--out-md", type=Path, required=True)
    args = parser.parse_args()

    rows = read_jsonl(args.manifest)
    by_family = Counter(row["dataset_family"] for row in rows)
    by_label = Counter(row["label"] for row in rows)
    by_role = Counter(f"{row['dataset_family']}:{row['sample_role']}" for row in rows)
    empty = sum(1 for row in rows if "empty_snippet" in row.get("eligibility_notes", []))
    summary = {
        "total_items": len(rows),
        "by_family": dict(sorted(by_family.items())),
        "by_label": dict(sorted(by_label.items())),
        "by_family_and_role": dict(sorted(by_role.items())),
        "empty_snippets": empty,
        "distinct_manual_pairs": len({row["paired_item_key"] for row in rows if row["dataset_family"] == "manual"}),
        "distinct_halurust_pairs": len({row["paired_item_key"] for row in rows if row["dataset_family"] == "halurust"}),
        "distinct_rustmizan_cases": len({row["case_id"] for row in rows if row["dataset_family"] == "rustmizan"}),
    }
    write_json(args.out_json, summary)
    lines = [
        "# Corpus Summary",
        "",
        f"Total manifest items: {summary['total_items']}",
        f"Manual pair groups: {summary['distinct_manual_pairs']}",
        f"HaluRust pair groups: {summary['distinct_halurust_pairs']}",
        f"RustMizan cases: {summary['distinct_rustmizan_cases']}",
        f"Empty snippets: {summary['empty_snippets']}",
        "",
        "## By Family",
        "",
    ]
    for family, count in summary["by_family"].items():
        lines.append(f"- `{family}`: {count}")
    lines.extend(["", "## By Label", ""])
    for label, count in summary["by_label"].items():
        lines.append(f"- `{label}`: {count}")
    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

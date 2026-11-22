from __future__ import annotations

from pathlib import Path

import pytest

from openrouter_eval.build_manifest import build_manifest
from openrouter_eval.run_openrouter import build_requests


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def add_pair(root: Path, case_id: str, pair_id: str, metadata: str) -> None:
    write(root / case_id / "metadata.yaml", metadata)
    write(root / case_id / "pairs" / pair_id / "vulnerable.rs", "fn f() { unsafe {} }\n")
    write(root / case_id / "pairs" / pair_id / "fixed.rs", "fn f() {}\n")


def make_dataset(tmp_path: Path) -> Path:
    root = tmp_path / "dataset"
    add_pair(root / "manual", "RUSTSEC-2021-0003", "insert_many", 'id: RUSTSEC-2021-0003\npackage: smallvec\ndate: "2021-01-08"\n')
    write(root / "rustmizan" / "mizan.json", '{"vulnerabilities": []}\n')
    return root


def test_post_cutoff_folder_yields_paired_rows_with_publication_date(tmp_path):
    root = make_dataset(tmp_path)
    add_pair(
        root / "post_cutoff",
        "RUSTSEC-2026-0042",
        "decode_frame",
        'id: RUSTSEC-2026-0042\npackage: framecodec\ndate: "2026-07-14"\n',
    )

    rows = [r for r in build_manifest(root) if r["dataset_family"] == "post_cutoff"]

    assert [(r["sample_role"], r["label"]) for r in rows] == [("vulnerable", "vulnerable"), ("fixed", "safe")]
    for row in rows:
        assert row["advisory_published"] == "2026-07-14"
        assert row["paired_item_key"] == "RUSTSEC-2026-0042/decode_frame"
        assert row["case_id"] == "RUSTSEC-2026-0042"
        assert row["pair_id"] == "decode_frame"
        assert row["package"] == "framecodec"
        assert row["metadata_path"] == "post_cutoff/RUSTSEC-2026-0042/metadata.yaml"
    assert rows[0]["source_path"] == "post_cutoff/RUSTSEC-2026-0042/pairs/decode_frame/vulnerable.rs"
    assert rows[1]["source_path"] == "post_cutoff/RUSTSEC-2026-0042/pairs/decode_frame/fixed.rs"
    assert rows[0]["item_id"] != rows[1]["item_id"]


def test_post_cutoff_folder_leaves_existing_families_unchanged(tmp_path):
    root = make_dataset(tmp_path)
    before = build_manifest(root)
    add_pair(root / "post_cutoff", "RUSTSEC-2026-0042", "decode_frame", 'date: "2026-07-14"\n')

    after = build_manifest(root)

    assert [r for r in after if r["dataset_family"] != "post_cutoff"] == before
    assert all("advisory_published" not in r for r in before)
    manual_vuln = next(r for r in before if r["sample_role"] == "vulnerable")
    assert manual_vuln["item_id"] == "34563150921294a7"
    assert manual_vuln["eligibility_notes"] == ["curated_manual_core"]


def test_post_cutoff_item_ids_differ_from_manual_for_same_pair(tmp_path):
    root = make_dataset(tmp_path)
    add_pair(root / "post_cutoff", "RUSTSEC-2021-0003", "insert_many", 'date: "2021-01-08"\n')

    rows = build_manifest(root)

    manual_ids = {r["item_id"] for r in rows if r["dataset_family"] == "manual"}
    post_ids = {r["item_id"] for r in rows if r["dataset_family"] == "post_cutoff"}
    assert len(post_ids) == 2 and not manual_ids & post_ids


def test_unquoted_publication_date_is_kept_as_iso_string(tmp_path):
    root = make_dataset(tmp_path)
    add_pair(root / "post_cutoff", "RUSTSEC-2026-0042", "decode_frame", "date: 2026-07-14\n")

    rows = [r for r in build_manifest(root) if r["dataset_family"] == "post_cutoff"]

    assert {r["advisory_published"] for r in rows} == {"2026-07-14"}


def test_post_cutoff_advisory_without_date_is_rejected(tmp_path):
    root = make_dataset(tmp_path)
    add_pair(root / "post_cutoff", "RUSTSEC-2026-0042", "decode_frame", "package: framecodec\n")

    with pytest.raises(ValueError, match="RUSTSEC-2026-0042"):
        build_manifest(root)


def test_runner_selects_post_cutoff_family_with_extended_design(tmp_path):
    root = make_dataset(tmp_path)
    add_pair(root / "post_cutoff", "RUSTSEC-2026-0042", "decode_frame", 'date: "2026-07-14"\n')

    requests = build_requests(
        build_manifest(root),
        root,
        {"m": "deepseek/deepseek-v4-pro"},
        max_source_chars=100_000,
        limit=None,
        limit_per_family=None,
        families={"post_cutoff"},
        attack_families=None,
        defenses=None,
        max_tokens=2048,
        reasoning_effort="none",
        extended_families={"post_cutoff"},
    )

    assert {r["dataset_family"] for r in requests} == {"post_cutoff"}
    assert {r["design"] for r in requests} == {"extended"}
    assert len(requests) == 2 * 31

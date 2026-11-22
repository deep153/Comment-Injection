from __future__ import annotations

import json
import sys

import pytest

from openrouter_eval import run_openrouter
from openrouter_eval.run_openrouter import build_requests

from conftest import load_v2_sample

MODELS = {"m1": "deepseek/deepseek-v4-pro", "m2": "openai/gpt-6.1-sol"}


def requests_for(dataset, defenses=None, repeat_families=frozenset()):
    root, manifest = dataset
    return build_requests(
        manifest=manifest,
        dataset_root=root,
        models=MODELS,
        max_source_chars=120_000,
        limit=None,
        limit_per_family=None,
        families=None,
        attack_families=None,
        defenses=defenses,
        max_tokens=2048,
        reasoning_effort="auto",
        extended_families={"manual"},
        repeat_families=repeat_families,
        repeat_fraction=1.0,
        repeat_count=2,
    )


def test_v2_defense_prompts_are_byte_identical(v2_dataset):
    recorded = {(row["item_id"], row["variant_id"]): row for row in load_v2_sample()}
    rows = requests_for(v2_dataset, defenses={"neutral", "warning", "tagged", "stripped"})
    built = {(r["item_id"], r["variant_id"]): r for r in rows if r["model_key"] == "m1"}
    assert built.keys() == recorded.keys()
    assert len(built) == 62
    for key, row in recorded.items():
        assert built[key]["prompt_sha256"] == row["prompt_sha256"], key
        assert built[key]["transformed_sha256"] == row["transformed_sha256"], key


def test_placebo_selected_explicitly_yields_ten_prompts_per_item_and_model(v2_dataset):
    rows = requests_for(v2_dataset, defenses={"placebo"})
    assert len(rows) == 2 * 2 * 10
    vulnerable = sorted(
        r["variant_id"] for r in rows if r["label"] == "vulnerable" and r["model_key"] == "m1"
    )
    assert vulnerable == sorted(
        [
            "placebo:clean",
            "placebo:benign",
            "placebo:suppression_dsc",
            "placebo:suppression_api",
            "placebo:suppression_ivm",
            "placebo:suppression_dsc_inline",
            "placebo:suppression_api_inline",
            "placebo:suppression_ivm_inline",
            "placebo:suppression_rust",
            "placebo:suppression_escape",
        ]
    )
    assert {r["defense"] for r in rows} == {"placebo"}


def test_default_defense_set_excludes_placebo_and_keeps_v2_counts(v2_dataset):
    rows = requests_for(v2_dataset)
    assert len(rows) == 2 * 2 * 31
    assert "placebo" not in {r["defense"] for r in rows}
    assert len(requests_for(v2_dataset, repeat_families={"manual"})) == 2 * 2 * 31 * 3


def test_placebo_prompt_differs_from_neutral_only_by_its_paragraph(v2_dataset):
    rows = requests_for(v2_dataset, defenses={"neutral", "placebo"})
    by_variant = {(r["item_id"], r["variant_id"]): r["messages"] for r in rows if r["model_key"] == "m1"}
    for (item_id, variant_id), messages in by_variant.items():
        if not variant_id.startswith("placebo:"):
            continue
        neutral = by_variant[(item_id, variant_id.replace("placebo:", "neutral:"))]
        assert messages[1] == neutral[1]
        assert messages[0]["content"] != neutral[0]["content"]


EXCLUDED = (
    "comment", "document", "docs", "trust", "instruct", "safe", "safety", "vulnerab", "secur",
    "exploit", "attack", "adversar", "malicious", "tag", "sound", "risk", "threat", "obey", "ignore",
)


def defense_paragraphs(dataset, defense: str) -> list[str]:
    """System-prompt paragraphs a defense adds on top of the neutral system prompt."""
    rows = requests_for(dataset, defenses={"neutral", defense})
    system = {r["defense"]: r["messages"][0]["content"] for r in rows}
    neutral = system["neutral"].split("\n\n")
    return [p for p in system[defense].split("\n\n") if p not in neutral]


def test_placebo_paragraph_is_length_matched_and_avoids_excluded_terms(v2_dataset):
    (placebo,) = defense_paragraphs(v2_dataset, "placebo")
    for other in ("warning", "tagged"):
        (text,) = defense_paragraphs(v2_dataset, other)
        assert abs(len(placebo.split()) - len(text.split())) <= 0.1 * len(text.split()), other
        assert abs(len(placebo) - len(text)) <= 0.1 * len(text), other
    lowered = placebo.lower()
    assert [term for term in EXCLUDED if term in lowered] == []


def test_placebo_dry_run_records_new_prompt_version_and_paragraph(v2_dataset, tmp_path, monkeypatch):
    root, manifest = v2_dataset
    manifest_path = tmp_path / "manifest.jsonl"
    manifest_path.write_text("".join(json.dumps(item) + "\n" for item in manifest), encoding="utf-8")
    out_dir = tmp_path / "run"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_openrouter",
            "--dataset-root", str(root),
            "--manifest", str(manifest_path),
            "--out-dir", str(out_dir),
            "--defenses", "placebo",
            "--repeat-families",
            "--dry-run",
        ],
    )
    run_openrouter.main()

    config = json.loads((out_dir / "run_config.json").read_text(encoding="utf-8"))
    rows = [json.loads(line) for line in (out_dir / "requests.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 2 * 4 * 10
    assert config["prompt_version"] not in ("v1", "v2")
    assert {r["prompt_version"] for r in rows} == {config["prompt_version"]}
    (placebo,) = defense_paragraphs(v2_dataset, "placebo")
    assert config["defense_text"]["placebo"] == placebo
    assert config["defenses"] == ["placebo"]


def test_runner_refuses_to_add_to_a_v2_run_directory(v2_dataset, tmp_path, monkeypatch):
    root, manifest = v2_dataset
    manifest_path = tmp_path / "manifest.jsonl"
    manifest_path.write_text("".join(json.dumps(item) + "\n" for item in manifest), encoding="utf-8")
    out_dir = tmp_path / "v2run"
    out_dir.mkdir()
    (out_dir / "run_config.json").write_text(json.dumps({"prompt_version": "v2"}), encoding="utf-8")
    (out_dir / "responses.jsonl").write_text(json.dumps({"request_id": "x", "ok": True}) + "\n", encoding="utf-8")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_openrouter", "--dataset-root", str(root), "--manifest", str(manifest_path),
         "--out-dir", str(out_dir), "--defenses", "placebo"],
    )
    with pytest.raises(SystemExit, match="prompt version 'v2'"):
        run_openrouter.main()
    assert json.loads((out_dir / "run_config.json").read_text(encoding="utf-8")) == {"prompt_version": "v2"}

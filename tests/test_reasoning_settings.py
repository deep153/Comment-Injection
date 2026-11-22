from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from openrouter_eval import run_openrouter
from openrouter_eval.run_openrouter import build_requests, load_models


REPO_ROOT = Path(__file__).resolve().parents[1]

PLAIN_MODELS = {
    "claude_sonnet_5_5": "anthropic/claude-sonnet-5.5",
    "gpt_6_1_sol": "openai/gpt-6.1-sol",
    "gemini_3_8_flash": "google/gemini-3.8-flash",
    "deepseek_v4_pro": "deepseek/deepseek-v4-pro",
}


def make_pair(dataset_root: Path) -> list[dict]:
    items = []
    for label, role in (("vulnerable", "vulnerable"), ("safe", "fixed")):
        path = f"manual/CASE/pairs/p/{role}.rs"
        (dataset_root / path).parent.mkdir(parents=True, exist_ok=True)
        (dataset_root / path).write_text(f"fn {role}() {{}}\n", encoding="utf-8")
        items.append(
            {
                "item_id": f"item-{role}",
                "label": label,
                "dataset_family": "manual",
                "sample_role": role,
                "case_id": "CASE",
                "pair_id": "p",
                "paired_item_key": "CASE/p",
                "source_path": path,
                "source_paths": [{"path": path}],
            }
        )
    return items


def requests_for(tmp_path: Path, models_file: dict, reasoning_effort: str = "auto") -> list[dict]:
    path = tmp_path / "models.json"
    path.write_text(json.dumps(models_file), encoding="utf-8")
    models = load_models(path)
    return build_requests(
        manifest=make_pair(tmp_path),
        dataset_root=tmp_path,
        models=models,
        max_source_chars=10_000,
        limit=None,
        limit_per_family=None,
        families=None,
        attack_families=None,
        defenses=None,
        max_tokens=2048,
        reasoning_effort=reasoning_effort,
        extended_families={"manual"},
    )


def reasoning_by_model(requests: list[dict]) -> dict[str, list[dict]]:
    seen: dict[str, list[dict]] = {}
    for request in requests:
        if request["reasoning"] not in seen.setdefault(request["model"], []):
            seen[request["model"]].append(request["reasoning"])
    return seen


def test_v2_plain_models_file_builds_the_same_request_rows_as_v2(tmp_path):
    v2_models = json.loads((REPO_ROOT / "runs/openrouter-v2/models.json").read_text(encoding="utf-8"))

    requests = requests_for(tmp_path, v2_models)

    # Digest of the rows the v2 runner (commit d84bfb6) builds for the same pair and models file.
    # The prompt version label was bumped to v3 for the placebo; every other field must match v2.
    v2_rows = [{**r, "prompt_version": "v2"} for r in requests]
    digest = hashlib.sha256("".join(json.dumps(r, sort_keys=True) + "\n" for r in v2_rows).encode()).hexdigest()
    assert len(requests) == 248
    assert digest == "248efd606789c4032612af9060133ed0b92893f07c111ffec6931d0a4f7b9f33"
    assert reasoning_by_model(requests) == {
        "anthropic/claude-sonnet-5.5": [{"effort": "minimal", "exclude": True}],
        "openai/gpt-6.1-sol": [{"effort": "minimal", "exclude": True}],
        "google/gemini-3.8-flash": [{"effort": "minimal", "exclude": True}],
        "deepseek/deepseek-v4-pro": [{"effort": "none", "exclude": True}],
    }


def test_global_reasoning_flag_applies_to_models_without_an_override(tmp_path):
    models_file = dict(PLAIN_MODELS)
    models_file["deepseek_v4_pro"] = {"slug": "deepseek/deepseek-v4-pro", "reasoning_effort": "minimal"}

    seen = reasoning_by_model(requests_for(tmp_path, models_file, reasoning_effort="low"))

    assert seen["anthropic/claude-sonnet-5.5"] == [{"effort": "low", "exclude": True}]
    assert seen["deepseek/deepseek-v4-pro"] == [{"effort": "minimal", "exclude": True}]


def test_deepseek_matched_reasoning_dry_run_plans_10912_minimal_requests(tmp_path, monkeypatch, capsys):
    manifest_path = REPO_ROOT / "runs/openrouter-v2/manifest.jsonl"
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        item = json.loads(line)
        if item["dataset_family"] == "manual":
            for rec in item["source_paths"]:
                (tmp_path / "ds" / rec["path"]).parent.mkdir(parents=True, exist_ok=True)
                (tmp_path / "ds" / rec["path"]).write_text("fn f() {}\n", encoding="utf-8")
    out_dir = tmp_path / "out"
    models_path = REPO_ROOT / "runs/deepseek-matched-reasoning/models.json"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_openrouter",
            "--dataset-root", str(tmp_path / "ds"),
            "--manifest", str(manifest_path),
            "--out-dir", str(out_dir),
            "--models", str(models_path),
            "--families", "manual",
            "--repeat-families",
            "--dry-run",
        ],
    )

    run_openrouter.main()

    assert "wrote 10912 requests" in capsys.readouterr().out
    requests = [json.loads(line) for line in (out_dir / "requests.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(requests) == 10912
    assert {r["model"] for r in requests} == {"deepseek/deepseek-v4-pro"}
    assert {json.dumps(r["reasoning"], sort_keys=True) for r in requests} == {'{"effort": "minimal", "exclude": true}'}
    config = json.loads((out_dir / "run_config.json").read_text(encoding="utf-8"))
    assert config["models"] == {
        "deepseek_v4_pro": {"slug": "deepseek/deepseek-v4-pro", "reasoning_effort": "minimal"}
    }


def test_models_file_rejects_settings_entry_without_slug_or_with_unknown_keys(tmp_path):
    for entry in ({"reasoning_effort": "minimal"}, {"slug": "deepseek/deepseek-v4-pro", "effort": "minimal"}):
        path = tmp_path / "models.json"
        path.write_text(json.dumps({"deepseek_v4_pro": entry}), encoding="utf-8")
        with pytest.raises(SystemExit):
            load_models(path)


def test_per_model_reasoning_effort_overrides_global_default(tmp_path):
    models_file = dict(PLAIN_MODELS)
    models_file["deepseek_v4_pro"] = {"slug": "deepseek/deepseek-v4-pro", "reasoning_effort": "minimal"}

    seen = reasoning_by_model(requests_for(tmp_path, models_file))

    assert seen == {
        "anthropic/claude-sonnet-5.5": [{"effort": "minimal", "exclude": True}],
        "openai/gpt-6.1-sol": [{"effort": "minimal", "exclude": True}],
        "google/gemini-3.8-flash": [{"effort": "minimal", "exclude": True}],
        "deepseek/deepseek-v4-pro": [{"effort": "minimal", "exclude": True}],
    }

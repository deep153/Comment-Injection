"""Assemble an anonymized artifact folder for double-blind review.

The folder holds the harness code, the rendered prompt templates (every defense, including the placebo),
adaptive-attack logs reduced to experiment fields, and aggregate result tables. Provider metadata
(provider names, generation ids, routing, BYOK fields, keys) is dropped from the logs; local absolute
paths become relative `runs/...` paths and identifying strings are replaced in every exported file. The
export is scanned afterwards and refused if anything identifying remains.
"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable

from .adaptive_attack import ATTACKER_MODES, AdaptiveConfig, attacker_system_prompt
from .common import read_jsonl, sha256_file
from .prompts import (
    ATTACK_TEMPLATES,
    BENIGN_TEMPLATE,
    DEFENSE_TEXT,
    DEFENSES,
    PLACEBO_DEFENSE,
    PROMPT_VERSION,
    STRIPPED_DEFENSE,
    TAG_CLOSE,
    TAG_OPEN,
    PromptVariant,
    build_messages,
    system_prompt,
    variants_for_label,
)
from .score_results import response_content

PACKAGE_DIR = Path(__file__).resolve().parent

STEP_FIELDS = (
    "request_id", "task_id", "step", "role", "attempt", "ok", "cost",
    "attacker_output", "candidate", "verdict", "confidence", "rationale", "correct", "attack_success",
)
REQUEST_FIELDS = (
    "request_id", "role", "task_id", "step", "model_key", "model", "messages", "temperature", "max_tokens",
    "response_format", "reasoning", "variant_id", "attacker_mode", "repeat", "defense", "attack_family",
    "attack_goal", "placement", "prompt_version", "prompt_sha256", "transformed_sha256",
    "item_id", "dataset_family", "sample_role", "case_id", "pair_id", "paired_item_key", "package", "label",
    "source_path",
)
USAGE_FIELDS = ("prompt_tokens", "completion_tokens", "total_tokens")
OUTCOME_FIELDS = (
    "task_id", "item_id", "dataset_family", "sample_role", "case_id", "pair_id", "paired_item_key", "package",
    "label", "source_path", "model_key", "model", "defense", "attack_family", "attack_goal", "variant_id",
    "attacker_mode", "feedback_mode", "attacker_model", "prompt_version", "query_budget", "queries_used",
    "detector_queries", "rejected_candidates", "attack_success", "first_success_step", "final_comment",
    "final_placement", "verdict", "confidence", "correct", "clean_verdict", "clean_confidence",
)
# Routing settings and per-pass notes (which describe routing fallbacks) are not exported.
CONFIG_DROP = {"passes", "allow_byok_fallback", "byok_only", "provider"}

RUN_FILES = ("scores.json", "summary.md", "gee_*.json", "gee_*.md")
ANALYSIS_FILES = ("*.md", "*.json", "*.csv")
TEXT_SUFFIXES = {".py", ".md", ".json", ".jsonl", ".csv", ".txt", ".ini"}

ABS_PATH = re.compile(r"(?<![\w.~])/(?:Users|home)/[^\s\"'`<>|),;\]]+")
KEY_PATTERNS = (
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), "<redacted-key>"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._-]{12,}"), "Bearer <redacted-key>"),
    (re.compile(r"\bgen-\d{6,}-[A-Za-z0-9]{6,}"), "<redacted-id>"),
)


def default_scrub_terms() -> list[str]:
    """Local user name (also with separators as spaces) and the git author name and email, if set."""
    terms = []
    user = getpass.getuser()
    terms += [user, re.sub(r"[-_.]+", " ", user)]
    for key in ("user.name", "user.email"):
        try:
            value = subprocess.run(["git", "config", key], capture_output=True, text=True, check=False).stdout
        except OSError:
            value = ""
        terms.append(value.strip())
    return sorted({term for term in terms if len(term) >= 3})


def relative_path(path: str) -> str:
    """`.../runs/x` -> `runs/x`, `.../rust-vuln-dataset/x` -> `rust-vuln-dataset/x`, other local paths hidden."""
    for anchor in ("runs", "rust-vuln-dataset"):
        parts = path.split("/")
        if anchor in parts:
            index = len(parts) - 1 - parts[::-1].index(anchor)
            return "/".join(parts[index:])
    return "<local-path>"


class Scrubber:
    def __init__(self, terms: Iterable[str]) -> None:
        self.terms = sorted({t for t in terms if t}, key=len, reverse=True)
        self.term_pattern = re.compile("|".join(re.escape(t) for t in self.terms), re.I) if self.terms else None

    def text(self, text: str) -> str:
        text = ABS_PATH.sub(lambda m: relative_path(m.group(0)), text)
        for pattern, replacement in KEY_PATTERNS:
            text = pattern.sub(replacement, text)
        if self.term_pattern:
            text = self.term_pattern.sub("anonymous", text)
        return text

    def hits(self, text: str) -> list[str]:
        found = [m.group(0) for m in ABS_PATH.finditer(text)]
        found += [m.group(0) for pattern, _ in KEY_PATTERNS for m in pattern.finditer(text)]
        if self.term_pattern:
            found += [m.group(0) for m in self.term_pattern.finditer(text)]
        return found


def dir_label(path: Path) -> str:
    """Destination label for an input directory: its path from the last `runs` component, else its name."""
    parts = path.resolve().parts
    if "runs" in parts:
        index = len(parts) - 1 - parts[::-1].index("runs")
        return "/".join(parts[index:])
    return path.resolve().name


def export_response(response: dict[str, Any]) -> dict[str, Any]:
    raw = response.get("raw") or {}
    choices = raw.get("choices") or [{}]
    usage = raw.get("usage") or {}
    out = {"ok": bool(response.get("ok")), "status": response.get("status")}
    if choices[0]:
        out["content"] = response_content(raw)
        out["finish_reason"] = choices[0].get("finish_reason")
    if usage:
        out["usage"] = {key: usage.get(key) for key in USAGE_FIELDS}
        out["usage"]["reasoning_tokens"] = (usage.get("completion_tokens_details") or {}).get("reasoning_tokens")
    return out


def export_step(row: dict[str, Any]) -> dict[str, Any]:
    out = {key: row[key] for key in STEP_FIELDS if key in row}
    out["request"] = {key: row["request"][key] for key in REQUEST_FIELDS if key in (row.get("request") or {})}
    out["response"] = export_response(row.get("response") or {})
    return out


def export_outcome(row: dict[str, Any]) -> dict[str, Any]:
    return {key: row[key] for key in OUTCOME_FIELDS if key in row}


def export_config(data: Any) -> Any:
    if isinstance(data, dict):
        return {key: export_config(value) for key, value in data.items() if key not in CONFIG_DROP}
    if isinstance(data, list):
        return [export_config(value) for value in data]
    return data


class Artifact:
    """Writes scrubbed files under out_dir and remembers what was written."""

    def __init__(self, out_dir: Path, scrubber: Scrubber) -> None:
        self.out_dir = out_dir
        self.scrubber = scrubber
        self.files: list[tuple[str, str]] = []

    def write_text(self, rel: str, text: str, source: str) -> None:
        path = self.out_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.scrubber.text(text), encoding="utf-8")
        self.files.append((rel, source))

    def write_json(self, rel: str, data: Any, source: str) -> None:
        self.write_text(rel, json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", source)

    def write_jsonl(self, rel: str, rows: Iterable[dict[str, Any]], source: str) -> None:
        text = "".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows)
        self.write_text(rel, text, source)


def add_code(artifact: Artifact, include_tests: bool) -> None:
    roots = [PACKAGE_DIR]
    if include_tests and (PACKAGE_DIR.parent / "tests").is_dir():
        roots.append(PACKAGE_DIR.parent / "tests")
    for root in roots:
        for path in sorted(root.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or path.name.startswith(".env"):
                continue
            if path.suffix not in TEXT_SUFFIXES:
                continue
            rel = path.relative_to(PACKAGE_DIR.parent).as_posix()
            artifact.write_text(f"code/{rel}", path.read_text(encoding="utf-8"), "harness code")
    if include_tests and (PACKAGE_DIR.parent / "pytest.ini").is_file():
        artifact.write_text("code/pytest.ini", (PACKAGE_DIR.parent / "pytest.ini").read_text(encoding="utf-8"), "harness code")


def add_prompts(artifact: Artifact) -> None:
    defenses = DEFENSES + (PLACEBO_DEFENSE, STRIPPED_DEFENSE)
    for defense in defenses:
        artifact.write_text(f"prompts/system/{defense}.txt", system_prompt(defense) + "\n", "prompts.py")
    user_template = build_messages("{code}", PromptVariant("neutral", "clean", "none", None))[0][1]["content"]
    artifact.write_text("prompts/user_template.txt", user_template + "\n", "prompts.py")
    config = AdaptiveConfig()
    for mode in ATTACKER_MODES:
        artifact.write_text(f"prompts/attacker/{mode}.txt", attacker_system_prompt(mode, config) + "\n", "adaptive_attack.py defaults")
    conditions = {
        design: {
            label: [v.variant_id for v in variants_for_label(label, extended=design == "extended", placebo=True)]
            for label in ("vulnerable", "safe")
        }
        for design in ("core", "extended")
    }
    artifact.write_json("prompts/templates.json", {
        "prompt_version": PROMPT_VERSION,
        "defense_text": DEFENSE_TEXT,
        "attack_templates": ATTACK_TEMPLATES,
        "benign_template": BENIGN_TEMPLATE,
        "tags": [TAG_OPEN, TAG_CLOSE],
        "user_template": user_template,
        "variants_by_design_and_label": conditions,
    }, "prompts.py")


def add_adaptive(artifact: Artifact, run_dir: Path) -> None:
    dest = f"adaptive/{dir_label(run_dir)}"
    source = f"{dir_label(run_dir)} (provider metadata removed)"
    artifact.write_jsonl(f"{dest}/steps.jsonl", (export_step(r) for r in read_jsonl(run_dir / "steps.jsonl")), source)
    artifact.write_jsonl(f"{dest}/outcomes.jsonl", (export_outcome(r) for r in read_jsonl(run_dir / "outcomes.jsonl")), source)
    config_path = run_dir / "run_config.json"
    if config_path.exists():
        artifact.write_json(f"{dest}/run_config.json", export_config(json.loads(config_path.read_text(encoding="utf-8"))), source)


def add_tables(artifact: Artifact, directory: Path, patterns: Iterable[str]) -> None:
    dest = f"results/{dir_label(directory)}"
    paths = sorted({path for pattern in patterns for path in directory.glob(pattern) if path.is_file()})
    for path in paths:
        if path.name == "run_config.json" or ".before-" in path.name:
            continue
        artifact.write_text(f"{dest}/{path.name}", path.read_text(encoding="utf-8"), dir_label(directory))
    config_path = directory / "run_config.json"
    if config_path.exists():
        config = export_config(json.loads(config_path.read_text(encoding="utf-8")))
        artifact.write_json(f"{dest}/run_config.json", config, f"{dir_label(directory)} (routing settings removed)")


MANIFEST_RULES = """## Scrub rules

- Adaptive `steps.jsonl` rows keep only: {step}. The `request` object keeps only: {request}. The `response` object is rebuilt as `ok`, `status`, `content` (the answer text), `finish_reason` and `usage` ({usage}, `reasoning_tokens`). Everything else is dropped, including raw provider payloads, generation ids, `provider` routing and provider names, service tiers, `is_byok` and upstream cost details, timestamps, latency and provider error bodies. `cost` is the total USD of the call.
- Adaptive `outcomes.jsonl` rows keep only: {outcome}.
- `run_config.json` files drop these keys at any depth: {drop}.
- In every exported file, absolute local paths are rewritten to `runs/...` or `rust-vuln-dataset/...` (other local paths become `<local-path>`), key-like strings and generation ids are redacted, and identifying terms are replaced with `anonymous`.
- After writing, every file is scanned for absolute local paths, key-like strings, generation ids and the identifying terms; the export fails if any remain.
"""


def write_manifest(artifact: Artifact, inputs: dict[str, list[str]]) -> None:
    lines = [
        "# Anonymized review artifact",
        "",
        f"Prompt version {PROMPT_VERSION}. Produced by `python3 -m openrouter_eval.export_review_artifact`.",
        "",
        "## Contents",
        "",
        "- `code/`: the `openrouter_eval` harness package (see `code/openrouter_eval/README.md`).",
        "- `prompts/`: rendered detector system prompts for every defense (`neutral`, `warning`, `tagged`, `placebo`, "
        "`stripped`), the user template, the default adaptive attacker system prompts and `templates.json` with every "
        "attack template and the conditions of the core and extended designs.",
        "- `adaptive/`: adaptive-attack logs: " + (", ".join(f"`{d}`" for d in inputs["adaptive"]) or "none") + ".",
        "- `results/`: aggregate tables from " + (", ".join(f"`{d}`" for d in inputs["tables"]) or "none") + ".",
        "",
        MANIFEST_RULES.format(
            step=", ".join(f"`{f}`" for f in STEP_FIELDS),
            request=", ".join(f"`{f}`" for f in REQUEST_FIELDS),
            usage=", ".join(f"`{f}`" for f in USAGE_FIELDS),
            outcome=", ".join(f"`{f}`" for f in OUTCOME_FIELDS),
            drop=", ".join(f"`{f}`" for f in sorted(CONFIG_DROP)),
        ),
        "## Files",
        "",
        "| File | Source | Bytes | SHA-256 |",
        "|---|---|---:|---|",
    ]
    for rel, source in sorted(artifact.files):
        path = artifact.out_dir / rel
        lines.append(f"| `{rel}` | {source} | {path.stat().st_size} | `{sha256_file(path)}` |")
    (artifact.out_dir / "MANIFEST.md").write_text(artifact.scrubber.text("\n".join(lines) + "\n"), encoding="utf-8")


def scan(out_dir: Path, scrubber: Scrubber) -> dict[str, list[str]]:
    """Identifying strings left in any exported file, by relative path."""
    found = {}
    for path in sorted(out_dir.rglob("*")):
        if path.is_file():
            hits = scrubber.hits(path.read_text(encoding="utf-8", errors="replace"))
            if hits:
                found[path.relative_to(out_dir).as_posix()] = sorted(set(hits))[:5]
    return found


def prepare_out_dir(out_dir: Path, force: bool) -> None:
    out = out_dir.resolve()
    if out == PACKAGE_DIR or PACKAGE_DIR in out.parents:
        raise SystemExit(f"--out-dir {out_dir} is inside the harness package")
    if out_dir.exists() and any(out_dir.iterdir()):
        if not force:
            raise SystemExit(f"{out_dir} is not empty; pass --force to replace an earlier artifact")
        if not (out_dir / "MANIFEST.md").exists():
            raise SystemExit(f"{out_dir} is not empty and holds no MANIFEST.md; refusing to replace it")
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)


def export(
    out_dir: Path,
    adaptive_run_dirs: list[Path],
    analysis_dirs: list[Path],
    run_dirs: list[Path],
    scrub_terms: Iterable[str],
    include_tests: bool = False,
    force: bool = False,
) -> Artifact:
    for directory in adaptive_run_dirs + analysis_dirs + run_dirs:
        if not directory.is_dir():
            raise SystemExit(f"{directory} is not a directory")
    prepare_out_dir(out_dir, force)
    artifact = Artifact(out_dir, Scrubber(scrub_terms))
    add_code(artifact, include_tests)
    add_prompts(artifact)
    for run_dir in adaptive_run_dirs:
        add_adaptive(artifact, run_dir)
    for directory in analysis_dirs:
        add_tables(artifact, directory, ANALYSIS_FILES)
    for run_dir in run_dirs:
        add_tables(artifact, run_dir, RUN_FILES)
    write_manifest(artifact, {
        "adaptive": [dir_label(d) for d in adaptive_run_dirs],
        "tables": [dir_label(d) for d in analysis_dirs + run_dirs],
    })
    leftovers = scan(out_dir, artifact.scrubber)
    if leftovers:
        details = "; ".join(f"{path}: {hits}" for path, hits in leftovers.items())
        raise SystemExit(f"identifying strings remain in the export: {details}")
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description="Assemble an anonymized artifact folder for double-blind review.")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--adaptive-run-dir", type=Path, action="append", default=[],
                        help="Adaptive-attack run directory (steps.jsonl, outcomes.jsonl); repeatable.")
    parser.add_argument("--analysis-dir", type=Path, action="append", default=[],
                        help="Revision-analysis output directory; its .md, .json and .csv tables are copied. Repeatable.")
    parser.add_argument("--run-dir", type=Path, action="append", default=[],
                        help="Scored run directory; scores.json, summary.md, GEE tables and run_config.json are copied. Repeatable.")
    parser.add_argument("--scrub", action="append", default=[],
                        help="Extra identifying string to replace in every file (case-insensitive); repeatable. "
                             "The local user name and git author name and email are always included.")
    parser.add_argument("--include-tests", action="store_true", help="Also copy tests/ and pytest.ini.")
    parser.add_argument("--force", action="store_true", help="Replace an earlier artifact in --out-dir.")
    args = parser.parse_args()
    artifact = export(
        args.out_dir,
        args.adaptive_run_dir,
        args.analysis_dir,
        args.run_dir,
        default_scrub_terms() + args.scrub,
        include_tests=args.include_tests,
        force=args.force,
    )
    print(f"wrote {len(artifact.files)} files and MANIFEST.md to {args.out_dir}; scan found no identifying strings")


if __name__ == "__main__":
    main()

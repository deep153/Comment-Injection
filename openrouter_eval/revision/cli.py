from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any

from ..common import write_json
from .analyses import discover
from .base import Context, Result
from .runs import AnalysisInput, load_adaptive, load_runs


def build_parser(units: dict[str, Any]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline revision analyses over scored run directories.")
    parser.add_argument("--run-dir", type=Path, action="append", default=[],
                        help="Scored run directory with parsed.jsonl; repeat to combine runs.")
    parser.add_argument("--allow-replace", action="store_true",
                        help="Let a later --run-dir replace rows an earlier one also holds (refused by default).")
    parser.add_argument("--adaptive-run-dir", type=Path, action="append", default=[],
                        help="Adaptive-attack run directory with steps.jsonl and outcomes.jsonl; repeatable.")
    parser.add_argument("--out-dir", type=Path, required=True, help="Output directory, outside every run directory.")
    parser.add_argument("--family", default="manual", help="Dataset family to analyse, or 'all'.")
    parser.add_argument("--analyses", default="all", help=f"Comma-separated subset of: {', '.join(units)}.")
    parser.add_argument("--seed", type=int, default=20260101, help="Bootstrap seed.")
    parser.add_argument("--bootstrap", type=int, default=2000, help="Cluster-bootstrap resamples.")
    for unit in units.values():
        if hasattr(unit, "add_arguments"):
            unit.add_arguments(parser)
    return parser


def check_out_dir(out_dir: Path, run_dirs: list[Path]) -> None:
    out = out_dir.resolve()
    for run_dir in run_dirs:
        run = run_dir.resolve()
        if out == run or run in out.parents:
            raise SystemExit(f"--out-dir {out_dir} is inside run directory {run_dir}; choose a separate directory")


def provenance_lines(data: AnalysisInput) -> list[str]:
    runs = "; ".join(f"`{run.run_dir}` (prompt version {', '.join(run.prompt_versions)})" for run in data.runs)
    provenance = data.provenance()
    lines = [f"Runs: {runs or 'none'}."]
    replaced = [run for run in data.runs if run.rows_replaced_by_later_runs]
    if replaced:
        lines.append("Replaced by a later run (--allow-replace): " + "; ".join(
            f"{run.rows_replaced_by_later_runs} rows of `{run.run_dir}`" for run in replaced) + ".")
    if data.adaptive:
        lines.append(f"Adaptive runs: {'; '.join(f'`{run.run_dir}`' for run in data.adaptive)}.")
    return lines + [
        f"Dataset family: {provenance['dataset_family']}; clustering unit: {provenance['clustering_unit']}; "
        f"repeats excluded.",
    ]


def write_result(out_dir: Path, name: str, result: Result, data: AnalysisInput) -> None:
    write_json(out_dir / f"{name}.json", {"analysis": name, "provenance": data.provenance(), **result.payload})
    lines = [f"# {result.title}", "", *provenance_lines(data), "", *result.markdown]
    (out_dir / f"{name}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> None:
    units = discover()
    args = build_parser(units).parse_args(argv)
    selected = list(units) if args.analyses == "all" else [name.strip() for name in args.analyses.split(",")]
    unknown = [name for name in selected if name not in units]
    if unknown:
        raise SystemExit(f"unknown analyses: {', '.join(unknown)}; available: {', '.join(units)}")
    if not args.run_dir and not args.adaptive_run_dir:
        raise SystemExit("give at least one --run-dir or --adaptive-run-dir")
    check_out_dir(args.out_dir, args.run_dir + args.adaptive_run_dir)

    started = time.perf_counter()
    data = load_runs(args.run_dir, None if args.family == "all" else args.family, args.allow_replace)
    data.adaptive = load_adaptive(args.adaptive_run_dir)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    ctx = Context(data=data, args=args, out_dir=args.out_dir)
    for name in selected:
        result = units[name].run(ctx)
        if result is None:
            print(f"skipped {name}: no applicable rows")
            continue
        write_result(args.out_dir, name, result, data)
        print(f"wrote {name}.json and {name}.md")
    print(f"analysed {len(data.rows)} rows in {time.perf_counter() - started:.1f}s; outputs under {args.out_dir}")


if __name__ == "__main__":
    main()

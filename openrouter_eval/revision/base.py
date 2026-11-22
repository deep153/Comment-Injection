from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .runs import AnalysisInput


@dataclass
class Context:
    data: AnalysisInput
    args: argparse.Namespace
    out_dir: Path


@dataclass
class Result:
    """JSON payload and Markdown body of one analysis; the CLI adds provenance to both."""

    title: str
    payload: dict[str, Any]
    markdown: list[str]


def fmt(value: float | None, digits: int = 3) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"

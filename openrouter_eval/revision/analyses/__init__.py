"""Each module here is one analysis unit, found automatically by `discover`.

A unit defines `NAME` (output file stem), `run(ctx: Context) -> Result | None`
(None skips the unit, e.g. when its inputs are absent), and optionally
`add_arguments(parser)` for unit-specific command-line options.
"""

from __future__ import annotations

import importlib
import pkgutil
from types import ModuleType


def discover() -> dict[str, ModuleType]:
    units: dict[str, ModuleType] = {}
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        module = importlib.import_module(f"{__name__}.{info.name}")
        if hasattr(module, "NAME") and hasattr(module, "run"):
            units[module.NAME] = module
    return units

from __future__ import annotations

import random
from typing import Any, Callable, Sequence, TypeVar

C = TypeVar("C")


def percentile(sorted_values: Sequence[float], q: float) -> float:
    """Linear-interpolated percentile of already sorted values, q in [0, 1]."""
    position = q * (len(sorted_values) - 1)
    low = int(position)
    high = min(low + 1, len(sorted_values) - 1)
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * (position - low)


def cluster_bootstrap(
    clusters: Sequence[C],
    statistic: Callable[[Sequence[C]], float | None],
    resamples: int,
    seed: int,
    level: float = 0.95,
) -> dict[str, Any]:
    """Percentile interval from resampling whole clusters with replacement.

    `clusters` holds one caller-defined summary per cluster (e.g. a (sum, count)
    tuple); `statistic` maps a resampled list of them to a number, or None when
    undefined for that resample (those resamples are dropped).
    """
    estimate = statistic(clusters) if clusters else None
    rng = random.Random(seed)
    values = []
    for _ in range(resamples if clusters else 0):
        value = statistic(rng.choices(clusters, k=len(clusters)))
        if value is not None:
            values.append(value)
    values.sort()
    tail = (1.0 - level) / 2
    return {
        "estimate": estimate,
        "ci_low": percentile(values, tail) if values else None,
        "ci_high": percentile(values, 1.0 - tail) if values else None,
    }


def ratio_of_sums(clusters: Sequence[tuple[float, float]]) -> float | None:
    """Pooled mean from per-cluster (sum, count) pairs."""
    total = sum(c[1] for c in clusters)
    return sum(c[0] for c in clusters) / total if total else None


def bin_labels(edges: Sequence[float]) -> list[str]:
    last = len(edges) - 2
    return [f"[{edges[i]:.1f}, {edges[i + 1]:.1f}{']' if i == last else ')'}" for i in range(len(edges) - 1)]


def bin_index(value: float, edges: Sequence[float]) -> int | None:
    """Index of the half-open bin holding value; the last bin is closed. None if out of range."""
    if value < edges[0] or value > edges[-1]:
        return None
    for i in range(len(edges) - 1):
        if value < edges[i + 1]:
            return i
    return len(edges) - 2


def bootstrap_meta(resamples: int, seed: int) -> dict[str, Any]:
    return {"resamples": resamples, "seed": seed, "unit": "vulnerable/fixed pair", "interval": "percentile 95%"}

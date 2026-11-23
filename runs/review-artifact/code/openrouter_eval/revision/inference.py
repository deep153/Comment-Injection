from __future__ import annotations

import math
from statistics import NormalDist
from typing import Any, Sequence

Z = NormalDist()


def cluster_mean(clusters: Sequence[tuple[float, float]]) -> tuple[float, float]:
    """Mean and cluster-robust standard error from per-cluster (sum, count) pairs."""
    n = sum(c[1] for c in clusters)
    mean = sum(c[0] for c in clusters) / n
    g = len(clusters)
    if g < 2:
        return mean, 0.0
    spread = sum((s - k * mean) ** 2 for s, k in clusters)
    return mean, math.sqrt(g / (g - 1) * spread) / n


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value: binomial(b + c, 1/2) on the discordant counts."""
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, k) for k in range(min(b, c) + 1))
    return min(1.0, 2 * tail / 2**n)


def holm(p_values: Sequence[float | None]) -> list[float | None]:
    """Holm step-down adjustment; None entries are left out of the family and stay None."""
    order = sorted((p, i) for i, p in enumerate(p_values) if p is not None)
    adjusted: list[float | None] = [None] * len(p_values)
    running = 0.0
    for rank, (p, i) in enumerate(order):
        running = max(running, min(1.0, (len(order) - rank) * p))
        adjusted[i] = running
    return adjusted


def tost(mean: float, se: float, margin: float, alpha: float = 0.05) -> dict[str, Any]:
    """Two one-sided z-tests of |difference| < margin and the matching (1 - 2 alpha) interval."""
    if se == 0:
        p_lower = p_upper = 0.0 if -margin < mean < margin else 1.0
    else:
        p_lower = 1.0 - Z.cdf((mean + margin) / se)
        p_upper = Z.cdf((mean - margin) / se)
    half = Z.inv_cdf(1.0 - alpha) * se
    p = max(p_lower, p_upper)
    return {
        "ci90_low": mean - half,
        "ci90_high": mean + half,
        "p_lower": p_lower,
        "p_upper": p_upper,
        "p_tost": p,
        "equivalent": p < alpha,
    }

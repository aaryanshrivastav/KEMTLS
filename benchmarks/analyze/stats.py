from __future__ import annotations

import math
import random
import statistics
from typing import Dict, Iterable, List


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * p)))
    return float(ordered[idx])


def bootstrap_ci(values: List[float], *, alpha: float = 0.05, iterations: int = 1000) -> Dict[str, float]:
    if not values:
        return {"low": 0.0, "high": 0.0}
    means: List[float] = []
    n = len(values)
    for _ in range(iterations):
        sample = [values[random.randint(0, n - 1)] for _ in range(n)]
        means.append(statistics.mean(sample))
    means.sort()
    low_i = int((alpha / 2.0) * (iterations - 1))
    high_i = int((1 - alpha / 2.0) * (iterations - 1))
    return {"low": float(means[low_i]), "high": float(means[high_i])}


def summarize(values: Iterable[float]) -> Dict[str, float]:
    vals = [float(v) for v in values]
    if not vals:
        return {
            "mean": 0.0,
            "median": 0.0,
            "min": 0.0,
            "max": 0.0,
            "stddev": 0.0,
            "p95": 0.0,
            "p99": 0.0,
            "cov": 0.0,
            "ci_low": 0.0,
            "ci_high": 0.0,
        }

    mean_v = statistics.mean(vals)
    std_v = statistics.pstdev(vals) if len(vals) > 1 else 0.0
    ci = bootstrap_ci(vals)
    cov = (std_v / mean_v) if mean_v != 0 else 0.0
    return {
        "mean": float(mean_v),
        "median": float(statistics.median(vals)),
        "min": float(min(vals)),
        "max": float(max(vals)),
        "stddev": float(std_v),
        "p95": percentile(vals, 0.95),
        "p99": percentile(vals, 0.99),
        "cov": float(cov),
        "ci_low": ci["low"],
        "ci_high": ci["high"],
    }

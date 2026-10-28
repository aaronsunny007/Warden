"""Statistics used for every reported number: Wilson intervals, exact McNemar, bootstrap."""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class Rate:
    successes: int
    n: int
    low: float
    high: float

    @property
    def value(self) -> float:
        return self.successes / self.n if self.n else float("nan")

    def fmt(self, pct: bool = True) -> str:
        if not self.n:
            return "n/a"
        f = 100.0 if pct else 1.0
        unit = "%" if pct else ""
        return f"{self.value * f:.1f}{unit} [{self.low * f:.1f}, {self.high * f:.1f}] (n={self.n})"


def wilson(successes: int, n: int, z: float = 1.959963984540054) -> Rate:
    """Wilson score interval for a binomial proportion (95% by default)."""
    if n <= 0:
        return Rate(0, 0, float("nan"), float("nan"))
    if not 0 <= successes <= n:
        raise ValueError("successes must be within [0, n]")
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    low = 0.0 if successes == 0 else max(0.0, centre - half)
    high = 1.0 if successes == n else min(1.0, centre + half)
    return Rate(successes, n, low, high)


@dataclass(frozen=True)
class McNemar:
    b: int  # pass under A, fail under B
    c: int  # fail under A, pass under B
    p_value: float


def mcnemar_exact(a: Sequence[bool], b: Sequence[bool]) -> McNemar:
    """Exact (binomial) two-sided McNemar test on paired outcomes."""
    if len(a) != len(b):
        raise ValueError("paired outcomes must have equal length")
    n01 = sum(1 for x, y in zip(a, b, strict=True) if x and not y)
    n10 = sum(1 for x, y in zip(a, b, strict=True) if not x and y)
    n = n01 + n10
    if n == 0:
        return McNemar(n01, n10, 1.0)
    k = min(n01, n10)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2**n
    return McNemar(n01, n10, min(1.0, 2 * tail))


def bootstrap_ci(
    values: Sequence[float],
    stat: Callable[[np.ndarray], float] = lambda x: float(np.percentile(x, 95)),
    n_boot: int = 2000,
    alpha: float = 0.05,
    seed: int = 0,
) -> tuple[float, float, float]:
    """Percentile bootstrap CI of a statistic (default: the 95th percentile, for latency)."""
    arr = np.asarray(values, dtype=float)
    if arr.size == 0:
        return (float("nan"), float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, arr.size, size=(n_boot, arr.size))
    boots = np.array([stat(arr[i]) for i in idx])
    return (
        stat(arr),
        float(np.percentile(boots, 100 * alpha / 2)),
        float(np.percentile(boots, 100 * (1 - alpha / 2))),
    )


def cohen_kappa(a: Sequence[str], b: Sequence[str]) -> float:
    """Cohen's kappa for two raters over the same items."""
    if len(a) != len(b) or not a:
        raise ValueError("need two equal, non-empty label sequences")
    labels = sorted(set(a) | set(b))
    n = len(a)
    po = sum(1 for x, y in zip(a, b, strict=True) if x == y) / n
    pe = sum((sum(1 for x in a if x == lab) / n) * (sum(1 for y in b if y == lab) / n) for lab in labels)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)

from __future__ import annotations

import math

from hypothesis import given
from hypothesis import strategies as st

from warden.stats import bootstrap_ci, cohen_kappa, mcnemar_exact, wilson


def test_wilson_known_values() -> None:
    r = wilson(0, 10)
    assert r.low == 0.0
    assert math.isclose(r.high, 0.2775, abs_tol=1e-3)
    r = wilson(5, 10)
    assert math.isclose(r.low, 0.2366, abs_tol=1e-3) and math.isclose(r.high, 0.7634, abs_tol=1e-3)


@given(st.integers(min_value=1, max_value=500).flatmap(lambda n: st.tuples(st.integers(0, n), st.just(n))))
def test_wilson_contains_estimate(kn: tuple[int, int]) -> None:
    k, n = kn
    r = wilson(k, n)
    assert 0.0 <= r.low <= k / n <= r.high <= 1.0


def test_mcnemar_exact() -> None:
    a = [True] * 10 + [False] * 10
    b = [False] * 10 + [False] * 10
    m = mcnemar_exact(a, b)
    assert (m.b, m.c) == (10, 0)
    assert math.isclose(m.p_value, 2 / 2**10, rel_tol=1e-9)
    assert mcnemar_exact([True, False], [True, False]).p_value == 1.0


def test_kappa() -> None:
    assert cohen_kappa(["a", "b", "a", "b"], ["a", "b", "a", "b"]) == 1.0
    assert math.isclose(cohen_kappa(["a", "a", "b", "b"], ["a", "b", "a", "b"]), 0.0)


def test_bootstrap_brackets_p95() -> None:
    vals = list(range(1, 1001))
    est, lo, hi = bootstrap_ci(vals)
    assert lo <= est <= hi

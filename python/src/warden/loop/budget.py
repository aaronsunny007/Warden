"""Hard budgets (as in AEGIS): caps on new rules, LLM calls and tokens per rolling hour.

A budget is a safety limit on the loop itself, so an adversary who provokes the loop cannot
make it propose or promote defences without bound.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class _Window:
    per_hour: int
    _start: float = field(default_factory=time.monotonic)
    _used: int = 0

    def take(self, n: int = 1) -> bool:
        now = time.monotonic()
        if now - self._start > 3600:
            self._start, self._used = now, 0
        if self._used + n > self.per_hour:
            return False
        self._used += n
        return True

    @property
    def used(self) -> int:
        return self._used


@dataclass
class Budgets:
    max_rules_per_hour: int = 6
    max_llm_calls_per_hour: int = 120
    max_llm_tokens_per_hour: int = 200_000

    def __post_init__(self) -> None:
        self.rules = _Window(self.max_rules_per_hour)
        self.llm_calls = _Window(self.max_llm_calls_per_hour)
        self.llm_tokens = _Window(self.max_llm_tokens_per_hour)

    def allow_rule(self) -> bool:
        return self.rules.take()

    def allow_llm(self, est_tokens: int) -> bool:
        return self.llm_calls.take() and self.llm_tokens.take(est_tokens)

    def snapshot(self) -> dict[str, int]:
        return {
            "rules_used": self.rules.used,
            "llm_calls_used": self.llm_calls.used,
            "llm_tokens_used": self.llm_tokens.used,
        }

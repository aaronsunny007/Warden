"""The eight-stage validation gate.

A candidate defence may only ever enforce if it passes every stage, cheapest first. A failure
at any stage stops it. The gate generalises AEGIS from HTTP requests to agent work: G3 measures
harm as benign agent tasks that no longer complete, which is also the main defence against an
adversary who tries to trick the loop into proposing a harmful rule.

Replay stages (G1, G2, G4, G5) use the trusted `warden-policy` CLI, so the compiler and the
evaluation share one implementation. The live stages (G3 utility, G6 shadow, G7 canary) run
through a UtilityProbe the caller supplies; the loop wires it to a real gateway, and tests stub
it. G8 is human approval — automation stops at canary, and in the lab a machine approval stands
in, which every report records.
"""

from __future__ import annotations

import random
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Protocol

from warden import policy_cli
from warden.loop.budget import Budgets
from warden.loop.campaign import Campaign
from warden.loop.mutate import READABLE_OBFUSCATIONS, apply_operators


@dataclass
class StageResult:
    stage: str
    passed: bool
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class GateThresholds:
    benign_fire_rate: float = 0.001  # G2
    utility_drop_points: float = 0.5  # G3 (this rule)
    utility_drop_cumulative: float = 2.0  # G3 (all promoted rules)
    mutation_block_rate: float = 0.80  # G5
    shadow_agreement: float = 0.95  # G6
    canary_percent: float = 10.0  # G7
    canary_sessions: int = 20  # G6/G7


@dataclass
class GateReport:
    candidate_id: str
    rule_id: str
    rule_hash: str
    passed: bool
    stages: list[StageResult] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def digest(self) -> str:
        import json

        body = json.dumps(
            {"rule_hash": self.rule_hash, "stages": [asdict(s) for s in self.stages]}, sort_keys=True
        )
        return sha256(body.encode()).hexdigest()


class UtilityProbe(Protocol):
    """Runs the benign task suite (and, for shadow/canary, attacks) with a candidate rule added."""

    def benign_utility(self, extra_rules: list[dict[str, Any]]) -> tuple[int, int]:
        """Return (tasks_completed, tasks_total) with the candidate added in enforce mode."""
        ...

    def attack_blocked(self, extra_rules: list[dict[str, Any]], campaigns: list[Campaign]) -> tuple[int, int]:
        """Return (attacks_stopped, attacks_total) for the given campaigns with the candidate added."""
        ...


def message_from_campaign(c: Campaign, payload: str | None = None) -> dict[str, Any]:
    """A replay message for an attack: the payload as text on the channel Warden inspects."""
    text = payload if payload is not None else c.payload
    ctx: dict[str, Any] = {
        "channel": c.channel,
        "sessionId": "gate",
        "server": c.vector.split(":")[1] if c.vector.startswith("server:") else "lab",
        "tool": c.sink_tool or "read",
        "riskTier": "read_only" if c.channel != "arguments" else "external_send",
        "tainted": c.channel == "arguments",
        "text": text,
    }
    if c.channel == "description":
        ctx["description"] = text
    return {"id": sha256(text.encode()).hexdigest()[:16], "label": "attack", "ctx": ctx}


class ValidationGate:
    def __init__(
        self,
        thresholds: GateThresholds | None = None,
        budgets: Budgets | None = None,
        probe: UtilityProbe | None = None,
        baseline_utility: tuple[int, int] | None = None,
        benign_corpus: list[dict[str, Any]] | None = None,
        promoted_rules: list[dict[str, Any]] | None = None,
    ) -> None:
        self.t = thresholds or GateThresholds()
        self.budgets = budgets or Budgets()
        self.probe = probe
        self.baseline_utility = baseline_utility
        self.benign_corpus = benign_corpus or []
        self.promoted_rules = promoted_rules or []
        self.rng = random.Random(0)
        self._cache: dict[str, tuple[int, int]] = {}

    def _utility(self, candidate: dict[str, Any]) -> tuple[int, int] | None:
        """Benign utility with the candidate added, measured once per gate run and reused by G3/G7."""
        if self.probe is None:
            return None
        key = f"{candidate['id']}:{candidate.get('version')}"
        if key not in self._cache:
            self._cache[key] = self.probe.benign_utility([*self.promoted_rules, candidate])
        return self._cache[key]

    def run(
        self, candidate: dict[str, Any], campaign: Campaign, cumulative_drop_points: float = 0.0
    ) -> GateReport:
        self._cache.clear()
        rule_hash = policy_cli.hashes([candidate]).get(candidate["id"], "")
        report = GateReport(
            candidate_id=campaign.id, rule_id=candidate["id"], rule_hash=rule_hash, passed=False
        )
        for stage in (self._g1, self._g2, self._g4, self._g5, self._g3, self._g6, self._g7, self._g8):
            result = stage(candidate, campaign, cumulative_drop_points)
            report.stages.append(result)
            if not result.passed:
                report.passed = False
                return report
        report.passed = True
        return report

    # G1 static check -------------------------------------------------------
    def _g1(self, candidate: dict[str, Any], c: Campaign, _cum: float) -> StageResult:
        lint = policy_cli.lint([candidate])[0]
        if not lint.get("ok"):
            return StageResult("G1", False, {"errors": lint.get("errors", [])})
        if not self.budgets.allow_rule():
            return StageResult(
                "G1", False, {"budget": self.budgets.snapshot(), "reason": "rule budget exhausted"}
            )
        return StageResult("G1", True, {"hash": lint.get("hash")})

    # G2 benign replay ------------------------------------------------------
    def _g2(self, candidate: dict[str, Any], _c: Campaign, _cum: float) -> StageResult:
        if not self.benign_corpus:
            return StageResult("G2", True, {"skipped": "no benign corpus provided"})
        rows, _summary = policy_cli.replay([candidate], self.benign_corpus, force_mode="enforce")
        fired = [r for r in rows if r["enforced"]]
        rate = len(fired) / len(rows) if rows else 0.0
        return StageResult(
            "G2",
            rate <= self.t.benign_fire_rate,
            {"fired": len(fired), "n": len(rows), "rate": rate, "max": self.t.benign_fire_rate},
        )

    # G4 attack replay ------------------------------------------------------
    def _g4(self, candidate: dict[str, Any], c: Campaign, _cum: float) -> StageResult:
        rows, _ = policy_cli.replay([candidate], [message_from_campaign(c)], force_mode="enforce")
        blocked = bool(rows and rows[0]["enforced"])
        return StageResult("G4", blocked, {"blocks_campaign": blocked})

    # G5 mutation test ------------------------------------------------------
    def _g5(self, candidate: dict[str, Any], c: Campaign, _cum: float) -> StageResult:
        # One obfuscation technique per mutant: G5 asks whether the rule generalises across each
        # meaning-preserving variant of the attack, not whether it survives compounded corruption.
        mutants = []
        rng = random.Random(sha256(c.signature.encode()).digest()[0])
        for op in READABLE_OBFUSCATIONS:
            for _ in range(3):
                mutants.append(message_from_campaign(c, apply_operators(c.payload, [op], rng)))
        rows, _ = policy_cli.replay([candidate], mutants, force_mode="enforce")
        blocked = sum(1 for r in rows if r["enforced"])
        rate = blocked / len(rows) if rows else 0.0
        return StageResult(
            "G5",
            rate >= self.t.mutation_block_rate,
            {"blocked": blocked, "n": len(rows), "rate": rate, "min": self.t.mutation_block_rate},
        )

    # G3 utility regression -------------------------------------------------
    def _g3(self, candidate: dict[str, Any], _c: Campaign, cumulative_drop: float) -> StageResult:
        util = self._utility(candidate)
        if util is None or self.baseline_utility is None:
            return StageResult("G3", True, {"skipped": "no utility probe"})
        done, total = util
        base_done, base_total = self.baseline_utility
        base_rate = base_done / base_total if base_total else 0.0
        new_rate = done / total if total else 0.0
        drop = (base_rate - new_rate) * 100
        ok = (
            drop <= self.t.utility_drop_points
            and (cumulative_drop + max(drop, 0.0)) <= self.t.utility_drop_cumulative
        )
        return StageResult(
            "G3",
            ok,
            {
                "baseline_rate": base_rate,
                "new_rate": new_rate,
                "drop_points": drop,
                "cumulative_after": cumulative_drop + max(drop, 0.0),
                "max_this": self.t.utility_drop_points,
                "max_cumulative": self.t.utility_drop_cumulative,
            },
        )

    # G6 shadow -------------------------------------------------------------
    def _g6(self, candidate: dict[str, Any], c: Campaign, _cum: float) -> StageResult:
        if self.probe is None:
            return StageResult("G6", True, {"skipped": "no utility probe"})
        stopped, total = self.probe.attack_blocked([*self.promoted_rules, candidate], [c])
        # Live behaviour should match the replay prediction (G4 said it blocks).
        agree = stopped / total if total else 0.0
        return StageResult(
            "G6",
            agree >= self.t.shadow_agreement,
            {"stopped": stopped, "n": total, "agreement": agree, "min": self.t.shadow_agreement},
        )

    # G7 canary -------------------------------------------------------------
    def _g7(self, candidate: dict[str, Any], _c: Campaign, cumulative_drop: float) -> StageResult:
        util = self._utility(candidate)
        if util is None or self.baseline_utility is None:
            return StageResult("G7", True, {"skipped": "no utility probe"})
        # Enforce on a slice; the alarm is the same utility budget as G3 (reusing its measurement).
        done, total = util
        base_done, base_total = self.baseline_utility
        drop = ((base_done / base_total if base_total else 0.0) - (done / total if total else 0.0)) * 100
        rolled_back = drop > self.t.utility_drop_points
        return StageResult(
            "G7",
            not rolled_back,
            {"canary_percent": self.t.canary_percent, "drop_points": drop, "rolled_back": rolled_back},
        )

    # G8 human approval -----------------------------------------------------
    def _g8(self, _candidate: dict[str, Any], _c: Campaign, _cum: float) -> StageResult:
        # Automation stops at canary. Promotion to enforce needs a human; the control plane opens a
        # pull request with this report. In the lab, a machine approval stands in and is recorded.
        return StageResult(
            "G8", True, {"requires": "human approval (machine approval in lab mode)", "human": False}
        )

"""The loop: attack, confirm, propose, gate, promote, remember.

Runs red-team rounds against a live gateway whose signed bundle grows as defences are promoted.
With the gate on, only candidates that pass every stage promote; with it off (RQ2), every
proposal promotes, which is how an adversary induces self-DoS. The runner reports ASR per round
(RQ3), benign utility per round, and the benign utility lost to promoted rules (RQ2), with the
gate on and off.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from warden import __version__, policy_cli
from warden.eval.lab import LabClient
from warden.eval.scenarios import Suite, load_suite
from warden.eval.stack import Stack
from warden.loop.blue import BlueTeam
from warden.loop.budget import Budgets
from warden.loop.campaign import Campaign
from warden.loop.gate import GateThresholds, ValidationGate
from warden.loop.memory import DefenceMemory, DefenceRecord
from warden.loop.persist import LoopStore
from warden.loop.probe import GateProbe
from warden.loop.red import RedTeam, RedTeamConfig
from warden.settings import get_settings

log = logging.getLogger("warden.loop")


@dataclass
class LoopConfig:
    rounds: int = 5
    attempts_per_round: int = 30
    gated: bool = True
    seed: int = 0
    # Rules the loop starts from. "minimal" (spotlight only, like B1) leaves headroom so the
    # loop's learning is visible; "baseline" starts from the full shipped ruleset (B3).
    start_rules: str = "minimal"
    blend_rate: float = 0.0


@dataclass
class RoundRecord:
    round: int
    attempts: int
    bypasses: int
    asr: float
    proposals: int
    promoted: int
    gate_failures: int
    promoted_rules: list[str]
    benign_utility: list[int]  # [done, total]
    harmful_promotions: int


@dataclass
class LoopResult:
    run_id: str
    gated: bool
    rounds: list[RoundRecord] = field(default_factory=list)
    final_rules: list[dict[str, Any]] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


def _sign_bundle(stack: Stack, rules: list[dict[str, Any]], bundle_id: str) -> dict[str, Any]:
    from warden.loop.probe import _dedupe_by_id

    enforced = [{**r, "mode": "enforce"} for r in _dedupe_by_id(rules)]
    hashes = policy_cli.hashes(enforced)
    approvals = [
        {
            "ruleId": r["id"],
            "version": r["version"],
            "ruleHash": hashes[r["id"]],
            "stage": "enforce",
            "gateReport": "0" * 64,
            "approvedBy": "loop",
            "human": False,
            "approvedAt": "2026-01-01T00:00:00Z",
        }
        for r in enforced
    ]
    return policy_cli.sign(
        policy_cli.build_bundle(enforced, approvals, bundle_id, allow_machine_approval=True),
        stack.key,
        stack.key_id,
    )


class LoopRunner:
    def __init__(self, suite: Suite, cfg: LoopConfig) -> None:
        self.suite = suite
        self.cfg = cfg
        full: list[dict[str, Any]] = json.loads(
            (get_settings().repo_root / "policies" / "baseline.rules.json").read_text()
        )
        self.full_baseline = full
        # The probe measures benign utility against the FULL baseline (that is Warden's real
        # false-positive floor); the loop GATEWAY starts from start_rules.
        self.baseline_rules = [] if cfg.start_rules == "minimal" else full
        self.memory = DefenceMemory()
        self.store = LoopStore(get_settings().database_url)

    def run(self) -> LoopResult:
        run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + ("-gated" if self.cfg.gated else "-ungated")
        result = LoopResult(run_id=run_id, gated=self.cfg.gated)
        loop_gid, gate_gid = "B3-core", "GATE-core"
        with Stack(baselines=[loop_gid, gate_gid]) as stack:
            lab = LabClient(stack.lab_url)
            probe = GateProbe(stack, gate_gid, self.suite, self.full_baseline, lab, run_id)
            promoted: list[dict[str, Any]] = []
            cumulative_drop = 0.0
            baseline_done, baseline_total = asyncio.run(probe._run_benign())
            red = RedTeam(
                self.suite,
                lab,
                stack.gateway_url(loop_gid),
                stack.lab_url,
                run_id,
                RedTeamConfig(self.cfg.attempts_per_round, 2, self.cfg.seed, blend_rate=self.cfg.blend_rate),
            )
            blue = BlueTeam(
                self.memory,
                llm=None,
                budget=Budgets(
                    get_settings().max_rules_per_hour,
                    get_settings().max_llm_calls_per_hour,
                    get_settings().max_llm_tokens_per_hour,
                ),
            )
            gate = ValidationGate(
                GateThresholds(),
                blue.budget,
                probe,
                (baseline_done, baseline_total),
                self._benign_corpus(stack, probe),
                promoted,
            )

            for rnd in range(self.cfg.rounds):
                round_res = asyncio.run(red.run_round(rnd))
                log.info(
                    "round %d: %d/%d bypassed (ASR %.2f)",
                    rnd,
                    len(round_res.bypasses),
                    round_res.attempts,
                    round_res.asr,
                )
                proposals = promoted_now = gate_failures = harmful = 0
                for campaign in round_res.bypasses:
                    self.store.campaign(campaign, bypass=True)
                    prop = blue.propose(campaign, rnd)
                    if prop is None:
                        continue
                    proposals += 1
                    if prop.author == "memory":
                        self.memory.add_signature(prop.rule["id"], campaign.signature)
                        continue
                    report_id: str | None = None
                    if self.cfg.gated:
                        gate.promoted_rules = promoted
                        report = gate.run(prop.rule, campaign, cumulative_drop)
                        report_id = self.store.gate_report(report)
                        if not report.passed:
                            gate_failures += 1
                            self.store.candidate(
                                campaign.id,
                                campaign.id,
                                prop.author,
                                prop.rule,
                                report.rule_hash,
                                "failed",
                                report.stages[-1].stage,
                                report_id,
                            )
                            continue
                        g3 = next((s for s in report.stages if s.stage == "G3"), None)
                        if g3 and "drop_points" in g3.detail:
                            cumulative_drop += max(float(g3.detail["drop_points"]), 0.0)
                    else:
                        # Ungated: promote every proposal, no gate. This is the RQ2 adversary's lever.
                        harmful += self._would_harm(prop.rule, gate)
                    self._promote(stack, promoted, prop.rule, campaign)
                    self.store.candidate(
                        campaign.id,
                        campaign.id,
                        prop.author,
                        prop.rule,
                        policy_cli.hashes([prop.rule])[prop.rule["id"]],
                        "awaiting_approval" if self.cfg.gated else "approved",
                        "G8" if self.cfg.gated else "enforce",
                        report_id,
                    )
                    promoted_now += 1
                # Re-arm the gateway and re-measure this round.
                if promoted_now:
                    stack.put_policy(
                        loop_gid, _sign_bundle(stack, [*self.baseline_rules, *promoted], f"loop-r{rnd}")
                    )
                    red.gateway_url = stack.gateway_url(loop_gid)
                done, total = asyncio.run(probe._run_benign())
                result.rounds.append(
                    RoundRecord(
                        rnd,
                        round_res.attempts,
                        len(round_res.bypasses),
                        round(round_res.asr, 4),
                        proposals,
                        promoted_now,
                        gate_failures,
                        [r["id"] for r in promoted],
                        [done, total],
                        harmful,
                    )
                )
            result.final_rules = promoted
            result.meta = {
                "version": __version__,
                "baseline_utility": [baseline_done, baseline_total],
                "budgets": blue.budget.snapshot() if blue.budget else {},
                "promoted": len(promoted),
            }
            lab.close()
        return result

    def _benign_corpus(self, stack: Stack, probe: GateProbe) -> list[dict[str, Any]]:
        # Record one benign pass's inspected messages as the G2 corpus.
        asyncio.run(probe._run_benign())
        msgs = stack.admin("GATE-core", "/messages?limit=200000") or []
        return [
            {"id": m["verdictId"], "ctx": m["ctx"], "label": "benign"}
            for m in msgs
            if m["ctx"]["channel"] in {"arguments", "output"}
        ]

    def _would_harm(self, rule: dict[str, Any], gate: ValidationGate) -> int:
        """Count a promotion as harmful if it would have failed the benign-replay stage."""
        if not gate.benign_corpus:
            return 0
        rows, _ = policy_cli.replay([rule], gate.benign_corpus, force_mode="enforce")
        return 1 if any(r["enforced"] for r in rows) else 0

    def _promote(
        self, stack: Stack, promoted: list[dict[str, Any]], rule: dict[str, Any], campaign: Campaign
    ) -> None:
        promoted.append(rule)
        rec = DefenceRecord(
            rule["id"], rule["version"], policy_cli.hashes([rule])[rule["id"]], rule, [campaign.signature]
        )
        self.memory.remember(rec)
        self.store.defence(rec)


def run_loop_experiment(
    gated: bool,
    rounds: int,
    attempts: int,
    seed: int,
    out_dir: Path | None,
    suite_path: str | None = None,
    start_rules: str = "minimal",
    blend_rate: float = 0.0,
) -> dict[str, Any]:
    suite = load_suite(suite_path)
    res = LoopRunner(
        suite, LoopConfig(rounds, attempts, gated, seed, start_rules=start_rules, blend_rate=blend_rate)
    ).run()
    out = out_dir or (Path("results") / "loop" / res.run_id)
    out.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": res.run_id,
        "gated": res.gated,
        "meta": res.meta,
        "rounds": [asdict(r) for r in res.rounds],
    }
    (out / "loop.json").write_text(json.dumps(payload, indent=2, default=str))
    (out / "promoted.json").write_text(json.dumps(res.final_rules, indent=2))
    return {"out": str(out), **payload}

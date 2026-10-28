"""A UtilityProbe backed by a live Warden gateway.

G3/G6/G7 ask: with this candidate rule added in enforce mode, do benign tasks still complete,
and are the attacks stopped? This probe answers by swapping the gateway's signed bundle (via the
admin API) to baseline + promoted + candidate, then running the benign task suite and the
campaigns through it with the simulated agent, and judging on lab state.
"""

from __future__ import annotations

import asyncio
from typing import Any

from warden import policy_cli
from warden.eval import judge
from warden.eval.agent_sim import AttackSpec, SimulatedAgent
from warden.eval.lab import LabClient
from warden.eval.scenarios import Suite, vector_to_target
from warden.eval.stack import Stack
from warden.eval.tools import ToolSession
from warden.loop.campaign import Campaign


def _dedupe_by_id(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep the last rule for each id (a reproposal supersedes an earlier version)."""
    by_id: dict[str, dict[str, Any]] = {}
    for r in rules:
        by_id[r["id"]] = r
    return list(by_id.values())


class GateProbe:
    def __init__(
        self,
        stack: Stack,
        gid: str,
        suite: Suite,
        baseline_rules: list[dict[str, Any]],
        lab: LabClient,
        run_id: str,
        max_tasks: int | None = None,
    ) -> None:
        self.stack = stack
        self.gid = gid
        self.suite = suite
        self.baseline_rules = baseline_rules
        self.lab = lab
        self.run_id = run_id
        self.agent = SimulatedAgent(suite.spotlight_factor, suite.mcp_compliance_p)
        self._n = 0
        self._tasks = suite.benign_tasks[:max_tasks] if max_tasks else suite.benign_tasks

    def _install(self, extra_rules: list[dict[str, Any]]) -> None:
        # Candidates are proposed in shadow mode; the probe tests them as if enforcing. Hashes and
        # approvals are computed on the enforce-mode rules (mode is part of the rule hash).
        merged = _dedupe_by_id([*self.baseline_rules, *extra_rules])
        enforced = [{**r, "mode": "enforce"} for r in merged]
        hashes = policy_cli.hashes(enforced)
        approvals = [
            {
                "ruleId": r["id"],
                "version": r["version"],
                "ruleHash": hashes[r["id"]],
                "stage": "enforce",
                "gateReport": "0" * 64,
                "approvedBy": "gate-probe",
                "human": False,
                "approvedAt": "2026-01-01T00:00:00Z",
            }
            for r in enforced
        ]
        bundle = policy_cli.sign(
            policy_cli.build_bundle(enforced, approvals, f"gate-{self._n}", allow_machine_approval=True),
            self.stack.key,
            self.stack.key_id,
        )
        self.stack.put_policy(self.gid, bundle)
        self._n += 1

    def benign_utility(self, extra_rules: list[dict[str, Any]]) -> tuple[int, int]:
        self._install(extra_rules)
        return asyncio.run(self._run_benign())

    def attack_blocked(self, extra_rules: list[dict[str, Any]], campaigns: list[Campaign]) -> tuple[int, int]:
        self._install(extra_rules)
        return asyncio.run(self._run_attacks(campaigns))

    async def _run_benign(self) -> tuple[int, int]:
        url = self.stack.gateway_url(self.gid)
        done = 0
        for task in self._tasks:
            self.lab.reset([])
            session = f"{self.run_id}:probe:{self._n}:{task.id}"
            async with ToolSession(
                session,
                task.prompt,
                gateway_url=url,
                lab_url=self.stack.lab_url,
                servers=list(self.suite.servers),
            ) as ts:
                ep = await self.agent.run(task, ts, None, case_key=f"probe|{task.id}")
            if judge.check(task.success, self.lab.state(), ep.answer):
                done += 1
        return done, len(self._tasks)

    async def _run_attacks(self, campaigns: list[Campaign]) -> tuple[int, int]:
        url = self.stack.gateway_url(self.gid)
        stopped = 0
        for c in campaigns:
            task = next(
                (t for t in self.suite.benign_tasks if any(r == c.vector for r in t.reads)),
                self.suite.benign_tasks[0],
            )
            inj = (
                self.suite.injection(c.goal)
                if c.goal in {i.id for i in self.suite.injection_tasks}
                else self.suite.injection_tasks[0]
            )
            self.lab.reset([{"target": vector_to_target(c.vector), "payload": c.payload, "mode": "append"}])
            session = f"{self.run_id}:probe-atk:{self._n}:{c.id}"
            async with ToolSession(
                session,
                task.prompt,
                gateway_url=url,
                lab_url=self.stack.lab_url,
                servers=list(self.suite.servers),
            ) as ts:
                spec = AttackSpec(
                    kind="content",
                    template=c.family,
                    p=self.suite.templates[c.family].p if c.family in self.suite.templates else 0.5,
                    injection=inj,
                )
                ep = await self.agent.run(task, ts, spec, case_key=f"probe-atk|{c.id}")
            if not judge.check(inj.success, self.lab.state(), ep.answer):
                stopped += 1
        return stopped, len(campaigns)

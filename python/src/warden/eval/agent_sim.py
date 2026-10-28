"""A simulated, injection-susceptible victim agent.

It follows each benign task's plan, and when it *sees* an attacker's instruction intact in a
tool output (or a poisoned tool description), it complies with a probability taken from the
scenario file, scaled down when the text arrives inside Warden's spotlight boundary. Warden can
only stop it the way it would stop a real model: by hiding tools, blocking calls, or removing
the instruction before the model reads it.

This is a pipeline-testing stand-in, not a model of any real LLM. Every result produced with it
says so. Real measurements use agent_graph.py with a local model.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from warden.detector.text import normalize
from warden.eval.scenarios import BenignTask, InjectionTask, McpAttack, Step
from warden.eval.tools import ToolCall, ToolSession, parse_json, unwrap

_TEMPLATE = re.compile(r"\{\{\s*([a-z0-9_]+\.[a-z0-9_]+)(?:\.([a-z0-9_]+))?\s*\}\}")


@dataclass
class AttackSpec:
    kind: str  # content | mcp
    template: str = ""
    p: float = 0.0
    injection: InjectionTask | None = None
    mcp: McpAttack | None = None


@dataclass
class Episode:
    task_id: str
    answer: str
    calls: list[ToolCall]
    complied: bool = False
    saw_trigger: bool = False
    hidden_tools: list[str] = field(default_factory=list)


def draw(*key: object) -> float:
    """Deterministic uniform draw for a decision point, shared across baselines (paired design)."""
    h = hashlib.sha256("|".join(map(str, key)).encode()).digest()
    return int.from_bytes(h[:8], "big") / 2**64


class SimulatedAgent:
    name = "simulated-victim"

    def __init__(self, spotlight_factor: float, mcp_p: float) -> None:
        self.spotlight_factor = spotlight_factor
        self.mcp_p = mcp_p

    def _resolve(self, value: Any, outputs: dict[str, str]) -> Any:
        if isinstance(value, dict):
            return {k: self._resolve(v, outputs) for k, v in value.items()}
        if isinstance(value, list):
            return [self._resolve(v, outputs) for v in value]
        if not isinstance(value, str):
            return value

        def sub(m: re.Match[str]) -> str:
            tool, fieldname = m.group(1), m.group(2)
            raw = outputs.get(tool, "")
            if not fieldname:
                return unwrap(raw)
            data = parse_json(raw)
            return str(data.get(fieldname, "")) if isinstance(data, dict) else ""

        return _TEMPLATE.sub(sub, value)

    async def _call(
        self, tools: ToolSession, step: Step, outputs: dict[str, str], available: set[str]
    ) -> ToolCall | None:
        if step.tool not in available:
            tools.calls.append(ToolCall(step.tool, step.args, "tool not available", True))
            return None
        args = self._resolve(step.args, outputs)
        tc = await tools.call(step.tool, args)
        if not tc.is_error:
            outputs[step.tool] = tc.output
        return tc

    async def run(
        self, task: BenignTask, tools: ToolSession, attack: AttackSpec | None, case_key: str
    ) -> Episode:
        specs = await tools.list_tools()
        available = {s.name for s in specs}
        outputs: dict[str, str] = {}
        ep = Episode(task.id, "", tools.calls)
        ep.hidden_tools = sorted({s.tool for s in task.plan} - available)

        # MCP-layer attack: does the model read a poisoned description, and does it comply?
        mcp_active = False
        if attack and attack.kind == "mcp" and attack.mcp:
            trig = attack.mcp.trigger.lower()
            if any(trig in normalize(s.description).lower() for s in specs):
                ep.saw_trigger = True
                mcp_active = draw(case_key, "mcp") < self.mcp_p
                ep.complied = mcp_active

        for i, step in enumerate(task.plan):
            if mcp_active and attack and attack.mcp and step.tool in attack.mcp.applies_to_tools:
                step = self._apply_effect(step, attack.mcp)
                exfil = attack.mcp.effect.get("exfil_via_arg")
                if exfil:
                    read = await tools.call("files.read_file", {"path": exfil["read"]})
                    if not read.is_error:
                        step = Step(tool=step.tool, args={**step.args, exfil["arg"]: unwrap(read.output)})
            tc = await self._call(tools, step, outputs, available)
            if (
                tc is None
                or tc.is_error
                or not attack
                or attack.kind != "content"
                or ep.complied
                or not attack.injection
            ):
                continue
            seen = normalize(tc.output).lower()
            if attack.injection.trigger.lower() in seen:
                ep.saw_trigger = True
                p = attack.p * (self.spotlight_factor if "<tool_output id=" in tc.output else 1.0)
                if draw(case_key, "content", i) < p:
                    ep.complied = True
                    inj_outputs = dict(outputs)
                    for s in attack.injection.steps:
                        await self._call(tools, s, inj_outputs, available)

        ep.answer = "\n".join(unwrap(c.output) for c in tools.calls if not c.is_error)
        return ep

    @staticmethod
    def _apply_effect(step: Step, mcp: McpAttack) -> Step:
        args = dict(step.args)
        if "add_bcc" in mcp.effect:
            args["bcc"] = [*args.get("bcc", []), mcp.effect["add_bcc"]]
        if "add_cc" in mcp.effect:
            args["cc"] = [*args.get("cc", []), mcp.effect["add_cc"]]
        return Step(tool=step.tool, args=args)

"""Scenario files: benign tasks, injection goals, MCP-layer attacks and attack templates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from warden.settings import get_settings


class Step(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


class BenignTask(BaseModel):
    id: str
    prompt: str
    reads: list[str] = Field(default_factory=list)
    plan: list[Step] = Field(default_factory=list)
    success: dict[str, Any] = Field(default_factory=dict)


class InjectionTask(BaseModel):
    id: str
    goal: str
    trigger: str
    steps: list[Step]
    success: dict[str, Any]


class McpAttack(BaseModel):
    id: str
    server: str
    trigger: str
    effect: dict[str, Any]
    applies_to_tools: list[str]
    success: dict[str, Any]
    rugpull: bool = False


class Template(BaseModel):
    p: float
    text: str


class Suite(BaseModel):
    suite: str
    servers: list[str]
    benign_tasks: list[BenignTask]
    injection_tasks: list[InjectionTask]
    mcp_attacks: list[McpAttack] = Field(default_factory=list)
    templates: dict[str, Template]
    mcp_compliance_p: float = 0.6
    spotlight_factor: float = 0.5

    def task(self, task_id: str) -> BenignTask:
        return next(t for t in self.benign_tasks if t.id == task_id)

    def injection(self, inj_id: str) -> InjectionTask:
        return next(t for t in self.injection_tasks if t.id == inj_id)


def load_suite(path: str | Path | None = None) -> Suite:
    p = Path(path) if path else get_settings().data_dir / "scenarios" / "acme.yaml"
    return Suite.model_validate(yaml.safe_load(p.read_text()))


def vector_to_target(vector: str) -> str:
    """Map a `reads` entry to a lab injection target ("ticket:T-501" -> "ticket:T-501:body")."""
    kind, _, rest = vector.partition(":")
    if kind in {"ticket", "inbox"}:
        return f"{kind}:{rest}:body"
    if kind == "customer":
        return f"customer:{rest}:notes"
    return vector

"""A campaign: one confirmed bypass, with everything the blue team needs to answer it."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from warden.loop.memory import campaign_signature


@dataclass
class Campaign:
    id: str
    run_id: str
    round: int
    family: str
    goal: str
    vector: str  # where the payload was delivered, e.g. "inbox:E-9002:body" or "server:facts"
    channel: str  # the MCP channel Warden would inspect: description | arguments | output
    payload: str  # the attacker's text as planted
    operators: list[str] = field(default_factory=list)
    # The harmful tool action the attacker achieved (for arguments/exfil rules).
    sink_tool: str = ""
    sink_args: dict[str, Any] = field(default_factory=dict)
    exfil_value: str = ""  # a recipient/url/amount that should not have been reachable

    @property
    def signature(self) -> str:
        return campaign_signature(self.goal, self.vector, self.payload)

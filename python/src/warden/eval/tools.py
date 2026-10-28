"""Tool access for victim agents: through Warden (one MCP endpoint) or direct to the lab (B0)."""

from __future__ import annotations

import json
import re
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any, cast

from mcp import Client
from mcp.types import RequestParamsMeta


@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any]
    output: str
    is_error: bool


@dataclass
class ToolSession:
    """One agent episode's view of its tools. `gateway_url` set = through Warden; else direct to lab."""

    session_id: str
    user_request: str
    gateway_url: str | None = None
    lab_url: str | None = None
    servers: list[str] = field(default_factory=list)
    calls: list[ToolCall] = field(default_factory=list)
    _stack: AsyncExitStack = field(default_factory=AsyncExitStack)
    _clients: dict[str, Client] = field(default_factory=dict)

    async def __aenter__(self) -> ToolSession:
        if self.gateway_url:
            self._clients["*"] = await self._stack.enter_async_context(
                Client(f"{self.gateway_url.rstrip('/')}/mcp")
            )
        else:
            assert self.lab_url, "direct mode needs lab_url"
            for s in self.servers:
                self._clients[s] = await self._stack.enter_async_context(
                    Client(f"{self.lab_url.rstrip('/')}/mcp/{s}")
                )
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._stack.aclose()

    @property
    def meta(self) -> dict[str, Any]:
        return {"io.warden/session": self.session_id, "io.warden/user-request": self.user_request}

    async def list_tools(self) -> list[ToolSpec]:
        out: list[ToolSpec] = []
        if "*" in self._clients:
            res = await self._clients["*"].list_tools(cache_mode="bypass")
            for t in res.tools:
                out.append(ToolSpec(t.name, t.description or "", dict(t.input_schema or {})))
        else:
            for s, c in self._clients.items():
                res = await c.list_tools(cache_mode="bypass")
                for t in res.tools:
                    out.append(ToolSpec(f"{s}.{t.name}", t.description or "", dict(t.input_schema or {})))
        return out

    async def call(self, name: str, args: dict[str, Any]) -> ToolCall:
        if "*" in self._clients:
            client, tool = self._clients["*"], name
        else:
            server, _, tool = name.partition(".")
            client = self._clients.get(server)  # type: ignore[assignment]
            if client is None:
                tc = ToolCall(name, args, f"unknown tool {name}", True)
                self.calls.append(tc)
                return tc
        try:
            r = await client.call_tool(tool, args, meta=cast(RequestParamsMeta, self.meta))
            text = "\n".join(getattr(c, "text", "") or "" for c in r.content)
            tc = ToolCall(name, args, text, bool(r.is_error))
        except Exception as e:  # noqa: BLE001 - a transport failure is a tool error to the agent
            tc = ToolCall(name, args, f"tool error: {e}", True)
        self.calls.append(tc)
        return tc


_WRAPPER = re.compile(r'^<tool_output id="[0-9a-f]+"[^>]*>\n(.*)\n</tool_output id="[0-9a-f]+">', re.S)


def unwrap(text: str) -> str:
    """Strip Warden's spotlight boundary to get the tool's own text."""
    m = _WRAPPER.match(text)
    return m.group(1) if m else text


def parse_json(text: str) -> Any:
    try:
        return json.loads(unwrap(text))
    except (json.JSONDecodeError, ValueError):
        return None

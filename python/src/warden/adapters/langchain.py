"""Guard LangChain / LangGraph tools: inspect every tool output before the model reads it.

    from warden.adapters.langchain import guard_tools
    tools = guard_tools([search_tool, email_tool])          # in-process
    tools = guard_tools(tools, WardenClient("http://warden:8000"))

A tool whose output is judged malicious returns a short notice instead of the content. Uncertain
output is returned unchanged unless you pass `block_uncertain=True` (the lite classifier is cautious,
so blocking on uncertain will also stop some harmless text).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from langchain_core.tools import BaseTool
from pydantic import ConfigDict

from warden.adapters.client import WardenClient


def _text(out: Any) -> str:
    if isinstance(out, str):
        return out
    content = getattr(out, "content", None)  # ToolMessage and friends
    return content if isinstance(content, str) else str(out if content is None else content)


class GuardedTool(BaseTool):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    inner: Any
    warden: Any
    block_uncertain: bool = False

    def _verdict_notice(self, out: Any) -> Any:
        v = self.warden.check(_text(out), "output", "read_only")
        stop = v.malicious or (self.block_uncertain and v.verdict == "uncertain")
        if not stop:
            return out
        return f"[Warden blocked the output of {self.name}. {v.explanation}]"

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        return self._verdict_notice(self.inner.invoke(kwargs or (args[0] if args else {})))

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        return self._verdict_notice(await self.inner.ainvoke(kwargs or (args[0] if args else {})))


def guard_tool(
    tool: BaseTool, client: WardenClient | None = None, *, block_uncertain: bool = False
) -> GuardedTool:
    return GuardedTool(
        name=tool.name,
        description=tool.description,
        args_schema=tool.args_schema,
        return_direct=tool.return_direct,
        inner=tool,
        warden=client or WardenClient(),
        block_uncertain=block_uncertain,
    )


def guard_tools(
    tools: Sequence[BaseTool], client: WardenClient | None = None, *, block_uncertain: bool = False
) -> list[GuardedTool]:
    shared = client or WardenClient()
    return [guard_tool(t, shared, block_uncertain=block_uncertain) for t in tools]

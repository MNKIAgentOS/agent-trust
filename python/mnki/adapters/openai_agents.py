"""
OpenAI Agents SDK (Python) — `openai-agents`. `FunctionTool.on_invoke_tool(ctx, input_json)` is verified before
the original runs; every other attribute (name, params_json_schema, strict…) is untouched, so `Agent(tools=…)`
accepts the guarded copies.

    from agents import Agent, function_tool
    from mnki.adapters.openai_agents import guard_tools
    agent = Agent(name="invoice-agent", tools=guard_tools(guard, [refund, lookup]))
"""
from __future__ import annotations
import copy, json
from typing import Any, Optional

from .shared import check_or_refuse, parse_json_args, wanted


def guard_tool(guard: Any, tool: Any, on_refused: str = "result", only: Optional[list] = None, skip: Optional[list] = None, tool_name=None) -> Any:
    name = getattr(tool, "name", None) or getattr(tool, "__name__", "tool")
    if not wanted(name, only, skip): return tool
    verified = tool_name(name) if tool_name else name
    original = tool.on_invoke_tool

    async def on_invoke_tool(ctx: Any, input_json: str) -> Any:
        r = check_or_refuse(guard, verified, parse_json_args(input_json), on_refused)
        if r is not None: return json.dumps(r)
        return await original(ctx, input_json)

    g = copy.copy(tool)
    try: object.__setattr__(g, "on_invoke_tool", on_invoke_tool)
    except (AttributeError, TypeError): g = _replace(tool, on_invoke_tool)
    return g


def _replace(tool: Any, fn: Any) -> Any:
    import dataclasses
    if dataclasses.is_dataclass(tool): return dataclasses.replace(tool, on_invoke_tool=fn)
    raise TypeError("tool does not expose a writable on_invoke_tool")


def guard_tools(guard: Any, tools: list, **kw: Any) -> list: return [guard_tool(guard, t, **kw) for t in tools]

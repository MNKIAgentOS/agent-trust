"""
CrewAI — `crewai.tools.BaseTool`. Real tools become a `GuardedTool` subclass whose `_run` verifies before
delegating; other objects with `run`/`_run` get a duck-typed proxy. No framework import unless a real tool is given.

    from mnki.adapters.crewai import guard_tools
    Agent(role="Refunds", tools=guard_tools(guard, [refund_tool]))
"""
from __future__ import annotations
import json
from typing import Any, Optional

from .shared import check_or_refuse, wanted


def _base_tool():
    try:
        from crewai.tools import BaseTool  # type: ignore
        return BaseTool
    except ImportError: return None


def _guarded_class(BaseTool: Any) -> Any:
    class GuardedTool(BaseTool):  # type: ignore[misc,valid-type]
        inner: Any = None
        guard: Any = None
        verified_name: str = ""
        on_refused: str = "result"

        def _run(self, *a: Any, **kw: Any) -> Any:
            r = check_or_refuse(self.guard, self.verified_name, kw or ({"input": a[0]} if len(a) == 1 else {"args": list(a)}), self.on_refused)
            if r is not None: return json.dumps(r)
            return self.inner._run(*a, **kw)

    GuardedTool.__name__ = "GuardedTool"
    return GuardedTool


class _Proxy:
    def __init__(self, guard: Any, inner: Any, verified: str, on_refused: str): self._g, self._i, self._n, self._o = guard, inner, verified, on_refused
    def __getattr__(self, k: str) -> Any: return getattr(self._i, k)
    def _run(self, *a: Any, **kw: Any) -> Any:
        r = check_or_refuse(self._g, self._n, kw or ({"input": a[0]} if len(a) == 1 else {"args": list(a)}), self._o); return json.dumps(r) if r is not None else self._i._run(*a, **kw)
    def run(self, *a: Any, **kw: Any) -> Any:
        r = check_or_refuse(self._g, self._n, kw or ({"input": a[0]} if len(a) == 1 else {"args": list(a)}), self._o); return json.dumps(r) if r is not None else self._i.run(*a, **kw)


def guard_tool(guard: Any, tool: Any, on_refused: str = "result", only: Optional[list] = None, skip: Optional[list] = None, tool_name=None) -> Any:
    name = getattr(tool, "name", None) or getattr(tool, "__name__", "tool")
    if not wanted(name, only, skip): return tool
    verified = tool_name(name) if tool_name else name
    BaseTool = _base_tool()
    if BaseTool is not None and isinstance(tool, BaseTool):
        fields = {"name": tool.name, "description": tool.description, "inner": tool, "guard": guard, "verified_name": verified, "on_refused": on_refused}
        if getattr(tool, "args_schema", None) is not None: fields["args_schema"] = tool.args_schema
        return _guarded_class(BaseTool)(**fields)
    return _Proxy(guard, tool, verified, on_refused)


def guard_tools(guard: Any, tools: list, **kw: Any) -> list: return [guard_tool(guard, t, **kw) for t in tools]

"""
LangChain / LangGraph (Python) — `langchain-core` tools. Real `BaseTool` instances become a `GuardedTool`
subclass (so `ToolNode`, `bind_tools` and isinstance checks keep working) that verifies in `_run`/`_arun` before
delegating to the original. Anything else with `invoke`/`run` gets a duck-typed proxy — no framework import.

    from mnki.adapters.langchain import guard_tools
    graph = create_react_agent(model, guard_tools(guard, [refund, lookup]))
"""
from __future__ import annotations
import json
from typing import Any, Optional

from .shared import check_or_refuse, wanted


def _base_tool():
    try:
        from langchain_core.tools import BaseTool  # type: ignore
        return BaseTool
    except ImportError: return None


def _guarded_class(BaseTool: Any) -> Any:
    class GuardedTool(BaseTool):  # type: ignore[misc,valid-type]
        inner: Any = None
        guard: Any = None
        verified_name: str = ""
        on_refused: str = "result"

        # LangChain passes `config` / `run_manager` when the signature declares them; the tool arguments are the rest.
        def _run(self, *a: Any, config: Any = None, run_manager: Any = None, **kw: Any) -> Any:
            args = kw or ({"input": a[0]} if len(a) == 1 else {"args": list(a)})
            r = check_or_refuse(self.guard, self.verified_name, args, self.on_refused)
            if r is not None: return json.dumps(r)
            return self.inner.invoke(args if kw else (a[0] if len(a) == 1 else list(a)), config)

        async def _arun(self, *a: Any, config: Any = None, run_manager: Any = None, **kw: Any) -> Any:
            args = kw or ({"input": a[0]} if len(a) == 1 else {"args": list(a)})
            r = check_or_refuse(self.guard, self.verified_name, args, self.on_refused)
            if r is not None: return json.dumps(r)
            return await self.inner.ainvoke(args if kw else (a[0] if len(a) == 1 else list(a)), config)

    GuardedTool.__name__ = "GuardedTool"
    return GuardedTool


class _Proxy:
    """Duck-typed guard for tool-like objects with invoke / ainvoke / run (used when langchain-core is absent)."""
    def __init__(self, guard: Any, inner: Any, verified: str, on_refused: str): self._g, self._i, self._n, self._o = guard, inner, verified, on_refused
    def __getattr__(self, k: str) -> Any: return getattr(self._i, k)
    def _args(self, inp: Any) -> Any: return inp.get("args", inp) if isinstance(inp, dict) and "name" in inp and "args" in inp else inp
    def invoke(self, inp: Any, config: Any = None, **kw: Any) -> Any:
        r = check_or_refuse(self._g, self._n, self._args(inp), self._o); return json.dumps(r) if r is not None else self._i.invoke(inp, config, **kw)
    async def ainvoke(self, inp: Any, config: Any = None, **kw: Any) -> Any:
        r = check_or_refuse(self._g, self._n, self._args(inp), self._o); return json.dumps(r) if r is not None else await self._i.ainvoke(inp, config, **kw)
    def run(self, inp: Any, **kw: Any) -> Any:
        r = check_or_refuse(self._g, self._n, self._args(inp), self._o); return json.dumps(r) if r is not None else self._i.run(inp, **kw)


def guard_tool(guard: Any, tool: Any, on_refused: str = "result", only: Optional[list] = None, skip: Optional[list] = None, tool_name=None) -> Any:
    name = getattr(tool, "name", None) or getattr(tool, "__name__", "tool")
    if not wanted(name, only, skip): return tool
    verified = tool_name(name) if tool_name else name
    BaseTool = _base_tool()
    if BaseTool is not None and isinstance(tool, BaseTool):
        fields = {"name": tool.name, "description": tool.description, "inner": tool, "guard": guard, "verified_name": verified, "on_refused": on_refused}
        for k in ("args_schema", "return_direct", "response_format", "metadata", "tags"):
            v = getattr(tool, k, None)
            if v is not None: fields[k] = v
        return _guarded_class(BaseTool)(**fields)
    return _Proxy(guard, tool, verified, on_refused)


def guard_tools(guard: Any, tools: list, **kw: Any) -> list: return [guard_tool(guard, t, **kw) for t in tools]

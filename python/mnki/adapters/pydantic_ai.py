"""
Pydantic AI — tools are plain functions registered with `@agent.tool` / `@agent.tool_plain`, or `Tool(...)`
objects. `guard_tool` wraps the function (sync or async, with or without a `RunContext` first argument) so the
guard runs before the body; a refusal returns the structured JSON result to the model.

    from mnki.adapters.pydantic_ai import guard_tool
    @agent.tool_plain
    @guard_tool(guard)
    def refund(customer_id: str, amount: float, currency: str = "EUR") -> str: ...
"""
from __future__ import annotations
import functools, inspect, json
from typing import Any, Callable, Optional

from .shared import check_or_refuse, wanted


def _is_run_context(v: Any) -> bool: return type(v).__name__ == "RunContext"


def guard_tool(guard: Any, name: Optional[str] = None, on_refused: str = "result", only: Optional[list] = None, skip: Optional[list] = None) -> Callable:
    def deco(fn: Callable) -> Callable:
        tool = name or fn.__name__
        if not wanted(tool, only, skip): return fn
        sig = inspect.signature(fn)

        def args_of(a: tuple, kw: dict) -> dict:
            params = list(sig.parameters); vals = list(a)
            if vals and _is_run_context(vals[0]): vals = vals[1:]; params = params[1:]
            out = dict(zip(params, vals)); out.update(kw); return out

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def aw(*a: Any, **kw: Any) -> Any:
                r = check_or_refuse(guard, tool, args_of(a, kw), on_refused); return json.dumps(r) if r is not None else await fn(*a, **kw)
            return aw

        @functools.wraps(fn)
        def w(*a: Any, **kw: Any) -> Any:
            r = check_or_refuse(guard, tool, args_of(a, kw), on_refused); return json.dumps(r) if r is not None else fn(*a, **kw)
        return w
    return deco


def guard_tools(guard: Any, fns: list, **kw: Any) -> list:
    """Wrap plain functions, or `Tool` objects (their `.function` is replaced)."""
    out = []
    for f in fns:
        if callable(f) and not hasattr(f, "function"): out.append(guard_tool(guard, **kw)(f)); continue
        fn = getattr(f, "function", None)
        if callable(fn):
            try: f.function = guard_tool(guard, name=getattr(f, "name", None), **kw)(fn)
            except (AttributeError, TypeError): pass
        out.append(f)
    return out

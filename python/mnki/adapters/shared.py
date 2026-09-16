"""Shared by every adapter: refusal handling and tool filtering."""
from __future__ import annotations
import inspect, json
from typing import Any, Callable, Optional

from ..errors import AgentTrustError
from ..guard import ApprovalRequired, Denied


def wanted(name: str, only: Optional[list] = None, skip: Optional[list] = None) -> bool:
    return name not in (skip or []) and (not only or name in only)


def refusal(e: BaseException) -> dict:
    """Turn a guard error into the structured result the model sees; anything else is re-raised."""
    if isinstance(e, Denied):
        return {"error": "denied", "message": str(e), "reasons": e.reasons, "evidence": [{k: x[k] for k in ("step", "status", "title", "detail") if k in x} for x in e.evidence if x.get("status") != "pass"], "decision_id": e.decision.get("decision_id")}
    if isinstance(e, ApprovalRequired):
        return {"error": e.code, "message": str(e), "reasons": e.reasons, "decision_id": e.decision_id, "approval_id": e.approval_id}
    if isinstance(e, AgentTrustError):
        return {"error": "verification_failed", "message": f"{e.code}: {e}", "reasons": [e.code]}
    raise e


def refusal_json(e: BaseException) -> str: return json.dumps(refusal(e))


def check_or_refuse(guard: Any, tool: str, args: Any, on_refused: str) -> Optional[dict]:
    """None when the call may proceed; the refusal dict otherwise (or raises when on_refused == "throw")."""
    try: guard.check(tool, args if isinstance(args, dict) else {"input": args}); return None
    except AgentTrustError as e:
        if on_refused == "throw": raise
        return refusal(e)


def parse_json_args(inp: Any) -> Any:
    if not isinstance(inp, str): return inp if inp is not None else {}
    try: return json.loads(inp)
    except ValueError: return {"input": inp}


def is_coroutine_fn(fn: Callable) -> bool: return inspect.iscoroutinefunction(fn)

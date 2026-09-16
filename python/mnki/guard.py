"""
guard() / wrap() for Python: verify a tool call before it runs, against the hosted control plane.
Modes: observe (log only), warn (run, surface evidence), require_approval (escalate only), enforce.

    from mnki import AgentTrustClient, Guard, Denied, ApprovalRequired
    g = Guard(AgentTrustClient("https://mnki.com", api_key="at_verify_…"), agent="invoice-agent")

    @g.wrap("refund.create")
    def refund(customer_id: str, amount: float, currency: str = "EUR"): ...

Local mode (no account): `Guard(world=demo_world(), agent="invoice-agent", action_prefix="")` runs the same
pipeline in-process (`mnki.pipeline`, validated against the conformance vectors).
"""
from __future__ import annotations
import asyncio, functools, hashlib, inspect, json, random, time
from typing import Any, Callable, Optional

from .errors import AgentTrustError
from .identity import AgentIdentity, b64url
from .local import local_verify

Mode = str  # "observe" | "warn" | "require_approval" | "enforce"


class Denied(AgentTrustError):
    """The action was verified and refused. `evidence` is the ✓/⚠/✕ list (fail and warn rows first)."""
    def __init__(self, decision: dict):
        reasons = [r for r in decision.get("reasons", []) if not r.endswith("_verified") and r != "authority_valid"]
        super().__init__(403, "denied", decision); self.decision = decision; self.reasons = decision.get("reasons", [])
        self.args = (f"denied: {', '.join(reasons) or 'policy'}",)
    @property
    def evidence(self) -> list:
        order = {"fail": 0, "warn": 1, "pass": 2, "skipped": 3}
        return sorted(self.decision.get("evidence", []), key=lambda e: order.get(e.get("status"), 9))


class ApprovalRequired(AgentTrustError):
    """A human must decide (or already decided against, or the wait ended)."""
    def __init__(self, approval_id: Optional[str], decision_id: str, status: str, reasons: Optional[list] = None):
        code = {"pending": "approval_required", "rejected": "approval_rejected", "expired": "approval_expired"}.get(status, "approval_timeout")
        super().__init__(202, code, {"approval_id": approval_id, "decision_id": decision_id}); self.approval_id, self.decision_id, self.status, self.reasons = approval_id, decision_id, status, reasons or []


def _default_map(_tool: str, args: dict) -> dict:
    out: dict = {}
    amount = args.get("amount", args.get("value"))
    if isinstance(amount, str) and amount.replace(".", "", 1).isdigit(): amount = float(amount)
    if isinstance(amount, (int, float)) and not isinstance(amount, bool): out["amount"] = amount
    cur = args.get("currency")
    if isinstance(cur, str) and len(cur) == 3 and cur.isupper(): out["currency"] = cur
    for k in ("resource", "customer_id", "customerId", "id"):
        if isinstance(args.get(k), str): out["resource"] = args[k]; break
    if isinstance(args.get("region"), str): out["context"] = {"region": args["region"]}
    return out


def _tags(d: dict) -> list:
    t: list = []; r = d.get("reasons", [])
    if d.get("decision") == "DENY": t.append("would_deny")
    if d.get("decision") == "REQUIRE_APPROVAL": t.append("approval_required")
    if "agent_unknown" in r or any(x.startswith("credential_") for x in r): t.append("missing_identity")
    if "no_delegation" in r or any(x.startswith("delegation_") for x in r): t.append("missing_delegation")
    if any(x in r for x in ("capability_missing", "constraint_violated", "budget_exceeded")): t.append("excess_capability")
    if any(x.startswith("policy:") and not x.endswith(":allow") for x in r): t.append("policy_mismatch")
    return t


class Guard:
    def __init__(self, client: Any = None, agent: str = "", identity: Optional[AgentIdentity] = None, mode: Mode = "enforce", action_prefix: str = "tool:", map_args: Optional[Callable[[str, dict], dict]] = None, on_approval: str = "wait", approval_timeout: float = 300.0, initial_delay: float = 1.0, max_delay: float = 15.0, on_decision: Optional[Callable[[dict], None]] = None, sleep: Callable[[float], None] = time.sleep, world: Optional[dict] = None, now: Optional[Callable[[], Any]] = None):
        if mode not in ("observe", "warn", "require_approval", "enforce"): raise ValueError("mode must be observe | warn | require_approval | enforce")
        if client is None and world is None: raise ValueError("guard needs either `client` (hosted) or `world` (local)")
        if not agent: raise ValueError("agent is required")
        self.client, self.agent, self.identity, self.mode, self.prefix, self.world, self._now = client, agent, identity, mode, action_prefix, world, now
        self.map_args, self.on_approval, self.timeout, self.initial_delay, self.max_delay, self.on_decision, self._sleep = map_args or _default_map, on_approval, approval_timeout, initial_delay, max_delay, on_decision, sleep

    def _input(self, tool: str, args: dict) -> dict:
        mapped = self.map_args(tool, args or {})
        ctx = dict(mapped.pop("context", {}) or {}); ctx.update({"tool": tool, "arguments_hash": b64url(hashlib.sha256(json.dumps(args or {}, sort_keys=True, separators=(",", ":")).encode()).digest())})
        return {"agent": self.agent, "action": f"{self.prefix}{tool}", **mapped, "context": ctx}

    def wait_for_approval(self, approval_id: str) -> str:
        deadline = time.time() + self.timeout; delay = self.initial_delay
        while True:
            s = self.client.approval_status(approval_id); st = s.get("status")
            if st in ("approved", "rejected", "expired"): return st
            if time.time() >= deadline: return "timeout"
            self._sleep(min(max(0.0, deadline - time.time()), delay + random.random() * 0.25)); delay = min(self.max_delay, delay * 2)

    def check(self, tool: str, args: Optional[dict] = None) -> dict:
        """Verify one tool call. Returns the decision when the call may proceed; raises Denied / ApprovalRequired otherwise (mode permitting)."""
        if self.client is not None: d = self.client.verify(self._input(tool, args or {}), identity=self.identity)
        else:
            r = local_verify(self.world, self._input(tool, args or {}), self._now() if self._now else None)
            if not r["ok"]: raise AgentTrustError(400, r["code"])
            d = dict(r["result"]); d.update({"request_id": "local", "decision_id": f"local_{int(time.time() * 1000):x}", "approval_id": "local_pending" if d["decision"] == "REQUIRE_APPROVAL" else None, "latency_ms": 0})
        enforced = self.mode == "enforce" or (self.mode == "require_approval" and d.get("decision") == "REQUIRE_APPROVAL")
        record = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "mode": self.mode, "tool": tool, "decision": d.get("decision"), "enforced": enforced, "reasons": d.get("reasons", []), "evidence": d.get("evidence", []), "decision_id": d.get("decision_id"), "approval_id": d.get("approval_id"), "tags": _tags(d)}
        if self.on_decision: self.on_decision(record)
        result = {"allowed": d.get("decision") == "ALLOW", "decision": d.get("decision"), "reasons": d.get("reasons", []), "evidence": d.get("evidence", []), "decision_id": d.get("decision_id"), "approval_id": d.get("approval_id"), "enforced": enforced}
        if d.get("decision") == "ALLOW" or not enforced: result["allowed"] = True; return result
        if d.get("decision") == "DENY": raise Denied(d)
        if self.client is None or self.on_approval == "throw" or not d.get("approval_id"): raise ApprovalRequired(d.get("approval_id"), d.get("decision_id", ""), "pending", d.get("reasons"))
        status = self.wait_for_approval(d["approval_id"])
        if status != "approved": raise ApprovalRequired(d["approval_id"], d.get("decision_id", ""), status, d.get("reasons"))
        try: result["attestation"] = self.client.issue_attestation(d["decision_id"]).get("token")
        except AgentTrustError: pass
        result["allowed"] = True; return result

    def wrap(self, tool: Optional[str] = None):
        """Decorator: the function runs only after `check` resolves. Keyword arguments (or a single dict) are the tool arguments."""
        def deco(fn: Callable):
            name = tool or fn.__name__
            if inspect.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def aw(*a, **kw):
                    await asyncio.get_running_loop().run_in_executor(None, self.check, name, _args(a, kw)); return await fn(*a, **kw)
                return aw
            @functools.wraps(fn)
            def w(*a, **kw):
                self.check(name, _args(a, kw)); return fn(*a, **kw)
            return w
        return deco


def _args(a: tuple, kw: dict) -> dict:
    if kw: return dict(kw)
    if len(a) == 1 and isinstance(a[0], dict): return a[0]
    return {"args": list(a)} if a else {}


def wrap(client: Any, agent: str, tool: Optional[str] = None, **guard_kw):
    """`@mnki.wrap(client, "invoice-agent", "refund.create")` — a one-line guard for a single tool."""
    return Guard(client, agent, **guard_kw).wrap(tool)

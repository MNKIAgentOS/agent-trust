"""
Local mode: run the exact verifier the control plane runs, in-process, against a JSON "world" — the same shape
as the conformance vectors (`conformance/vectors/*.json` → `world`) and the TypeScript `LocalWorld`. No account,
no network. `demo_world()` is the 15-second story: an invoice agent may refund up to €5,000; €47,000 is denied,
€420 allowed, €3,200 needs a human.
"""
from __future__ import annotations
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .pipeline import parse_verify_request, verify


class WorldDeps:
    """VerifierDeps over a world dict (pure, synchronous data)."""
    def __init__(self, w: dict):
        self.w = w; self._revoked = set(w.get("revoked") or []); self._dels = w.get("delegations") or []
    def get_agent(self, ref: str) -> Optional[dict]:
        a = self.w.get("agent")
        return a if a and (ref == a.get("id") or ref == a.get("stable_id") or ref in (self.w.get("agentAliases") or self.w.get("agent_aliases") or [])) else None
    def get_active_credential(self, agent_id: str) -> Optional[dict]: return self.w.get("credential")
    def get_principal(self, pid: str) -> Optional[dict]: return next((p for p in self.w.get("principals") or [] if p.get("id") == pid), None)
    def get_leaf_delegation(self, agent_id: str, delegation_id: Optional[str] = None) -> Optional[dict]:
        d = next((d for d in self._dels if (d.get("id") == delegation_id if delegation_id else (d.get("subject_agent_id") == agent_id and d.get("parent_id") is not None))), None)
        return d or next((d for d in self._dels if d.get("subject_agent_id") == agent_id), None)
    def get_delegation_ancestry(self, leaf_id: str) -> list: return self._dels
    def get_agent_capabilities(self, agent_id: str) -> list: return self.w.get("capabilities") or []
    def is_revoked(self, subject_type: str, subject_id: str) -> bool: return subject_id in self._revoked
    def get_attestations(self, agent_id: str) -> list: return self.w.get("attestations") or []
    def get_policy(self) -> Optional[dict]: return self.w.get("policy")
    def get_org_key(self, kid: str, iss: str) -> Optional[dict]: return ((self.w.get("keys") or {}).get(iss) or {}).get(kid)
    def get_federated_issuer(self, iss: str) -> Optional[dict]:
        p = next((p for p in self.w.get("peers") or [] if p.get("entity_id") == iss), None)
        return {"name": p["name"], "trust_level": p["trust_level"]} if p else None
    def __getattr__(self, name: str) -> Any:
        if name == "spent_so_far" and self.w.get("spent") is not None:
            return lambda scope: (self.w.get("spent") or {}).get(f"{scope.get('delegation_id') or scope.get('agent_id')}|{scope.get('action')}|{scope.get('currency')}", 0)
        raise AttributeError(name)


def deps_from_world(world: dict) -> WorldDeps: return WorldDeps(world)


def load_world(source: Any) -> dict:
    """A world from a dict, a JSON string, or a file path (a conformance vector file is unwrapped to its `world`)."""
    if isinstance(source, dict): w = source
    elif isinstance(source, str) and source.lstrip().startswith("{"): w = json.loads(source)
    else:
        with open(source, encoding="utf-8") as f: w = json.load(f)
    return w.get("world", w) if "world" in w and "agent" not in w else w


def local_verify(world: dict, req: Any, now: Optional[datetime] = None) -> dict:
    """Verify a request against a world exactly as the hosted endpoint would (minus the ledger)."""
    parsed = parse_verify_request(req)
    if not parsed["ok"]: return {"ok": False, "code": f"invalid_{parsed['code']}"}
    return {"ok": True, "result": verify(parsed["request"], deps_from_world(world), now or datetime.now(timezone.utc))}


def demo_world(now: Optional[datetime] = None) -> dict:
    """Accounts Receivable delegates `refund.create` up to €5,000 to invoice-agent; refunds above €3,000 need approval."""
    now = now or datetime.now(timezone.utc); y = (now + timedelta(days=365)).isoformat().replace("+00:00", "Z")
    return {
        "agent": {"id": "agt_invoice", "stable_id": "spiffe://acme.example/agent/invoice-agent", "lifecycle": "active", "risk_tier": "medium", "owner_principal_id": "prn_ar", "labels": {"department": "Finance", "framework": "openai-agents"}},
        "agentAliases": ["invoice-agent"],
        "credential": {"id": "crd_invoice", "kind": "jwt_svid", "status": "active", "not_after": y, "issuer": "internal-ca.acme.example"},
        "principals": [{"id": "prn_ar", "display_name": "Accounts Receivable", "kind": "team"}],
        "delegations": [{"id": "dlg_ar_invoice", "parent_id": None, "subject_agent_id": "agt_invoice", "status": "active", "not_after": y, "capabilities": [
            {"action": "refund.create", "resource": "customer:*", "constraints": {"max_value": 5000, "currency": "EUR"}},
            {"action": "invoice.read", "resource": "invoice:*"}, {"action": "crm.read", "resource": "crm:*"}]}],
        "capabilities": [], "revoked": [], "attestations": [],
        "policy": {"version_id": "pv_demo", "hash": "demo", "doc": {"version": 1, "rules": [
            {"id": "large-refunds-need-a-human", "description": "Refunds above €3,000 require approval", "match": {"action": "refund.create"}, "conditions": [{"kind": "amount_gt", "value": 3000}], "effect": "require_approval"},
            {"id": "no-database-writes", "description": "Agents never write to the database directly", "match": {"action": "database.write"}, "effect": "deny"}]}},
    }

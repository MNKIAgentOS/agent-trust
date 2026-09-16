"""Policy evaluation — a port of packages/verifier/src/policy/evaluate.ts. Deterministic: same doc + input + clock ⇒ same outcome."""
from __future__ import annotations
from datetime import datetime
from typing import Any, Optional

from .offline import resource_contains

_RANK = {"allow": 0, "require_approval": 1, "deny": 2}
_EFFECTS = ("allow", "deny", "require_approval")


def _action_matches(pattern: Any, action: str) -> bool:
    if pattern is None: return True
    for p in (pattern if isinstance(pattern, list) else [pattern]):
        if (p.endswith("*") and action.startswith(p[:-1])) or p == action: return True
    return False


def _hm(s: str) -> int:
    h, _, m = s.partition(":")
    return (int(h or 0)) * 60 + int(m or 0)


def condition_holds(c: dict, i: dict) -> bool:
    k = c.get("kind"); amount, currency, region = i.get("amount"), i.get("currency"), i.get("region")
    atts: list = i.get("attestations", []); depth = i.get("delegation_depth", 0)
    if k == "amount_lte": return amount is not None and amount <= c["value"]
    if k == "amount_gt": return amount is not None and amount > c["value"]
    if k == "currency_in": return currency is not None and currency in c["values"]
    if k == "region_in": return region is not None and region in c["values"]
    if k == "requires_attestation": return (c["attestation"] in atts) if c.get("attestation") else len(atts) > 0
    if k == "missing_attestation": return (c["attestation"] not in atts) if c.get("attestation") else len(atts) == 0
    if k == "delegation_depth_lte": return depth <= c["value"]
    if k == "delegation_depth_gt": return depth > c["value"]
    if k == "time_window":
        t: datetime = i["time"]; mins = t.hour * 60 + t.minute; a, b = _hm(c["start"]), _hm(c["end"])
        return (a <= mins < b) if a <= b else (mins >= a or mins < b)
    return False


def rule_matches(r: dict, i: dict) -> bool:
    m = r.get("match")
    if not m: return True
    if not _action_matches(m.get("action"), i["action"]): return False
    if m.get("resource") is not None and (i.get("resource") is None or not resource_contains(m["resource"], i["resource"])): return False
    if m.get("risk_tier") and i.get("risk_tier") not in m["risk_tier"]: return False
    if m.get("agent_labels") and any(i.get("agent_labels", {}).get(k) != v for k, v in m["agent_labels"].items()): return False
    return True


def evaluate(doc: dict, i: dict) -> dict:
    fired: list = []; reasons: list = []; effect: Optional[str] = None
    for r in doc.get("rules", []):
        if not rule_matches(r, i): continue
        if not all(condition_holds(c, i) for c in (r.get("conditions") or [])): continue
        fired.append(r["id"]); reasons.append(f"policy:{r['id']}:{r['effect']}")
        if effect is None or _RANK[r["effect"]] > _RANK[effect]: effect = r["effect"]
    if effect is None:
        effect = doc.get("default") or "allow"; reasons.append(f"policy:default:{effect}")
    return {"effect": effect, "fired": fired, "reasons": reasons}


def simulate(doc: dict, inputs: list) -> list: return [evaluate(doc, i) for i in inputs]


def parse_policy_doc(inp: Any) -> dict:
    """Runtime check for untrusted policy JSON. Never raises: {"ok": True, "doc"} or {"ok": False, "error"}."""
    if not isinstance(inp, dict): return {"ok": False, "error": "not_object"}
    if inp.get("version") != 1: return {"ok": False, "error": "version"}
    if not isinstance(inp.get("rules"), list): return {"ok": False, "error": "rules"}
    if inp.get("default") is not None and inp["default"] not in _EFFECTS: return {"ok": False, "error": "default"}
    for n, r in enumerate(inp["rules"]):
        if not isinstance(r, dict): return {"ok": False, "error": f"rules[{n}]"}
        if not isinstance(r.get("id"), str) or not r["id"]: return {"ok": False, "error": f"rules[{n}].id"}
        if r.get("effect") not in _EFFECTS: return {"ok": False, "error": f"rules[{n}].effect"}
        if r.get("conditions") is not None and not isinstance(r["conditions"], list): return {"ok": False, "error": f"rules[{n}].conditions"}
    return {"ok": True, "doc": inp}

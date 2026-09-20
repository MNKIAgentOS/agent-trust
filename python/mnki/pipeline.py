"""
The verification pipeline in Python — a line-for-line port of packages/verifier/src/pipeline.ts (spec §8,
steps 3–13). Pure: no I/O beyond `deps`, no clock beyond `now`. Every step appends one evidence row; the
decision is derived from the evidence, never from a score. Validated against conformance/vectors.

`deps` is any object with the VerifierDeps methods (see `mnki.local.deps_from_world`); optional methods
may be absent. Dates are ISO-8601 strings, `now` a timezone-aware datetime.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from .offline import attenuate, capability_covered, constraints_tighter, decode_jwt, resource_contains, verify_attestation, verify_request_proof
from .policy import evaluate

MAX_CHAIN_DEPTH = 8


def _ms(iso: Optional[str]) -> Optional[float]:
    if not iso: return None
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000


def parse_verify_request(o: Any) -> dict:
    """Validate an untrusted verify request; never raises. {"ok": True, "request"} | {"ok": False, "code"}."""
    ne = lambda v: isinstance(v, str) and v.strip() != "" and len(v) <= 512
    opt = lambda v: v is None or ne(v)
    if not isinstance(o, dict): return {"ok": False, "code": "not_object"}
    if not ne(o.get("agent")): return {"ok": False, "code": "agent"}
    if not ne(o.get("action")): return {"ok": False, "code": "action"}
    for k in ("resource", "principal", "delegation_id"):
        if not opt(o.get(k)): return {"ok": False, "code": k}
    a = o.get("amount")
    if a is not None and (isinstance(a, bool) or not isinstance(a, (int, float)) or a != a or a < 0): return {"ok": False, "code": "amount"}
    c = o.get("currency")
    if c is not None and not (isinstance(c, str) and len(c) == 3 and c.isalpha() and c.isupper()): return {"ok": False, "code": "currency"}
    att = o.get("attestation")
    if att is not None and not (isinstance(att, str) and att.count(".") == 2 and len(att) <= 16384): return {"ok": False, "code": "attestation"}
    if o.get("context") is not None and not isinstance(o["context"], dict): return {"ok": False, "code": "context"}
    req = {"agent": o["agent"].strip(), "action": o["action"].strip()}
    for k in ("resource", "principal", "delegation_id"):
        if o.get(k) is not None: req[k] = o[k].strip()
    for k in ("amount", "currency", "context", "attestation"):
        if o.get(k) is not None: req[k] = o[k]
    return {"ok": True, "request": req}


def resolve_chain(leaf_id: str, get: Callable[[str], Optional[dict]], max_depth: int = MAX_CHAIN_DEPTH) -> dict:
    seen: set = set(); chain: list = []; cursor: Optional[str] = leaf_id
    while cursor is not None:
        if cursor in seen: return {"ok": False, "reason": "cycle", "at": cursor}
        if len(chain) >= max_depth: return {"ok": False, "reason": "depth", "at": cursor}
        d = get(cursor)
        if not d: return {"ok": False, "reason": "missing", "at": cursor}
        seen.add(cursor); chain.append(d); cursor = d.get("parent_id")
    chain.reverse(); return {"ok": True, "chain": chain}


def link_valid_at(d: dict, t: float) -> bool:
    if d.get("status") != "active": return False
    nb, na = _ms(d.get("not_before")), _ms(d.get("not_after"))
    if nb is not None and t < nb: return False
    if na is not None and t >= na: return False
    return True


def compute_effective_authority(chain: list, t: float) -> list:
    if not chain or not all(link_valid_at(d, t) for d in chain): return []
    eff = chain[0].get("capabilities", [])
    for d in chain[1:]: eff = attenuate(eff, d.get("capabilities", []))
    return eff


def _has(deps: Any, name: str) -> bool: return callable(getattr(deps, name, None))


def verify(req: dict, deps: Any, now: datetime, request: Optional[dict] = None, require_proof: bool = False, request_hash: Optional[str] = None, audience: Optional[str] = None) -> dict:
    """`request` binds a proof: {"proof", "htm", "htu", "body_hash", "credential"?}.

    `request_hash` (profile v0.2 §9.2) is the canonical hash of the request being executed; a single-use
    attestation whose `atp.request_hash` differs is refused."""
    if now.tzinfo is None: now = now.replace(tzinfo=timezone.utc)
    ev: list = []; reasons: list = []; state = {"hard_fail": False}
    t = now.timestamp() * 1000

    def fail(step: str, title: str, reason: str, detail: Optional[str] = None, refs: Optional[list] = None) -> None:
        row = {"step": step, "status": "fail", "title": title}
        if detail: row["detail"] = detail
        if refs: row["refs"] = refs
        ev.append(row); reasons.append(reason); state["hard_fail"] = True

    def push(step: str, status: str, title: str, detail: Optional[str] = None, refs: Optional[list] = None) -> None:
        row = {"step": step, "status": status, "title": title}
        if detail: row["detail"] = detail
        if refs: row["refs"] = refs
        ev.append(row)

    cred = principal = leaf = pol = None; effective: list = []; chain_ids: list = []
    delegation_valid = authorized = revoked = False; remaining: Optional[float] = None
    proof_state = {"present": bool(request and request.get("proof")), "verified": False, "kid": None, "alg": None}
    att_state = {"present": bool(req.get("attestation")), "valid": False, "jti": None, "expires_in": None, "use": None, "consumed": False}
    att_exp = att_iat = 0; att_approval: Optional[dict] = None; peer_stale_ok = 0
    federation = None; fed_caps = None; fed_chain: list = []; fed_principal = None; fed_approved = False
    amount, currency, resource, action = req.get("amount"), req.get("currency"), req.get("resource"), req["action"]
    region = (req.get("context") or {}).get("region"); region = region if isinstance(region, str) else None

    def finish(decision: str) -> dict:
        seen: set = set(); uniq = [r for r in reasons if not (r in seen or seen.add(r))]
        return {"decision": decision, "reasons": uniq, "evidence": ev,
                "agent": ({"id": agent["id"], "verified": agent.get("lifecycle") == "active"} if agent else None),
                "principal": ({"id": principal["id"], "verified": True} if principal else None),
                "delegation": {"valid": delegation_valid, "chain_length": len(chain_ids), "chain": chain_ids},
                "authorization": {"capability": action, "valid": authorized, "remaining_limit": remaining if authorized else None},
                "revocation": {"checked": True, "valid": not revoked},
                "policy_version": pol.get("version_id") if pol else None, "policy_hash": pol.get("hash") if pol else None,
                "proof": proof_state, "attestation": att_state, "federation": federation}

    def _aud_ok(aud: Any) -> bool:
        """§17: a relying party that declares its audience accepts only permits that name it."""
        if not audience: return True
        return audience in aud if isinstance(aud, list) else aud == audience

    def _aud_text(aud: Any) -> str: return (",".join(aud) if isinstance(aud, list) else aud) or "(none)"

    def _bound_elsewhere(atp: dict) -> bool:
        """§9.2: a single-use permit is bound to the request it was approved for."""
        return atp.get("use") == "single" and bool(request_hash) and bool(atp.get("request_hash")) and atp["request_hash"] != request_hash

    def _approval_of(atp: dict) -> Optional[dict]:
        """A human approval the attestation carries, and whether it covers this very request."""
        ha = atp.get("human_approval") or {}
        if not ha.get("approved"): return None
        return {"approval_id": ha.get("approval_id"), "bound": not request_hash or not atp.get("request_hash") or atp["request_hash"] == request_hash}

    detail = action + (f" on {resource}" if resource else "") + (f" · {amount} {currency or ''}".rstrip() if amount is not None else "")
    push("request", "pass", "Request parsed", detail)

    # 3. agent identity — local registry, or a federated agent attested by a trusted peer organization
    agent = deps.get_agent(req["agent"])
    if not agent and req.get("attestation") and _has(deps, "get_federated_issuer") and _has(deps, "get_org_key"):
        dec = decode_jwt(req["attestation"]); iss = dec[1].get("iss") if dec else None
        peer = deps.get_federated_issuer(iss) if isinstance(iss, str) else None
        if peer and peer.get("trust_level", 0) >= 2:
            a = verify_attestation(req["attestation"], lambda kid, i: deps.get_org_key(kid, i), now)
            if not a["ok"]: fail("identity", "Federated attestation invalid", f"attestation_invalid:{a['reason']}", f"issuer {iss}: {a['reason']}"); return finish("DENY")
            p = a["payload"]; atp = p["atp"]
            if p.get("sub") != req["agent"]: fail("identity", "Federated attestation names a different agent", "attestation_invalid:subject", f"sub {p.get('sub')}"); return finish("DENY")
            if not _aud_ok(p.get("aud")): fail("identity", "Federated attestation is for a different audience", "attestation_invalid:audience", f"aud {_aud_text(p.get('aud'))}; expected {audience}"); return finish("DENY")
            if atp.get("action") != action or (atp.get("resource") and resource and not resource_contains(atp["resource"], resource)):
                fail("identity", "Federated attestation does not cover this action", "attestation_invalid:action", f"attested {atp.get('action')}" + (f" on {atp['resource']}" if atp.get("resource") else "")); return finish("DENY")
            if _bound_elsewhere(atp):
                fail("identity", "Federated attestation is bound to a different request", "attestation_invalid:request_hash", f"single-use attestation {p.get('jti')} was issued for another request", [p.get("jti")]); return finish("DENY")
            agent = {"id": p["sub"], "stable_id": p["sub"], "lifecycle": "active", "risk_tier": "medium", "owner_principal_id": None, "labels": {"federated_org": iss}}
            federation = {"issuer": iss, "name": peer["name"], "trust_level": peer["trust_level"]}; fed_caps = atp.get("capabilities", []); fed_chain = atp.get("delegation_chain") or []; fed_principal = atp.get("principal"); fed_approved = bool((atp.get("human_approval") or {}).get("approved"))
            att_state.update({"valid": True, "jti": p.get("jti"), "expires_in": a.get("expires_in"), "use": atp.get("use") or "multi"})
            att_exp = p.get("exp") or 0; att_iat = p.get("iat") or 0; att_approval = _approval_of(atp); peer_stale_ok = peer.get("stale_ok_seconds") or 0
            reasons += ["identity_federated", "attestation_valid"]
            push("identity", "pass", f"Federated agent — attested by {peer['name']} (trust level {peer['trust_level']})", p["sub"], [p.get("jti")])
        elif peer:
            fail("identity", "Peer organization is trusted at level 1 only", "federation_level_insufficient", f"{peer['name']} may not act here; raise it to trust level 2"); return finish("DENY")
    if not agent:
        fail("identity", "Agent unknown", "agent_unknown", f'No agent matches "{req["agent"]}"'); return finish("DENY")
    if federation: pass
    elif agent.get("lifecycle") != "active": fail("identity", f"Agent is {agent.get('lifecycle')}", f"agent_{agent.get('lifecycle')}", None, [agent["id"]])
    else: push("identity", "pass", "Agent identity resolved", agent.get("stable_id"), [agent["id"]])

    if federation:
        push("credential", "pass", f"Issuer attestation stands in for a local credential ({federation['name']})")
        if request and request.get("proof"): push("proof", "skipped", "Request proof not checked for federated agents", "The agent's key lives in the peer registry.")
        elif require_proof: fail("proof", "Unsigned request", "request_unsigned", "This organization requires signed requests")
        if fed_principal: push("principal", "pass", f"Principal {fed_principal} asserted by {federation['name']}", "Not resolved locally")
        else: push("principal", "warn", "No principal in the federated attestation"); reasons.append("principal_unbound")
        effective = fed_caps or []; chain_ids = list(fed_chain); delegation_valid = len(fed_chain) > 0
        n = len(fed_chain)
        push("delegation", "pass" if n else "warn", f"Delegation chain attested by issuer ({n} link{'s' if n > 1 else ''})" if n else "No delegation chain in the attestation — issuer-asserted capabilities", None, fed_chain or None)
        reasons.append("delegation_attested" if n else "no_delegation")
        if fed_approved: reasons.append("human_approved_by_issuer")
    else:
        # 4. credential — a presented issuer token verified against the trust anchors, else the registered credential
        cred = deps.get_active_credential(agent["id"])
        presented = (request or {}).get("credential")
        if presented and _has(deps, "verify_presented_credential"):
            v = deps.verify_presented_credential(presented)
            if not v.get("ok"): fail("credential", "Presented credential invalid", f"credential_presented_invalid:{v.get('reason')}", (f"issuer {v['issuer']}: {v.get('reason')}" if v.get("issuer") else v.get("reason")), [agent["id"]])
            elif v.get("sub") not in (agent.get("stable_id"), agent["id"]): fail("credential", "Presented credential names a different agent", "credential_presented_invalid:subject", f"sub {v.get('sub')}", [agent["id"]])
            else:
                if not cred: cred = {"id": f"presented:{v['kind']}", "kind": v["kind"], "status": "active", "not_after": (datetime.fromtimestamp(v["exp"], tz=timezone.utc).isoformat().replace("+00:00", "Z") if v.get("exp") else None), "issuer": v.get("issuer")}
                kind = "JWT-SVID" if v["kind"] == "jwt_svid" else "Issuer token"
                push("credential", "pass", f"{kind} verified against {v.get('issuer')}", (f"kid {v['kid']}" + (f" · valid until {datetime.fromtimestamp(v['exp'], tz=timezone.utc).isoformat()[:19]}Z" if v.get("exp") else "")) if v.get("kid") else None, [agent["id"]])
                reasons.append("credential_presented_verified")
        elif not cred: fail("credential", "No active credential", "credential_missing", None, [agent["id"]])
        elif cred.get("not_after") and (_ms(cred["not_after"]) or 0) <= t: fail("credential", "Credential expired", "credential_expired", f"expired {cred['not_after']}", [cred["id"]])
        elif _has(deps, "is_trusted_issuer") and not deps.is_trusted_issuer(cred.get("issuer")): fail("credential", "Credential issuer not trusted", "credential_issuer_untrusted", (f"issuer {cred['issuer']} is not a configured trust domain" if cred.get("issuer") else "credential has no issuer"), [cred["id"]])
        else: push("credential", "pass", f"Credential fresh ({cred.get('kind')})", f"valid until {cred['not_after'][:10]}" if cred.get("not_after") else None, [cred["id"]])

        # 4b. request proof-of-possession
        if request and request.get("proof"):
            def resolve(kid: Optional[str]) -> Optional[dict]:
                if not _has(deps, "get_credential_key"): return None
                k = deps.get_credential_key(agent["id"], kid); return k["jwk"] if k else None
            out = verify_request_proof(request["proof"], resolve, request["htm"], request["htu"], request["body_hash"], now, seen_jti=(deps.seen_jti if _has(deps, "seen_jti") else None))
            kid_refs = [out["kid"]] if out.get("kid") else None
            if not out["ok"]: fail("proof", "Request signature invalid", f"proof_invalid:{out['reason']}", out["reason"], kid_refs)
            elif out["claims"].get("iss") not in (agent["id"], agent.get("stable_id")): fail("proof", "Request signed by a different agent", "proof_invalid:issuer", f"iss {out['claims'].get('iss')}", kid_refs)
            else:
                proof_state.update({"verified": True, "kid": out.get("kid"), "alg": out.get("alg")}); reasons.append("request_signed")
                push("proof", "pass", f"Request signature verified ({out.get('alg')})", f"kid {out['kid']}" if out.get("kid") else None, kid_refs)
        elif require_proof: fail("proof", "Unsigned request", "request_unsigned", "This organization requires signed requests")
        else: push("proof", "warn", "Request not signed", "No Agent-Proof header — possession of the agent key was not proven."); reasons.append("request_unsigned")

        # 4c. presented Agent Authorization Attestation
        if req.get("attestation"):
            if not _has(deps, "get_org_key"): fail("attestation_token", "Attestation cannot be verified", "attestation_invalid:no_resolver")
            else:
                a = verify_attestation(req["attestation"], lambda kid, i: deps.get_org_key(kid, i), now)
                if not a["ok"]: fail("attestation_token", "Authorization attestation invalid", f"attestation_invalid:{a['reason']}", a["reason"])
                else:
                    p = a["payload"]; atp = p["atp"]
                    if p.get("sub") not in (agent["id"], agent.get("stable_id")): fail("attestation_token", "Attestation issued to a different agent", "attestation_invalid:subject", f"sub {p.get('sub')}")
                    elif not _aud_ok(p.get("aud")): fail("attestation_token", "Attestation is for a different audience", "attestation_invalid:audience", f"aud {_aud_text(p.get('aud'))}; expected {audience}", [p.get("jti")])
                    elif atp.get("action") != action: fail("attestation_token", "Attestation covers a different action", "attestation_invalid:action", f"attested {atp.get('action')}")
                    elif atp.get("resource") and resource and not resource_contains(atp["resource"], resource): fail("attestation_token", "Attestation does not cover this resource", "attestation_invalid:resource", f"attested {atp['resource']}")
                    elif _bound_elsewhere(atp): fail("attestation_token", "Attestation bound to a different request", "attestation_invalid:request_hash", f"single-use attestation {p.get('jti')} was issued for another request", [p.get("jti")])
                    elif _has(deps, "is_attestation_revoked") and deps.is_attestation_revoked(p.get("jti")): fail("attestation_token", "Attestation revoked", "attestation_invalid:revoked", None, [p.get("jti")])
                    else:
                        att_state.update({"valid": True, "jti": p.get("jti"), "expires_in": a.get("expires_in"), "use": atp.get("use") or "multi"})
                        att_exp = p.get("exp") or 0; att_iat = p.get("iat") or 0; att_approval = _approval_of(atp)
                        reasons.append("attestation_valid")
                        push("attestation_token", "pass", f"Authorization attestation valid (expires in {a.get('expires_in')}s)", f"issued by {p.get('iss')} for {atp.get('action')}", [p.get("jti")])

        # 5. principal
        principal = deps.get_principal(agent["owner_principal_id"]) if agent.get("owner_principal_id") else None
        if principal: push("principal", "pass", f"Principal binding active ({principal.get('display_name')})", None, [principal["id"]])
        else: push("principal", "warn", "No delegating principal", "Authority is not bound to a human or service owner."); reasons.append("principal_unbound")

        # 6–8. delegation chain → effective authority
        # §17: without an explicit delegation id, prefer the delegation that covers this action.
        leaf = None
        if not req.get("delegation_id") and _has(deps, "get_covering_delegation"): leaf = deps.get_covering_delegation(agent["id"], action, resource)
        if not leaf: leaf = deps.get_leaf_delegation(agent["id"], req.get("delegation_id"))
        if leaf:
            anc = deps.get_delegation_ancestry(leaf["id"]); by_id = {d["id"]: d for d in anc}
            chain = resolve_chain(leaf["id"], by_id.get)
            if not chain["ok"]: fail("delegation", f"Delegation chain {chain['reason']}", f"delegation_chain_{chain['reason']}", f"at {chain['at']}", [leaf["id"]])
            else:
                links = chain["chain"]; chain_ids = [d["id"] for d in links]; effective = compute_effective_authority(links, t)
                bad = next((d for d in links if d.get("status") != "active" or ((_ms(d.get("not_after")) or float("inf")) <= t) or ((_ms(d.get("not_before")) or float("-inf")) > t)), None)
                if bad:
                    label = "expired" if bad.get("status") == "active" else bad.get("status")
                    fail("delegation", f"Delegation {'outside validity window' if bad.get('status') == 'active' else bad.get('status')}", f"delegation_{label}", None, [bad["id"]])
                else:
                    delegation_valid = True; push("delegation", "pass", f"Delegation chain valid ({len(links)} link{'s' if len(links) > 1 else ''})", None, chain_ids)
        else:
            effective = deps.get_agent_capabilities(agent["id"])
            push("delegation", "warn", "No delegation — using directly assigned capabilities", None, [agent["id"]]); reasons.append("no_delegation")

    # 9. capability + constraints
    requested = {"action": action, "resource": resource if resource is not None else "*"}
    covering = [c for c in effective if c.get("action") == action and (resource is None or capability_covered({**c, "constraints": None}, requested))]
    if not covering: fail("capability", f"Capability {action} not granted", "capability_missing", f"for {resource}" if resource else None)
    else:
        rc: dict = {}
        if amount is not None: rc["max_value"] = amount
        if currency: rc["currency"] = currency
        if region: rc["region"] = [region]
        within = next((c for c in covering if constraints_tighter(c.get("constraints"), {**(c.get("constraints") or {}), **rc})), None)
        fmt = lambda v: "|".join(v) if isinstance(v, list) else str(v)
        if not within:
            lim = covering[0].get("constraints")
            fail("constraints", "Request exceeds capability constraints", "constraint_violated", ", ".join(f"{k}={fmt(v)}" for k, v in lim.items()) if lim else None)
        else:
            cons = within.get("constraints") or {}; max_total = cons.get("max_total")
            if isinstance(max_total, (int, float)) and not isinstance(max_total, bool) and amount is not None and _has(deps, "spent_so_far"):
                spent = deps.spent_so_far({"delegation_id": leaf["id"] if leaf else None, "agent_id": agent["id"], "action": action, "currency": currency}); left = max_total - spent
                if amount > left: fail("constraints", "Budget exhausted", "budget_exceeded", f"{spent} of {max_total} {currency or ''} already spent; {left} left".strip())
                else:
                    authorized = True; remaining = left - amount
                    push("capability", "pass", f"Capability {action} granted", within.get("resource")); push("constraints", "pass", "Constraints satisfied", f"budget {spent + amount} of {max_total} {currency or ''} used".strip())
            else:
                authorized = True
                if isinstance(cons.get("max_value"), (int, float)) and amount is not None: remaining = cons["max_value"] - amount
                push("capability", "pass", f"Capability {action} granted", within.get("resource"))
                push("constraints", "pass", "Constraints satisfied", " · ".join(f"{k} {fmt(v)}" for k, v in cons.items()) if cons else "none")

    # 10. revocation — every link of the chain is consulted
    if federation and _has(deps, "peer_attestation_status"):
        # §12.1: ask the issuing peer about this jti; unreachable refuses unless the peer's stale window still covers it.
        jti = att_state.get("jti"); st = deps.peer_attestation_status(federation["issuer"], jti)
        if st == "active": push("revocation", "pass", f"Peer revocation checked with {federation['name']} — none found", None, [jti])
        elif st == "revoked": revoked = True; fail("revocation", f"Attestation revoked by {federation['name']}", "revoked", None, [jti])
        else:
            age = max(0, int(now.timestamp()) - att_iat)
            if peer_stale_ok > 0 and age <= peer_stale_ok:
                push("revocation", "warn", f"{federation['name']} unreachable — attestation accepted inside the stale window", f"issued {age}s ago; stale window {peer_stale_ok}s", [jti]); reasons.append("revocation_remote_unreachable")
            else:
                revoked = True; fail("revocation", f"{federation['name']} unreachable — revocation status unknown", "revocation_remote_unreachable", f"issued {age}s ago; stale window {peer_stale_ok}s", [jti])
    elif federation:
        push("revocation", "warn", "Peer revocation not consulted", f"Attestation is short-lived (expires in {att_state.get('expires_in') if att_state.get('expires_in') is not None else '?'}s); {federation['name']}'s revocation list is not queried in v0.1."); reasons.append("revocation_remote_unchecked")
    else:
        revoked_ref = None
        if deps.is_revoked("agent", agent["id"]): revoked_ref = agent["id"]
        elif cred and deps.is_revoked("credential", cred["id"]): revoked_ref = cred["id"]
        else:
            for did in (chain_ids or ([leaf["id"]] if leaf else [])):
                if deps.is_revoked("delegation", did): revoked_ref = did; break
        revoked = revoked_ref is not None
        if revoked: fail("revocation", "Agent is revoked" if revoked_ref == agent["id"] else ("Credential is revoked" if cred and revoked_ref == cred["id"] else "A delegation in the chain is revoked"), "revoked", None, [revoked_ref])
        else: push("revocation", "pass", "Revocation checked — none found")

    # 11. attestation (evidence only in v0.1)
    atts = [a for a in deps.get_attestations(agent["id"]) if a.get("verified") and (not a.get("expires_at") or (_ms(a["expires_at"]) or 0) > t)]
    if atts: push("attestation", "pass", f"Runtime attested ({', '.join(a['kind'] for a in atts)})", None, [a["id"] for a in atts])
    else: push("attestation", "skipped", "No runtime attestation", "Not required by policy.")

    # 11b. effect path (§15): the caller declares how the effect is enforced; the evidence shows it on every decision.
    _effect_path = (req.get("context") or {}).get("effect_path")
    if _effect_path == "custody": push("enforcement", "pass", "Effect path: the enforcement point holds the effect credential", "the agent never holds it, so the effector is reachable only through a decision")
    elif _effect_path == "attested": push("enforcement", "pass", "Effect path: the effector verifies the attestation", "the effector executes only with an attestation bound to this request")
    else: push("enforcement", "warn", "A direct path to the effector may exist", f"effect path {_effect_path if _effect_path == 'none' else 'undeclared'}; this decision relies on deployment isolation")

    # 12. policy
    pol = deps.get_policy(); effect = "allow"
    if pol:
        out = evaluate(pol["doc"], {"action": action, "resource": resource, "amount": amount, "currency": currency, "region": region, "risk_tier": agent.get("risk_tier"), "agent_labels": agent.get("labels") or {}, "delegation_depth": len(chain_ids), "attestations": [a["kind"] for a in atts], "time": now})
        effect = out["effect"]; reasons.extend(out["reasons"])
        if effect == "require_approval" and att_state["valid"] and att_approval and att_approval["bound"] and att_state.get("jti"):
            # §9.2: the presented attestation carries the approval this policy asks for, for this very request.
            effect = "allow"; reasons.append("human_approved_by_attestation")
            d = f"approval {att_approval['approval_id'] or '?'} carried by {att_state['jti']}"
            if out["fired"]: d = f"fired: {', '.join(out['fired'])}; " + d
            push("policy", "pass", "Policy's approval requirement is met by a human-approved attestation", d, ([pol["version_id"]] if pol.get("version_id") else []) + [att_state["jti"]])
        else:
            status = "pass" if effect == "allow" else ("fail" if effect == "deny" else "warn")
            title = "Policy allows" if effect == "allow" else ("Policy denies" if effect == "deny" else "Policy requires human approval")
            push("policy", status, title, f"fired: {', '.join(out['fired'])}" if out["fired"] else "no rule fired", [pol["version_id"]] if pol.get("version_id") else None)
        if effect == "deny": state["hard_fail"] = True
    else: push("policy", "skipped", "No active policy")

    # 13. decide
    decision = "DENY" if state["hard_fail"] else ("REQUIRE_APPROVAL" if effect == "require_approval" else "ALLOW")

    # 14. single-use attestation (§9.2): spent only when the effect is about to be allowed, and atomically.
    if decision == "ALLOW" and att_state["valid"] and att_state.get("use") == "single" and att_state.get("jti"):
        jti = att_state["jti"]
        if not _has(deps, "consume_attestation"):
            fail("single_use", "Single-use attestation cannot be consumed here", "attestation_invalid:no_consume_store", f"No consumption store: single-use attestation {jti} is refused where its use cannot be recorded", [jti]); decision = "DENY"
        elif deps.consume_attestation(jti, att_exp) == "seen":
            fail("single_use", "Attestation already used", "attestation_invalid:consumed", f"Single-use attestation {jti} was consumed by an earlier request", [jti]); decision = "DENY"
        else:
            att_state["consumed"] = True; reasons.append("attestation_consumed")
            push("single_use", "pass", "Single-use attestation consumed", f"{jti} cannot be presented again", [jti])

    if decision == "ALLOW": reasons[0:0] = ["identity_verified", "authority_valid"]
    return finish(decision)

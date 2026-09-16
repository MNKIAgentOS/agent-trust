"""
mnki — the Agent Trust SDK for Python.

    from mnki import AgentTrustClient, AgentIdentity
    c = AgentTrustClient("https://staging.mnki.com", api_key="at_verify_…")
    d = c.verify({"agent": "procurement-7821", "action": "purchase.create", "amount": 2450, "currency": "EUR"})
    d["decision"]  # "ALLOW" | "DENY" | "REQUIRE_APPROVAL"; d["evidence"] is the ✓/⚠/✕ list

Signing (Agent-Proof, DPoP-style) needs `pip install cryptography`:
    ident = AgentIdentity.create(agent_id)            # ES256 key pair; register ident.public_jwk via c.rotate(...)
    c.verify(req, identity=ident)                     # adds the Agent-Proof header
"""
from __future__ import annotations
import base64, hashlib, json, os, time, urllib.request, urllib.error
from typing import Any, Callable, Optional
from .identity import AgentIdentity
from .errors import AgentTrustError

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def body_hash(body: bytes | str) -> str:
    return b64url(hashlib.sha256(body.encode() if isinstance(body, str) else body).digest())

class AgentTrustClient:
    def __init__(self, base_url: str, api_key: str, opener: Optional[Callable[[urllib.request.Request], Any]] = None, timeout: float = 15.0):
        self.base = base_url.rstrip("/"); self.key = api_key; self._open = opener or (lambda req: urllib.request.urlopen(req, timeout=timeout))

    def _call(self, method: str, path: str, body: Any = None, headers: Optional[dict] = None, raw: Optional[str] = None) -> Any:
        data = raw.encode() if raw is not None else (None if body is None else json.dumps(body).encode())
        req = urllib.request.Request(f"{self.base}/api{path}", data=data, method=method)
        req.add_header("authorization", f"Bearer {self.key}")
        if data is not None: req.add_header("content-type", "application/json")
        for k, v in (headers or {}).items(): req.add_header(k, v)
        try:
            with self._open(req) as r: return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try: j = json.loads(e.read() or b"{}")
            except Exception: j = {}
            raise AgentTrustError(e.code, j.get("error", f"http_{e.code}"), j.get("detail", j)) from None

    # --- decisions ---
    def verify(self, request: dict, identity: Optional[AgentIdentity] = None, credential: Optional[str] = None) -> dict:
        body = json.dumps(request); headers = {}
        if identity: headers["agent-proof"] = identity.sign_proof("POST", f"{self.base}/api/v1/verify", body)
        if credential: headers["agent-credential"] = credential
        return self._call("POST", "/v1/verify", headers=headers, raw=body)
    def approval_status(self, approval_id: str) -> dict: return self._call("GET", f"/v1/approvals/{approval_id}/status")
    def decision(self, decision_id: str) -> dict: return self._call("GET", f"/v1/decisions/{decision_id}")
    def authzen(self, subject_id: str, action: str, resource: Optional[dict] = None, context: Optional[dict] = None, properties: Optional[dict] = None) -> dict:
        return self._call("POST", "/access/v1/evaluation", {"subject": {"type": "agent", "id": subject_id}, "action": {"name": action, "properties": properties or {}}, "resource": resource or {}, "context": context or {}})
    # --- agents ---
    def register(self, **agent: Any) -> dict: return self._call("POST", "/v1/agents", agent)
    def agent(self, agent_id: str) -> dict: return self._call("GET", f"/v1/agents/{agent_id}")
    def rotate(self, agent_id: str, public_jwk: dict, kid: str, kind: str = "jwt_svid", issuer: Optional[str] = None) -> dict:
        return self._call("POST", f"/v1/agents/{agent_id}/rotate", {"kind": kind, "kid": kid, "publicKeyJwk": public_jwk, "issuer": issuer})
    def enrol(self, **agent: Any) -> tuple[dict, AgentIdentity]:
        r = self.register(**agent); ident = AgentIdentity.create(r["id"]); self.rotate(r["id"], ident.public_jwk, ident.kid, issuer=agent.get("issuer")); return r, ident
    def attest(self, agent_id: str, kind: str, claims: dict, proof: Optional[dict] = None, expires_at: Optional[str] = None) -> dict:
        return self._call("POST", f"/v1/agents/{agent_id}/attestations", {"kind": kind, "claims": claims, "proof": proof, "expires_at": expires_at})
    def agent_card(self, agent_id: str) -> dict: return self._call("GET", f"/v1/agents/{agent_id}/agent-card")
    # --- authority ---
    def delegate(self, issuer: dict, subject_agent_id: str, capabilities: list, parent_id: Optional[str] = None, task: Optional[str] = None, not_after: Optional[str] = None) -> dict:
        return self._call("POST", "/v1/delegations", {"issuer": issuer, "subjectAgentId": subject_agent_id, "capabilities": capabilities, "parentId": parent_id, "task": task, "notAfter": not_after})
    def credential_chain(self, delegation_id: str) -> dict: return self._call("GET", f"/v1/delegations/{delegation_id}/credential")
    def issue_attestation(self, decision_id: str, ttl_seconds: Optional[int] = None, audience: Optional[str] = None) -> dict:
        return self._call("POST", "/v1/attestations", {"decision_id": decision_id, "ttl_seconds": ttl_seconds, "audience": audience})
    def revoke_attestation(self, attestation_id: str, reason: str) -> dict: return self._call("DELETE", f"/v1/attestations/{attestation_id}", {"reason": reason})
    def status(self, subject: str) -> dict: return self._call("GET", f"/v1/status/{subject}")
    def jwks(self, org_id: str) -> dict:
        with self._open(urllib.request.Request(f"{self.base}/api/v1/orgs/{org_id}/jwks")) as r: return json.loads(r.read())

Client = AgentTrustClient

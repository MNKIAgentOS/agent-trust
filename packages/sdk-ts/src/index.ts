/**
 * Agent Trust SDK (TypeScript). Wraps the /v1 API and the pure verifier so an
 * agent can: create an identity (key pair), register it, sign every request
 * (Agent-Proof), ask for a decision, obtain an authorization attestation, and
 * verify delegation credentials or attestations offline against an org JWKS.
 *
 * Runs anywhere WebCrypto + fetch exist (Node ≥ 20, Workers, browsers).
 */
import { generateAgentKey, signRequestProof, verifyDelegationChain, verifyAttestation, type ProofAlg, type CapSet, type KeyResolver, type CredentialChainResult, type AttestationResult } from "mnki-verifier";
export { generateAgentKey, signRequestProof, verifyDelegationChain, verifyAttestation, decodeJwt, bodyHash } from "mnki-verifier";
export type { ProofAlg, CapSet } from "mnki-verifier";

export interface ClientOptions { baseUrl: string; apiKey: string; fetch?: typeof fetch }
/** One evidence row. `title`/`detail` are the normative English text; `code`/`params` (servers ≥ 0.2) are the same row in machine-readable form for rendering in any language. */
export interface Evidence { step: string; status: "pass" | "warn" | "fail" | "skipped"; title: string; detail?: string; refs?: string[]; code?: string; params?: Record<string, string | number | boolean | null> }
export interface Decision { decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL"; reasons: string[]; evidence: Evidence[]; request_id: string; decision_id: string; approval_id: string | null; latency_ms: number; proof: { present: boolean; verified: boolean; kid: string | null; alg: string | null }; attestation: { present: boolean; valid: boolean; jti: string | null; expires_in: number | null }; agent: { id: string; verified: boolean } | null; principal: { id: string; verified: boolean } | null; delegation: { valid: boolean; chain_length: number; chain: string[] }; authorization: { capability: string; valid: boolean }; revocation: { checked: true; valid: boolean }; policy_version: string | null; policy_hash: string | null }
export interface ApprovalStatus { id: string; decision_id: string; status: "pending" | "approved" | "rejected" | "expired"; expires_at: string | null; resolved_at: string | null }
export interface VerifyInput { agent: string; action: string; resource?: string; principal?: string; delegation_id?: string; amount?: number; currency?: string; context?: Record<string, unknown>; attestation?: string }
export interface RegisterAgentInput { name: string; description?: string; stableId?: string; ownerPrincipalId?: string; issuer?: string; riskTier?: "low" | "medium" | "high" | "critical"; runtimeKind?: "mcp" | "a2a" | "custom"; runtimeRef?: string; labels?: Record<string, string>; capabilities?: CapSet }
export interface DelegateInput { issuer: { type: "principal" | "agent"; id: string }; subjectAgentId: string; parentId?: string | null; task?: string; capabilities: CapSet; constraints?: Record<string, unknown>; notAfter?: string | null }

export class AgentTrustError extends Error { constructor(public status: number, public code: string, public detail?: unknown) { super(`${code} (${status})`); } }

/** A local agent identity: the private key never leaves the process; the public JWK is registered as the credential. */
export class AgentIdentity {
  constructor(public readonly agentId: string, public readonly kid: string, public readonly alg: ProofAlg, private readonly privateKey: CryptoKey, public readonly publicJwk: JsonWebKey) {}
  static async create(agentId: string, alg: ProofAlg = "ES256", kid = `kid-${Date.now().toString(36)}`): Promise<AgentIdentity> {
    const k = await generateAgentKey(alg); return new AgentIdentity(agentId, kid, alg, k.privateKey, k.publicJwk);
  }
  /** Serialise for local storage (contains the PRIVATE key — protect the file). */
  async export(): Promise<ExportedIdentity> {
    return { v: 1, agentId: this.agentId, kid: this.kid, alg: this.alg, publicJwk: this.publicJwk, privateJwk: await crypto.subtle.exportKey("jwk", this.privateKey) };
  }
  static async import(e: ExportedIdentity): Promise<AgentIdentity> {
    const params = e.alg === "ES256" ? ({ name: "ECDSA", namedCurve: "P-256" } as EcKeyImportParams) : ({ name: "Ed25519" } as Algorithm);
    const priv = await crypto.subtle.importKey("jwk", e.privateJwk, params, true, ["sign"]);
    return new AgentIdentity(e.agentId, e.kid, e.alg, priv, e.publicJwk);
  }
  /** The Agent-Proof header value for one request. */
  signProof(method: string, url: string, body: string, opts: { ttlSeconds?: number } = {}): Promise<string> {
    return signRequestProof({ privateKey: this.privateKey, alg: this.alg, kid: this.kid, iss: this.agentId, htm: method, htu: url, body, ttlSeconds: opts.ttlSeconds });
  }
}
export interface ExportedIdentity { v: 1; agentId: string; kid: string; alg: ProofAlg; publicJwk: JsonWebKey; privateJwk: JsonWebKey }


// ---- access broker (profile §17) ----
export interface GrantInput { agent: string; connection: string; operation: string; params?: Record<string, string | number | boolean>; approval_id?: string; attestation?: string; delegation_id?: string }
export interface GrantDecision { decision_id: string; request_id: string; decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL"; reasons: string[]; evidence: unknown[]; approval_id: string | null }
export interface GrantRecord { id: string; connection_id: string; agent_id: string; operation: string; action: string; resource: string; status: "issued" | "executed" | "failed" | "expired" | "revoked"; kind: "custody" | "permit" | "native_token"; decision_id: string; approval_id: string | null; attestation_id: string; issued_at: string; expires_at: string; executed_at: string | null; upstream_status: number | null; upstream_request_id: string | null; response_hash: string | null; latency_ms: number | null; error: string | null }
export interface GrantResult { ok: boolean; status: number; request_id: string | null; content_type: string | null; body: unknown; error?: string }
export type GrantExecution = { status: "executed"; grant: GrantRecord; decision: GrantDecision; result: GrantResult } | { status: "approval_required"; decision: GrantDecision; approval_id: string; poll_url: string; resume: GrantInput };
export interface ConnectionRecord { id: string; provider: string; name: string; auth_kind: string; status: string; allowed_operations: string[]; restrictions: Record<string, unknown>; has_credential: boolean; account_label: string | null; last_used_at: string | null; created_at: string }

export class AgentTrustClient {
  private readonly base: string; private readonly key: string; private readonly f: typeof fetch;
  constructor(o: ClientOptions) { this.base = o.baseUrl.replace(/\/+$/, ""); this.key = o.apiKey; this.f = o.fetch ?? fetch; }
  private async call<T>(method: string, path: string, body?: unknown, extra: Record<string, string> = {}): Promise<T> {
    const url = `${this.base}/api${path}`; const text = body === undefined ? undefined : JSON.stringify(body);
    const res = await this.f(url, { method, headers: { authorization: `Bearer ${this.key}`, ...(text !== undefined ? { "content-type": "application/json" } : {}), ...extra }, body: text });
    const j = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) throw new AgentTrustError(res.status, typeof j.error === "string" ? j.error : `http_${res.status}`, j.detail ?? j);
    return j as T;
  }
  readonly agents = {
    list: (q: { q?: string; lifecycle?: string; limit?: number; cursor?: string } = {}) => { const p = new URLSearchParams(); for (const [k, v] of Object.entries(q)) if (v !== undefined) p.set(k, String(v)); return this.call<{ items: Record<string, unknown>[]; nextCursor: string | null }>("GET", `/v1/agents${p.toString() ? `?${p}` : ""}`); },
    register: (input: RegisterAgentInput) => this.call<{ ok: true; id: string; stableId: string }>("POST", "/v1/agents", input),
    get: (id: string) => this.call<Record<string, unknown> & { id: string; stableId: string; name: string; lifecycle: string; chain: { ids: string[]; valid: boolean; effective: CapSet } | null }>("GET", `/v1/agents/${encodeURIComponent(id)}`),
    rotate: (id: string, input: { kind?: string; issuer?: string; kid?: string; publicKeyJwk?: JsonWebKey; notAfter?: string }) => this.call<{ ok: true; credentialId: string; previousId: string | null }>("POST", `/v1/agents/${encodeURIComponent(id)}/rotate`, input),
    attest: (id: string, input: { kind: "runtime" | "build" | "tee" | "self"; claims: Record<string, unknown>; expiresAt?: string; proof?: { format: "jwt_svid" | "jwt"; token: string } }) => this.call<{ ok: true; id: string; verified: boolean; issuer: string | null; reason?: string }>("POST", `/v1/agents/${encodeURIComponent(id)}/attestations`, { kind: input.kind, claims: input.claims, expires_at: input.expiresAt, proof: input.proof }),
    agentCard: (id: string) => this.call<Record<string, unknown>>("GET", `/v1/agents/${encodeURIComponent(id)}/agent-card`),
    /** Register an agent and bind a freshly generated key: returns the identity to keep locally. */
    enrol: async (input: RegisterAgentInput, alg: ProofAlg = "ES256") => {
      const r = await this.agents.register(input); const id = await AgentIdentity.create(r.id, alg);
      await this.agents.rotate(r.id, { kind: "jwt_svid", kid: id.kid, publicKeyJwk: id.publicJwk, issuer: input.issuer });
      return { agentId: r.id, stableId: r.stableId, identity: id };
    },
  };
  /** Minimal approval state, readable with a verify-scoped key (`decision(id)` needs read scope). */
  readonly approvals = { status: (id: string) => this.call<ApprovalStatus>("GET", `/v1/approvals/${encodeURIComponent(id)}/status`) };
  /** Poll until the approval leaves `pending`: jittered exponential backoff, bounded by `timeoutMs` (default 5 minutes). */
  async waitForApproval(id: string, o: { timeoutMs?: number; initialDelayMs?: number; maxDelayMs?: number; sleep?: (ms: number) => Promise<void> } = {}): Promise<"approved" | "rejected" | "expired" | "timeout"> {
    const deadline = Date.now() + (o.timeoutMs ?? 300_000); let delay = o.initialDelayMs ?? 1_000; const sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    for (;;) {
      const s = await this.approvals.status(id);
      if (s.status === "approved" || s.status === "rejected" || s.status === "expired") return s.status;
      if (s.expires_at && Date.parse(s.expires_at) < Date.now()) return "expired";
      if (Date.now() >= deadline) return "timeout";
      await sleep(Math.min(Math.max(0, deadline - Date.now()), delay + Math.floor(Math.random() * 250))); delay = Math.min(o.maxDelayMs ?? 15_000, delay * 2);
    }
  }
  /** Ask for a decision. With an identity the request is signed (Agent-Proof). */
  async verify(input: VerifyInput, opts: { identity?: AgentIdentity; /** An issuer-signed identity token (SPIRE JWT-SVID / IdP JWT) presented as Agent-Credential. */ credential?: string } = {}): Promise<Decision> {
    const url = `${this.base}/api/v1/verify`; const text = JSON.stringify(input);
    const headers: Record<string, string> = { authorization: `Bearer ${this.key}`, "content-type": "application/json" };
    if (opts.identity) headers["agent-proof"] = await opts.identity.signProof("POST", url, text);
    if (opts.credential) headers["agent-credential"] = opts.credential;
    const res = await this.f(url, { method: "POST", headers, body: text });
    const j = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) throw new AgentTrustError(res.status, typeof j.error === "string" ? j.error : `http_${res.status}`, j.detail ?? j);
    return j as unknown as Decision;
  }
  readonly delegations = {
    issue: (input: DelegateInput) => this.call<{ ok: true; id: string; effective: CapSet; depth: number }>("POST", "/v1/delegations", input),
    credential: (id: string) => this.call<{ delegation_id: string; chain: string[]; credentials: string[]; jwks_url: string }>("GET", `/v1/delegations/${encodeURIComponent(id)}/credential`),
  };
  readonly attestations = {
    issue: (decisionId: string, opts: { ttlSeconds?: number; audience?: string; /** §9.2: "single" consumes the permit on first use. */ use?: "single" | "multi" } = {}) => this.call<{ ok: true; id: string; token: string; expires_at: string; expires_in: number; use?: string }>("POST", "/v1/attestations", { decision_id: decisionId, ttl_seconds: opts.ttlSeconds, audience: opts.audience, use: opts.use }),
    revoke: (id: string, reason: string) => this.call<{ ok: true }>("DELETE", `/v1/attestations/${encodeURIComponent(id)}`, { reason }),
  };
  /** Access broker (profile §17): run one operation on a connection with a credential the agent never holds. */
  readonly grants = {
    /** Verify, grant once, execute. 200 → { grant, decision, result }; 202 → ApprovalRequired-shaped body (approval_id, poll_url, resume); errors throw AgentTrustError (403 denied carries reasons + access_request_hint). */
    execute: async (input: GrantInput, opts: { identity?: AgentIdentity } = {}): Promise<GrantExecution> => {
      const url = `${this.base}/api/v1/grants/execute`; const text = JSON.stringify(input);
      const headers: Record<string, string> = { authorization: `Bearer ${this.key}`, "content-type": "application/json" };
      if (opts.identity) headers["agent-proof"] = await opts.identity.signProof("POST", url, text);
      const res = await this.f(url, { method: "POST", headers, body: text });
      const j = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      if (res.status === 202) return { status: "approval_required", ...(j as { decision: GrantDecision; approval_id: string; poll_url: string; resume: GrantInput }) };
      if (!res.ok) throw new AgentTrustError(res.status, typeof j.error === "string" ? j.error : `http_${res.status}`, j);
      return { status: "executed", ...(j as { grant: GrantRecord; decision: GrantDecision; result: GrantResult }) };
    },
    /** Mint only: a single-use permit bound to the connection to present later (or, for AWS STS, the short-lived credential itself). */
    mint: (input: GrantInput) => this.call<{ grant: GrantRecord; decision: GrantDecision; permit?: { token: string; expires_at: string; expires_in: number; audience: string }; result?: GrantResult }>("POST", "/v1/grants", input),
    list: (q: { connection?: string; agent?: string; status?: string; limit?: number } = {}) => { const p = new URLSearchParams(); for (const [k, v] of Object.entries(q)) if (v !== undefined) p.set(k, String(v)); return this.call<{ items: GrantRecord[] }>("GET", `/v1/grants${p.size ? `?${p}` : ""}`); },
    get: (id: string) => this.call<GrantRecord>("GET", `/v1/grants/${encodeURIComponent(id)}`),
    /** Execute, waiting for a human approval when one is required (same backoff as `waitForApproval`). */
    run: async (input: GrantInput, opts: { identity?: AgentIdentity; approval?: { timeoutMs?: number; initialDelayMs?: number; maxDelayMs?: number } } = {}): Promise<Extract<GrantExecution, { status: "executed" }>> => {
      const first = await this.grants.execute(input, opts);
      if (first.status === "executed") return first;
      const status = await this.waitForApproval(first.approval_id, opts.approval);
      if (status !== "approved") throw new AgentTrustError(202, `approval_${status}`, { approval_id: first.approval_id, decision_id: first.decision.decision_id });
      const second = await this.grants.execute({ ...input, approval_id: first.approval_id }, opts);
      if (second.status !== "executed") throw new AgentTrustError(202, "approval_required", { approval_id: second.approval_id });
      return second;
    },
  };
  readonly connections = {
    list: () => this.call<{ items: ConnectionRecord[]; ready: boolean; disabled: boolean }>("GET", "/v1/connections"),
    get: (id: string) => this.call<ConnectionRecord>("GET", `/v1/connections/${encodeURIComponent(id)}`),
    operations: (id: string) => this.call<{ items: { id: string; title: string; description: string; method: string; risk: string; params: unknown; enabled: boolean; returns_credential: boolean }[] }>("GET", `/v1/connections/${encodeURIComponent(id)}/operations`),
  };
  readonly accessRequests = {
    /** Ask a person for a capability the agent lacks; poll `status` until approved, then request grants normally. */
    create: (input: { agent: string; connection: string; operations: string[]; duration_seconds?: number; constraints?: Record<string, unknown>; reason: string }) => this.call<{ id: string; status: "pending"; expires_at: string; poll_url: string }>("POST", "/v1/access-requests", input),
    status: (id: string) => this.call<{ id: string; status: "pending" | "approved" | "denied" | "expired" | "cancelled"; delegation_id: string | null; granted_not_after: string | null; review_reason: string | null }>("GET", `/v1/access-requests/${encodeURIComponent(id)}`),
    withdraw: (id: string) => this.call<{ cancelled: true }>("DELETE", `/v1/access-requests/${encodeURIComponent(id)}`),
  };
  decision = (id: string) => this.call<{ id: string; decision: string; approval: { id: string; status: string } | null }>("GET", `/v1/decisions/${encodeURIComponent(id)}`);
  status = (subject: string) => this.call<{ subject_id: string; revoked: boolean; reason: string | null }>("GET", `/v1/status/${encodeURIComponent(subject)}`);
  /** Public JWKS for an organization (no auth). */
  jwks = async (orgId: string): Promise<{ keys: JsonWebKey[] }> => { const r = await this.f(`${this.base}/api/v1/orgs/${encodeURIComponent(orgId)}/jwks`); return (await r.json()) as { keys: JsonWebKey[] }; };
  /** Key resolver for offline verification: fetches (and caches) the issuer org's JWKS. */
  keyResolver(): KeyResolver { const cache = new Map<string, JsonWebKey[]>(); return async (kid, iss) => { let keys = cache.get(iss); if (!keys) { keys = (await this.jwks(iss)).keys; cache.set(iss, keys); } return keys.find((k) => (k as JsonWebKey & { kid?: string }).kid === kid) ?? null; }; }
  verifyCredentialChain = (tokens: string[], now = new Date()): Promise<CredentialChainResult> => verifyDelegationChain(tokens, this.keyResolver(), now);
  verifyAttestationToken = (token: string, now = new Date()): Promise<AttestationResult> => verifyAttestation(token, this.keyResolver(), now);
}

// Guard, local mode, explainability and the error taxonomy live in their own modules; re-exported for convenience.
export { createGuard, Guard, type GuardMode, type GuardOptions, type GuardResult, type GuardRecord } from "./guard";
export { localVerify, depsFromWorld, demoWorld, type LocalWorld } from "./local";
export { explain, type Explanation } from "./explain";
export { MnkiError, Denied, ApprovalRequired, fromApi, type MnkiErrorCode } from "./errors";

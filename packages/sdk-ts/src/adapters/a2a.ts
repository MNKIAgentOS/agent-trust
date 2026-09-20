/**
 * A2A — agent-to-agent. MCP connects agents to tools; A2A connects agents to agents; mnki establishes identity,
 * authority and verifiable action trust across both. Two halves:
 *
 *  - client side: `signTaskRequest(identity, …)` signs the outgoing task (Agent-Proof, DPoP-style) and attaches
 *    the authorization attestation the caller's organisation issued for this action (`Agent-Attestation`);
 *  - server side: `verifyBeforeAccept(guard, task)` resolves the caller's Agent Card, verifies the presented
 *    attestation offline against the caller organisation's JWKS, checks the caller's public standing when a
 *    passport is advertised, then runs the receiving agent's own guard for `a2a:<skill>` — and returns the
 *    trust metadata without any private evidence, so the server can decide and explain.
 *
 * Type-only: no A2A SDK is imported; the card shape below is the subset of the A2A Agent Card the adapter reads.
 */
import { verifyAttestation, decodeJwt, type AttestationJwt } from "mnki-verifier";
import type { AgentIdentity } from "../index";
import { ApprovalRequired, Denied, MnkiError } from "../errors";
import type { GuardLike } from "./shared";
import type { GuardResult } from "../guard";

export const AGENT_TRUST_EXTENSION = "https://mnki.com/agent-trust/profile/v0.1";

export interface AgentTrustCardParams { agent_id?: string; stable_id?: string; public_id?: string; lifecycle?: string; risk_tier?: string; state?: string; principal?: { id: string; name: string } | null; organization?: string; organization_name?: string; jwks_url?: string; verify_url?: string; status_url?: string; /** v0.2 §12.1: base of the caller organisation's public attestation status endpoint. */ attestation_status_url?: string; passport_url?: string; badge_url?: string; attestations_url?: string; delegation_credential_url?: string | null; authority?: { valid: boolean; chain_length: number } }
export interface AgentCard { name?: string; url?: string | null; provider?: { organization?: string; url?: string }; capabilities?: { extensions?: { uri: string; params?: AgentTrustCardParams }[] }; skills?: { id: string; name?: string }[] }

/** The Agent Trust extension of a card, or null when the card does not carry it. */
export function readAgentCard(card: AgentCard): AgentTrustCardParams | null {
  const ext = card.capabilities?.extensions?.find((e) => e.uri === AGENT_TRUST_EXTENSION); return ext?.params ?? null;
}

// ---- client side ------------------------------------------------------------------------------------------------
export interface SignedTaskRequest { method: string; url: string; body: string; headers: Record<string, string> }
/** Sign an outgoing A2A request (JSON-RPC `message/send`, `tasks/*` …): Agent-Proof over method, URL and body, plus the attestation when one was issued for this action. */
export async function signTaskRequest(identity: AgentIdentity, o: { url: string; body: unknown; method?: string; attestation?: string | null; cardUrl?: string | null; ttlSeconds?: number }): Promise<SignedTaskRequest> {
  const method = (o.method ?? "POST").toUpperCase(); const body = typeof o.body === "string" ? o.body : JSON.stringify(o.body);
  const headers: Record<string, string> = { "content-type": "application/json", "agent-proof": await identity.signProof(method, o.url, body, { ttlSeconds: o.ttlSeconds }), "agent-id": identity.agentId };
  if (o.attestation) headers["agent-attestation"] = o.attestation;
  if (o.cardUrl) headers["agent-card"] = o.cardUrl;
  return { method, url: o.url, body, headers };
}
/** `signTaskRequest` then `fetch`. */
export async function sendTask(identity: AgentIdentity, o: Parameters<typeof signTaskRequest>[1] & { fetch?: typeof fetch }): Promise<Response> {
  const r = await signTaskRequest(identity, o); return (o.fetch ?? fetch)(r.url, { method: r.method, headers: r.headers, body: r.body });
}

// ---- server side ------------------------------------------------------------------------------------------------
export interface IncomingTask { /** The skill the caller invokes (A2A skill id); verified as action `<actionPrefix><skill>` by the receiving guard (configure the guard with `actionPrefix: "a2a:"`). */ skill: string; params?: unknown; headers: Headers | Record<string, string>; /** The caller's Agent Card (object) or its URL; defaults to the `Agent-Card` header. */ callerCard?: AgentCard | string | null }
export interface TrustMetadata {
  caller: { agent_id: string | null; stable_id: string | null; organization: string | null; public_id: string | null; card_url: string | null };
  proof: { present: boolean; note: string };
  /** §12.1: what the caller organisation's status endpoint said about the attestation. */
  revocation?: { checked: boolean; status?: "active" | "revoked" | "unreachable"; note?: string };
  attestation: { present: boolean; valid: boolean; reason?: string; jti?: string; action?: string; resource?: string | null; principal?: string | null; organization?: string; human_approved?: boolean; expires_in?: number; delegation_chain_length?: number; /** §9.2: "single" or "multi". */ use?: "single" | "multi"; /** true when this acceptance consumed a single-use attestation. */ consumed?: boolean };
  standing: { checked: boolean; state?: string; lifecycle?: string; organization_verified?: boolean; note?: string };
}
export type VerifyBeforeAcceptResult = { accept: true; reason?: undefined; trust: TrustMetadata; decision: GuardResult } | { accept: false; reason: "caller_card_missing" | "caller_card_invalid" | "attestation_required" | "attestation_invalid" | "attestation_mismatch" | "attestation_consumed" | "attestation_revoked" | "attestation_status_unavailable" | "caller_revoked" | "denied" | "approval_required" | "verification_failed"; detail?: string; trust: TrustMetadata; decision?: { decision_id?: string; approval_id?: string | null; reasons: string[] } };
export interface VerifyBeforeAcceptOptions {
  fetch?: typeof fetch; now?: () => Date;
  /** Refuse tasks that carry no attestation (default false: the receiving guard still decides). */
  requireAttestation?: boolean;
  /** Attestation action expected for this skill (default `a2a:<skill>`); return null to skip the check. */
  expectedAction?: (skill: string) => string | null;
  /** Fetch the caller's public passport when the card advertises one (default true). */
  checkStanding?: boolean;
  /** §12.1: ask the caller organisation's status endpoint about the attestation when the card advertises one (default true). */
  checkRevocation?: boolean;
  /** §12.1: when that endpoint is unreachable, still accept an attestation issued at most this many seconds ago (default 0 = refuse). */
  staleOkSeconds?: number;
  /** Cache for JWKS documents across calls. */
  jwksCache?: Map<string, { keys: JsonWebKey[] }>;
  /** §9.2: where consumed single-use attestation jtis are remembered until they expire. Default: this process's memory — enough for one receiver; share a store (Redis, a table) when several replicas receive for the same agent. */
  consumed?: ConsumedStore;
}
/** Atomic "first or seen" claim on an attestation jti, remembered until `exp` (unix seconds). */
export interface ConsumedStore { consume(jti: string, exp: number, now: number): Promise<"first" | "seen"> | "first" | "seen" }
/** In-memory store: one process, expired entries dropped on each call. */
export function memoryConsumedStore(): ConsumedStore {
  const seen = new Map<string, number>();
  return { consume(jti, exp, now) { for (const [k, e] of seen) if (e < now) seen.delete(k); if (seen.has(jti)) return "seen"; seen.set(jti, exp); return "first"; } };
}
const defaultConsumed = memoryConsumedStore();

const header = (h: IncomingTask["headers"], name: string): string | null => (h instanceof Headers ? h.get(name) : (Object.entries(h).find(([k]) => k.toLowerCase() === name)?.[1] ?? null));

export async function verifyBeforeAccept(guard: GuardLike, task: IncomingTask, o: VerifyBeforeAcceptOptions = {}): Promise<VerifyBeforeAcceptResult> {
  const f = o.fetch ?? fetch; const now = o.now?.() ?? new Date(); const cache = o.jwksCache ?? new Map();
  const trust: TrustMetadata = { caller: { agent_id: null, stable_id: null, organization: null, public_id: null, card_url: null }, proof: { present: !!header(task.headers, "agent-proof"), note: "Agent-Proof is verified by the caller's control plane on /v1/verify; a receiving server sees presence only." }, attestation: { present: !!header(task.headers, "agent-attestation"), valid: false }, standing: { checked: false } };
  // 1. the caller's card
  const cardRef = task.callerCard ?? header(task.headers, "agent-card");
  let card: AgentCard | null = null;
  if (typeof cardRef === "string") { trust.caller.card_url = cardRef; try { const r = await f(cardRef, { headers: { accept: "application/json" } }); if (r.ok) card = (await r.json()) as AgentCard; } catch { card = null; } }
  else if (cardRef && typeof cardRef === "object") card = cardRef;
  if (!card) return { accept: false, reason: "caller_card_missing", detail: "No Agent Card: pass task.callerCard or send the Agent-Card header", trust };
  const ext = readAgentCard(card); if (!ext) return { accept: false, reason: "caller_card_invalid", detail: `Agent Card has no ${AGENT_TRUST_EXTENSION} extension`, trust };
  trust.caller = { agent_id: ext.agent_id ?? null, stable_id: ext.stable_id ?? null, organization: ext.organization_name ?? card.provider?.organization ?? ext.organization ?? null, public_id: ext.public_id ?? null, card_url: trust.caller.card_url };
  // 2. the attestation (offline, against the caller organisation's JWKS)
  const att = header(task.headers, "agent-attestation");
  if (!att) { if (o.requireAttestation) return { accept: false, reason: "attestation_required", trust }; }
  else {
    const iss = decodeJwt<{ iss?: string }>(att)?.payload.iss;
    if (!ext.jwks_url) { trust.attestation.reason = "no_jwks_url"; return { accept: false, reason: "attestation_invalid", detail: "the caller's card advertises no jwks_url", trust }; }
    const resolve = async (kid: string): Promise<JsonWebKey | null> => {
      let jwks = cache.get(ext.jwks_url!); if (!jwks) { try { const r = await f(ext.jwks_url!, { headers: { accept: "application/json" } }); jwks = r.ok ? ((await r.json()) as { keys: JsonWebKey[] }) : { keys: [] }; } catch { jwks = { keys: [] }; } cache.set(ext.jwks_url!, jwks); }
      return jwks.keys.find((k: JsonWebKey & { kid?: string }) => k.kid === kid) ?? null;
    };
    const v = await verifyAttestation(att, resolve, now);
    if (!v.ok) { trust.attestation.reason = v.reason; return { accept: false, reason: "attestation_invalid", detail: v.reason, trust }; }
    const p: AttestationJwt = v.payload;
    trust.attestation = { present: true, valid: true, jti: p.jti, action: p.atp.action, resource: p.atp.resource, principal: p.atp.principal, organization: p.iss, human_approved: !!p.atp.human_approval?.approved, expires_in: v.expires_in, delegation_chain_length: p.atp.delegation_chain?.length ?? 0 };
    if (ext.organization && p.iss !== ext.organization) { trust.attestation.valid = false; trust.attestation.reason = "issuer_mismatch"; return { accept: false, reason: "attestation_mismatch", detail: `attestation issued by ${p.iss}, card names ${ext.organization}`, trust }; }
    if (ext.agent_id && p.sub !== ext.agent_id && p.sub !== ext.stable_id) { trust.attestation.valid = false; trust.attestation.reason = "subject_mismatch"; return { accept: false, reason: "attestation_mismatch", detail: `attestation subject ${p.sub} is not the card's agent`, trust }; }
    const expected = o.expectedAction ? o.expectedAction(task.skill) : `a2a:${task.skill}`;
    if (expected && p.atp.action !== expected) { trust.attestation.valid = false; trust.attestation.reason = "action_mismatch"; return { accept: false, reason: "attestation_mismatch", detail: `attested action ${p.atp.action}, task needs ${expected}`, trust }; }
    if (typeof iss === "string" && iss !== p.iss) { /* unreachable: decode and verify read the same token */ }
    // §12.1: the caller organisation may have revoked the attestation since it was issued.
    if ((o.checkRevocation ?? true) && ext.attestation_status_url) {
      let st: "active" | "revoked" | "unreachable" = "unreachable";
      try { const r = await f(`${ext.attestation_status_url.replace(/\/$/, "")}/${encodeURIComponent(p.jti)}`, { headers: { accept: "application/json" } }); if (r.ok) { const j = (await r.json()) as { status?: string }; st = j.status === "active" ? "active" : ["revoked", "expired", "unknown"].includes(j.status ?? "") ? "revoked" : "unreachable"; } } catch { st = "unreachable"; }
      if (st === "revoked") { trust.revocation = { checked: true, status: st }; trust.attestation.valid = false; trust.attestation.reason = "revoked"; return { accept: false, reason: "attestation_revoked", detail: `attestation ${p.jti} was revoked by ${p.iss}`, trust }; }
      if (st === "unreachable") {
        const age = Math.max(0, Math.floor(now.getTime() / 1000) - p.iat);
        if (!(o.staleOkSeconds && age <= o.staleOkSeconds)) { trust.revocation = { checked: false, status: st, note: `issued ${age}s ago; no stale window` }; return { accept: false, reason: "attestation_status_unavailable", detail: `${p.iss}'s attestation status endpoint is unreachable`, trust }; }
        trust.revocation = { checked: false, status: st, note: `issued ${age}s ago; accepted inside the ${o.staleOkSeconds}s stale window` };
      } else trust.revocation = { checked: true, status: st };
    } else trust.revocation = { checked: false, note: ext.attestation_status_url ? "revocation check disabled" : "the caller's card advertises no attestation_status_url" };
    // §9.2: a single-use attestation is spent by this acceptance; a replay is refused before the receiving guard runs.
    trust.attestation.use = p.atp.use ?? "multi";
    if (p.atp.use === "single") {
      if ((await (o.consumed ?? defaultConsumed).consume(p.jti, p.exp, Math.floor(now.getTime() / 1000))) === "seen") { trust.attestation.valid = false; trust.attestation.reason = "consumed"; return { accept: false, reason: "attestation_consumed", detail: `single-use attestation ${p.jti} was already used`, trust }; }
      trust.attestation.consumed = true;
    }
  }
  // 3. public standing (when the caller publishes a passport)
  if ((o.checkStanding ?? true) && ext.passport_url) {
    try {
      const r = await f(ext.passport_url.replace(/\/agent\/(pub_[a-z0-9]+)$/, "/api/v1/agents/pub/$1/passport"), { headers: { accept: "application/json" } });
      if (r.ok) { const p = (await r.json()) as { state?: string; lifecycle?: string; organization?: { verified?: boolean } }; trust.standing = { checked: true, state: p.state, lifecycle: p.lifecycle, organization_verified: p.organization?.verified }; if (p.state === "revoked" || p.lifecycle === "revoked" || p.lifecycle === "suspended") return { accept: false, reason: "caller_revoked", detail: `caller passport state ${p.state ?? p.lifecycle}`, trust }; }
      else trust.standing = { checked: false, note: `passport answered ${r.status}` };
    } catch { trust.standing = { checked: false, note: "passport unreachable" }; }
  }
  // 4. the receiving agent's own authority for this skill
  try {
    const decision = await guard.check(task.skill, { ...(task.params && typeof task.params === "object" ? (task.params as Record<string, unknown>) : { input: task.params }), a2a: { caller: trust.caller.agent_id ?? trust.caller.stable_id, caller_org: trust.caller.organization, attested: trust.attestation.valid }, effect_path: trust.attestation.valid ? "attested" : "none" });
    return { accept: true, trust, decision };
  } catch (e) {
    if (e instanceof Denied) return { accept: false, reason: "denied", detail: e.message, trust, decision: { decision_id: e.decision.decision_id, reasons: e.reasons } };
    if (e instanceof ApprovalRequired) return { accept: false, reason: "approval_required", detail: e.message, trust, decision: { decision_id: e.decisionId, approval_id: e.approvalId, reasons: e.reasons } };
    if (e instanceof MnkiError) return { accept: false, reason: "verification_failed", detail: `${e.code}: ${e.message}`, trust };
    throw e;
  }
}
/** The JSON-RPC error an A2A server answers with when a task is refused (mirrors the MCP codes). */
export function refusalToJsonRpc(id: string | number | null, r: Exclude<VerifyBeforeAcceptResult, { accept: true }>): { jsonrpc: "2.0"; id: string | number | null; error: { code: number; message: string; data: unknown } } {
  const code = r.reason === "approval_required" ? -32001 : r.reason === "denied" || r.reason === "caller_revoked" || r.reason === "attestation_consumed" || r.reason === "attestation_revoked" ? -32003 : r.reason === "verification_failed" || r.reason === "attestation_status_unavailable" ? -32006 : -32602;
  return { jsonrpc: "2.0", id, error: { code, message: `refused by Agent Trust: ${r.reason}`, data: { detail: r.detail, trust: r.trust, decision: r.decision } } };
}

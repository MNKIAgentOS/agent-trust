import { verifyRequestProof } from "./proof";
import { verifyAttestation, decodeJwt } from "./credential";
import { resourceContains } from "./delegation/attenuate";
import type { CapSet, Delegation, Decision, EvidenceItem, VerifyRequest } from "./types";
import type { EvidenceCode, EvidenceParams } from "./evidence-codes";
import { capabilityCovered, constraintsTighter } from "./delegation/attenuate";
import { computeEffectiveAuthority, resolveChain } from "./delegation/chain";
import { evaluate } from "./policy/evaluate";
import type { PolicyDoc } from "./policy/schema";

export type { EvidenceItem, EvidenceStatus } from "./types";

export interface AgentInfo { id: string; stable_id: string; lifecycle: string; risk_tier: "low" | "medium" | "high" | "critical"; owner_principal_id: string | null; labels: Record<string, string> }
export interface CredentialInfo { id: string; kind: string; status: string; not_after: string | null; issuer?: string | null }
export interface PrincipalInfo { id: string; display_name: string; kind: string }
export interface AttestationInfo { id: string; kind: string; verified: boolean; expires_at: string | null }
export interface ActivePolicy { version_id: string | null; hash: string | null; doc: PolicyDoc }

/** Everything the pipeline needs from storage, injected. The console passes a D1 adapter; tests pass maps. */
export interface VerifierDeps {
  getAgent(ref: string): Promise<AgentInfo | null>;
  getActiveCredential(agentId: string): Promise<CredentialInfo | null>;
  getPrincipal(id: string): Promise<PrincipalInfo | null>;
  getLeafDelegation(agentId: string, delegationId?: string): Promise<Delegation | null>;
  /** Optional (§17): among the agent's active delegations, the newest whose effective authority covers `action` on `resource`; used when the request names no delegation, so a time-boxed grant never shadows the chain an agent already has. Null → `getLeafDelegation` fallback. */
  getCoveringDelegation?(agentId: string, action: string, resource?: string): Promise<Delegation | null>;
  getDelegationAncestry(leafId: string): Promise<Delegation[]>;
  getAgentCapabilities(agentId: string): Promise<CapSet>;
  isRevoked(subjectType: "agent" | "credential" | "delegation", subjectId: string): Promise<boolean>;
  getAttestations(agentId: string): Promise<AttestationInfo[]>;
  getPolicy(): Promise<ActivePolicy | null>;
  /** Optional: when provided, a credential whose issuer is not trusted fails step 4 (`credential_issuer_untrusted`). */
  isTrustedIssuer?(issuer: string | null): Promise<boolean>;
  /** Optional: public key for a request proof — by `kid`, or the agent's current key when the header carries none. */
  getCredentialKey?(agentId: string, kid: string | null): Promise<{ credentialId: string; jwk: JsonWebKey } | null>;
  /** Optional replay guard for proof `jti`s: true when already seen (and remember it until `exp`). */
  seenJti?(jti: string, exp: number): Promise<boolean>;
  /** Optional: an organization signing key (by kid + issuer) for delegation credentials and attestations. */
  getOrgKey?(kid: string, iss: string): Promise<JsonWebKey | null>;
  /** Optional: has this attestation (jti) been revoked before its expiry? */
  isAttestationRevoked?(jti: string): Promise<boolean>;
  /** Optional single-use attestations (§9.2): atomically claim a jti on first acceptance — "first" when this call claimed it, "seen" when it was already consumed. Remembered until `exp`. Without it, single-use attestations are refused (fail closed). */
  consumeAttestation?(jti: string, exp: number): Promise<"first" | "seen">;
  /** Optional: verify a presented issuer token (JWT-SVID / OIDC) against the org's trust anchors. */
  verifyPresentedCredential?(token: string): Promise<{ ok: true; kind: string; issuer: string; sub: string; kid: string | null; exp: number | null } | { ok: false; reason: string; issuer?: string }>;
  /** Optional federation: is this issuer a trusted peer organization, and at what level (2 = its attested agents may act here)? */
  getFederatedIssuer?(iss: string): Promise<{ name: string; trust_level: 1 | 2; /** §12.1: seconds after issuance during which an attestation is still accepted (with a warning) when the peer's status endpoint is unreachable; 0 or absent = refuse. */ stale_ok_seconds?: number } | null>;
  /** Optional (§12.1, v0.2): ask the issuing peer whether it has revoked this attestation. Without it the peer's revocation list is not consulted and the evidence says so (v0.1 behaviour). */
  peerAttestationStatus?(iss: string, jti: string): Promise<"active" | "revoked" | "unreachable">;
  /** Optional budgets: total amount already ALLOWED for this authority (leaf delegation, or the agent when direct), action and currency. */
  spentSoFar?(scope: { delegationId: string | null; agentId: string; action: string; currency: string | null }): Promise<number>;
}

/** Transport facts about the request the proof must be bound to. */
export interface RequestBinding { proof: string | null; htm: string; htu: string; bodyHash: string; /** Issuer-signed identity token presented by the agent (JWT-SVID / OIDC JWT), header Agent-Credential. */ credential?: string | null }
export interface VerifyOptions { now: Date; /** §17: the relying party's own identifier (e.g. a broker connection id). When set, a presented attestation MUST carry an `aud` equal to it. */ audience?: string; /** §9.2: canonical hash of the request being executed (the verify request without its `attestation` field); a single-use attestation must be bound to it. */ requestHash?: string; /** Proof binding; omit when the caller is not a signed transport (console). */ request?: RequestBinding; /** Deny unsigned requests (organization security default). */ requireProof?: boolean }

export interface VerifyResult {
  decision: Decision;
  reasons: string[];
  evidence: EvidenceItem[];
  agent: { id: string; verified: boolean } | null;
  principal: { id: string; verified: boolean } | null;
  delegation: { valid: boolean; chain_length: number; chain: string[] };
  authorization: { capability: string; valid: boolean; remaining_limit: number | null };
  revocation: { checked: true; valid: boolean };
  policy_version: string | null;
  policy_hash: string | null;
  proof: { present: boolean; verified: boolean; kid: string | null; alg: string | null };
  attestation: { present: boolean; valid: boolean; jti: string | null; expires_in: number | null; /** §9.2: "single" or "multi" once verified. */ use: "single" | "multi" | null; /** true when this decision consumed a single-use attestation. */ consumed: boolean };
  /** Set when the agent is not in this registry but was attested by a federated peer organization. */
  federation: { issuer: string; name: string; trust_level: 1 | 2 } | null;
}

/**
 * The verification pipeline (spec §8, steps 3–13). Pure: no I/O beyond `deps`,
 * no clock beyond `opts.now`. Every step appends one evidence row; the decision
 * is derived from the evidence, never from a score.
 */
export async function verify(req: VerifyRequest, deps: VerifierDeps, opts: VerifyOptions): Promise<VerifyResult> {
  const ev: EvidenceItem[] = []; const reasons: string[] = [];
  let hardFail = false;
  const fail = (step: string, code: EvidenceCode, title: string, reason: string, detail?: string, refs?: string[], params?: EvidenceParams) => { ev.push({ step, status: "fail", title, detail, refs, code, params }); reasons.push(reason); hardFail = true; };
  const now = opts.now; const t = now.getTime();
  // State is declared up front: finish() closes over it and may run from an early return.
  let cred: CredentialInfo | null = null; let principal: PrincipalInfo | null = null; let leaf: Delegation | null = null;
  let effective: CapSet = []; let chainIds: string[] = []; let delegationValid = false; let authorized = false; let revoked = false;
  let pol: ActivePolicy | null = null; let remainingLimit: number | null = null;
  const proofState: VerifyResult["proof"] = { present: !!opts.request?.proof, verified: false, kid: null, alg: null };
  const attState: VerifyResult["attestation"] = { present: !!req.attestation, valid: false, jti: null, expires_in: null, use: null, consumed: false }; let attExp = 0; let attIat = 0; let peerStaleOk = 0; let attApproval: { approval_id: string | null; bound: boolean } | null = null;
  /** A human approval the attestation carries, and whether it is bound to this very request (hash known on both sides and equal; unknown on either side counts as bound by action/resource alone). */
  const approvalOf = (atp: { human_approval?: { approved?: boolean; approval_id?: string | null } | null; request_hash?: string | null }) => atp.human_approval?.approved ? { approval_id: atp.human_approval.approval_id ?? null, bound: !opts.requestHash || !atp.request_hash || atp.request_hash === opts.requestHash } : null;
  const audOk = (aud: string | string[] | undefined) => !opts.audience || (Array.isArray(aud) ? aud.includes(opts.audience) : aud === opts.audience);
  const audText = (aud: string | string[] | undefined) => (Array.isArray(aud) ? aud.join(",") : aud) || "(none)";
  const boundElsewhere = (atp: { use?: string; request_hash?: string | null }) => atp.use === "single" && !!opts.requestHash && !!atp.request_hash && atp.request_hash !== opts.requestHash;
  let federation: VerifyResult["federation"] = null; let federatedCaps: CapSet | null = null; let federatedChain: string[] = []; let federatedPrincipal: string | null = null; let federatedApproved = false;

  ev.push({ step: "request", status: "pass", title: "Request parsed", detail: `${req.action}${req.resource ? ` on ${req.resource}` : ""}${req.amount !== undefined ? ` · ${req.amount} ${req.currency ?? ""}`.trimEnd() : ""}`, code: "request.parsed", params: { action: req.action, resource: req.resource ?? null, amount: req.amount ?? null, currency: req.currency ?? null } });

  // 3. agent identity — local registry, or a federated agent attested by a trusted peer organization (trust level 2)
  let agent = await deps.getAgent(req.agent);
  if (!agent && req.attestation && deps.getFederatedIssuer && deps.getOrgKey) {
    const iss = decodeJwt<{ iss?: string }>(req.attestation)?.payload.iss;
    const peer = typeof iss === "string" ? await deps.getFederatedIssuer(iss) : null;
    if (peer && peer.trust_level >= 2) {
      const a = await verifyAttestation(req.attestation, (kid, i) => deps.getOrgKey!(kid, i), now);
      if (!a.ok) { fail("identity", "identity.federated_attestation_invalid", "Federated attestation invalid", `attestation_invalid:${a.reason}`, `issuer ${iss}: ${a.reason}`, undefined, { issuer: iss!, reason: a.reason }); return finish("DENY"); }
      if (a.payload.sub !== req.agent) { fail("identity", "identity.federated_attestation_subject", "Federated attestation names a different agent", "attestation_invalid:subject", `sub ${a.payload.sub}`, undefined, { sub: a.payload.sub }); return finish("DENY"); }
      if (!audOk(a.payload.aud)) { fail("identity", "identity.federated_attestation_audience", "Federated attestation is for a different audience", "attestation_invalid:audience", `aud ${audText(a.payload.aud)}; expected ${opts.audience}`, undefined, { aud: audText(a.payload.aud), expected: opts.audience! }); return finish("DENY"); }
      if (a.payload.atp.action !== req.action || (a.payload.atp.resource && req.resource && !resourceContains(a.payload.atp.resource, req.resource))) { fail("identity", "identity.federated_attestation_action", "Federated attestation does not cover this action", "attestation_invalid:action", `attested ${a.payload.atp.action}${a.payload.atp.resource ? ` on ${a.payload.atp.resource}` : ""}`, undefined, { action: a.payload.atp.action, resource: a.payload.atp.resource ?? null }); return finish("DENY"); }
      if (boundElsewhere(a.payload.atp)) { fail("identity", "identity.federated_attestation_request_hash", "Federated attestation is bound to a different request", "attestation_invalid:request_hash", `single-use attestation ${a.payload.jti} was issued for another request`, [a.payload.jti], { jti: a.payload.jti }); return finish("DENY"); }
      agent = { id: a.payload.sub, stable_id: a.payload.sub, lifecycle: "active", risk_tier: "medium", owner_principal_id: null, labels: { federated_org: iss! } };
      federation = { issuer: iss!, name: peer.name, trust_level: peer.trust_level }; peerStaleOk = peer.stale_ok_seconds ?? 0; attIat = a.payload.iat; federatedCaps = a.payload.atp.capabilities; federatedChain = a.payload.atp.delegation_chain ?? []; federatedPrincipal = a.payload.atp.principal; federatedApproved = !!a.payload.atp.human_approval?.approved;
      attState.valid = true; attState.jti = a.payload.jti; attState.expires_in = a.expires_in; attState.use = a.payload.atp.use ?? "multi"; attExp = a.payload.exp; attApproval = approvalOf(a.payload.atp); reasons.push("identity_federated", "attestation_valid");
      ev.push({ step: "identity", status: "pass", title: `Federated agent — attested by ${peer.name} (trust level ${peer.trust_level})`, detail: a.payload.sub, refs: [a.payload.jti], code: "identity.federated", params: { peer: peer.name, level: peer.trust_level, issuer: iss!, sub: a.payload.sub } });
    } else if (peer) { fail("identity", "identity.federation_level_insufficient", "Peer organization is trusted at level 1 only", "federation_level_insufficient", `${peer.name} may not act here; raise it to trust level 2`, undefined, { peer: peer.name, issuer: iss! }); return finish("DENY"); }
  }
  if (!agent) {
    fail("identity", "identity.unknown", "Agent unknown", "agent_unknown", `No agent matches "${req.agent}"`, undefined, { agent: req.agent });
    return finish("DENY");
  }
  if (federation) { /* identity evidence already recorded */ }
  else if (agent.lifecycle !== "active") fail("identity", "identity.lifecycle", `Agent is ${agent.lifecycle}`, `agent_${agent.lifecycle}`, undefined, [agent.id], { lifecycle: agent.lifecycle });
  else ev.push({ step: "identity", status: "pass", title: "Agent identity resolved", detail: agent.stable_id, refs: [agent.id], code: "identity.resolved", params: { stable_id: agent.stable_id } });

  if (federation) {
    // Federated path: the peer's attestation stands in for credential, principal and delegation; local policy still applies.
    ev.push({ step: "credential", status: "pass", title: `Issuer attestation stands in for a local credential (${federation.name})`, code: "credential.federated_issuer", params: { peer: federation.name, issuer: federation.issuer } });
    if (opts.request?.proof) ev.push({ step: "proof", status: "skipped", title: "Request proof not checked for federated agents", detail: "The agent's key lives in the peer registry.", code: "proof.federated_skipped", params: {} }); else if (opts.requireProof) fail("proof", "proof.unsigned_required", "Unsigned request", "request_unsigned", "This organization requires signed requests", undefined, {});
    if (federatedPrincipal) { ev.push({ step: "principal", status: "pass", title: `Principal ${federatedPrincipal} asserted by ${federation.name}`, detail: "Not resolved locally", code: "principal.federated", params: { principal: federatedPrincipal, peer: federation.name } }); } else { ev.push({ step: "principal", status: "warn", title: "No principal in the federated attestation", code: "principal.federated_none", params: {} }); reasons.push("principal_unbound"); }
    effective = federatedCaps ?? []; chainIds = federatedChain; delegationValid = federatedChain.length > 0;
    ev.push({ step: "delegation", status: federatedChain.length ? "pass" : "warn", title: federatedChain.length ? `Delegation chain attested by issuer (${federatedChain.length} link${federatedChain.length > 1 ? "s" : ""})` : "No delegation chain in the attestation — issuer-asserted capabilities", refs: federatedChain, code: federatedChain.length ? "delegation.federated" : "delegation.federated_none", params: federatedChain.length ? { links: federatedChain.length } : {} }); reasons.push(federatedChain.length ? "delegation_attested" : "no_delegation");
    if (federatedApproved) reasons.push("human_approved_by_issuer");
  } else {
  // 4. credential — a presented issuer token (SPIRE JWT-SVID, IdP JWT) verified against the trust anchors, else the registered credential
  cred = await deps.getActiveCredential(agent.id);
  const presented = opts.request?.credential ?? null;
  if (presented && deps.verifyPresentedCredential) {
    const v = await deps.verifyPresentedCredential(presented);
    if (!v.ok) fail("credential", "credential.presented_invalid", "Presented credential invalid", `credential_presented_invalid:${v.reason}`, v.issuer ? `issuer ${v.issuer}: ${v.reason}` : v.reason, [agent.id], { reason: v.reason, issuer: v.issuer ?? null });
    else if (v.sub !== agent.stable_id && v.sub !== agent.id) fail("credential", "credential.presented_subject", "Presented credential names a different agent", "credential_presented_invalid:subject", `sub ${v.sub}`, [agent.id], { sub: v.sub });
    else { if (!cred) cred = { id: `presented:${v.kind}`, kind: v.kind, status: "active", not_after: v.exp ? new Date(v.exp * 1000).toISOString() : null, issuer: v.issuer }; ev.push({ step: "credential", status: "pass", title: `${v.kind === "jwt_svid" ? "JWT-SVID" : "Issuer token"} verified against ${v.issuer}`, detail: v.kid ? `kid ${v.kid}${v.exp ? ` · valid until ${new Date(v.exp * 1000).toISOString().slice(0, 19)}Z` : ""}` : undefined, refs: [agent.id], code: v.kind === "jwt_svid" ? "credential.svid_verified" : "credential.token_verified", params: { kind: v.kind, issuer: v.issuer, kid: v.kid, exp: v.exp ? `${new Date(v.exp * 1000).toISOString().slice(0, 19)}Z` : null } }); reasons.push("credential_presented_verified"); }
  } else if (!cred) fail("credential", "credential.missing", "No active credential", "credential_missing", undefined, [agent.id], {});
  else if (cred.not_after && Date.parse(cred.not_after) <= t) fail("credential", "credential.expired", "Credential expired", "credential_expired", `expired ${cred.not_after}`, [cred.id], { not_after: cred.not_after });
  else if (deps.isTrustedIssuer && !(await deps.isTrustedIssuer(cred.issuer ?? null))) fail("credential", "credential.issuer_untrusted", "Credential issuer not trusted", "credential_issuer_untrusted", cred.issuer ? `issuer ${cred.issuer} is not a configured trust domain` : "credential has no issuer", [cred.id], { issuer: cred.issuer ?? null });
  else ev.push({ step: "credential", status: "pass", title: `Credential fresh (${cred.kind})`, detail: cred.not_after ? `valid until ${cred.not_after.slice(0, 10)}` : undefined, refs: [cred.id], code: "credential.fresh", params: { kind: cred.kind, not_after: cred.not_after ? cred.not_after.slice(0, 10) : null } });

  // 4b. request proof-of-possession (detached JWS bound to method, URL and body hash)
  if (opts.request?.proof) {
    const r = opts.request;
    const out = await verifyRequestProof({ proof: r.proof!, htm: r.htm, htu: r.htu, bodyHash: r.bodyHash, now,
      resolveKey: async (kid) => (deps.getCredentialKey ? (await deps.getCredentialKey(agent.id, kid))?.jwk ?? null : null),
      seenJti: deps.seenJti ? (jti, exp) => deps.seenJti!(jti, exp) : undefined });
    if (!out.ok) fail("proof", "proof.invalid", "Request signature invalid", `proof_invalid:${out.reason}`, out.reason, out.kid ? [out.kid] : undefined, { reason: out.reason, kid: out.kid ?? null });
    else if (out.claims.iss !== agent.id && out.claims.iss !== agent.stable_id) fail("proof", "proof.issuer_mismatch", "Request signed by a different agent", "proof_invalid:issuer", `iss ${out.claims.iss}`, out.kid ? [out.kid] : undefined, { iss: out.claims.iss, kid: out.kid ?? null });
    else { proofState.verified = true; proofState.kid = out.kid; proofState.alg = out.alg; reasons.push("request_signed"); ev.push({ step: "proof", status: "pass", title: `Request signature verified (${out.alg})`, detail: out.kid ? `kid ${out.kid}` : undefined, refs: out.kid ? [out.kid] : undefined, code: "proof.verified", params: { alg: out.alg, kid: out.kid ?? null } }); }
  } else if (opts.requireProof) {
    fail("proof", "proof.unsigned_required", "Unsigned request", "request_unsigned", "This organization requires signed requests", undefined, {});
  } else {
    ev.push({ step: "proof", status: "warn", title: "Request not signed", detail: "No Agent-Proof header — possession of the agent key was not proven.", code: "proof.unsigned", params: {} }); reasons.push("request_unsigned");
  }

  // 4c. presented Agent Authorization Attestation (signed by an organization key)
  if (req.attestation && !federation) {
    if (!deps.getOrgKey) fail("attestation_token", "attestation_token.no_resolver", "Attestation cannot be verified", "attestation_invalid:no_resolver", undefined, undefined, {});
    else {
      const a = await verifyAttestation(req.attestation, (kid, iss) => deps.getOrgKey!(kid, iss), now);
      if (!a.ok) fail("attestation_token", "attestation_token.invalid", "Authorization attestation invalid", `attestation_invalid:${a.reason}`, a.reason, undefined, { reason: a.reason });
      else if (a.payload.sub !== agent.id && a.payload.sub !== agent.stable_id) fail("attestation_token", "attestation_token.subject", "Attestation issued to a different agent", "attestation_invalid:subject", `sub ${a.payload.sub}`, undefined, { sub: a.payload.sub });
      else if (!audOk(a.payload.aud)) fail("attestation_token", "attestation_token.audience", "Attestation is for a different audience", "attestation_invalid:audience", `aud ${audText(a.payload.aud)}; expected ${opts.audience}`, [a.payload.jti], { aud: audText(a.payload.aud), expected: opts.audience! });
      else if (a.payload.atp.action !== req.action) fail("attestation_token", "attestation_token.action", "Attestation covers a different action", "attestation_invalid:action", `attested ${a.payload.atp.action}`, undefined, { action: a.payload.atp.action });
      else if (a.payload.atp.resource && req.resource && !resourceContains(a.payload.atp.resource, req.resource)) fail("attestation_token", "attestation_token.resource", "Attestation does not cover this resource", "attestation_invalid:resource", `attested ${a.payload.atp.resource}`, undefined, { resource: a.payload.atp.resource });
      else if (boundElsewhere(a.payload.atp)) fail("attestation_token", "attestation_token.request_hash", "Attestation bound to a different request", "attestation_invalid:request_hash", `single-use attestation ${a.payload.jti} was issued for another request`, [a.payload.jti], { jti: a.payload.jti });
      else if (deps.isAttestationRevoked && (await deps.isAttestationRevoked(a.payload.jti))) fail("attestation_token", "attestation_token.revoked", "Attestation revoked", "attestation_invalid:revoked", undefined, [a.payload.jti], { jti: a.payload.jti });
      else { attState.valid = true; attState.jti = a.payload.jti; attState.expires_in = a.expires_in; attState.use = a.payload.atp.use ?? "multi"; attExp = a.payload.exp; attApproval = approvalOf(a.payload.atp); reasons.push("attestation_valid"); ev.push({ step: "attestation_token", status: "pass", title: `Authorization attestation valid (expires in ${a.expires_in}s)`, detail: `issued by ${a.payload.iss} for ${a.payload.atp.action}`, refs: [a.payload.jti], code: "attestation_token.valid", params: { jti: a.payload.jti, expires_in: a.expires_in, issuer: a.payload.iss, action: a.payload.atp.action, human_approved: !!a.payload.atp.human_approval?.approved } }); }
    }
  }

  // 5. principal
  principal = agent.owner_principal_id ? await deps.getPrincipal(agent.owner_principal_id) : null;
  if (principal) ev.push({ step: "principal", status: "pass", title: `Principal binding active (${principal.display_name})`, refs: [principal.id], code: "principal.bound", params: { name: principal.display_name, id: principal.id } });
  else { ev.push({ step: "principal", status: "warn", title: "No delegating principal", detail: "Authority is not bound to a human or service owner.", code: "principal.unbound", params: {} }); reasons.push("principal_unbound"); }

  // 6–8. delegation chain → effective authority
  // §17: without an explicit delegation id, prefer the delegation that actually covers this action, so a narrow time-boxed grant never shadows the chain the agent already has.
  leaf = req.delegation_id ? await deps.getLeafDelegation(agent.id, req.delegation_id) : ((deps.getCoveringDelegation ? await deps.getCoveringDelegation(agent.id, req.action, req.resource) : null) ?? await deps.getLeafDelegation(agent.id));
  if (leaf) {
    const anc = await deps.getDelegationAncestry(leaf.id);
    const byId = new Map(anc.map((d) => [d.id, d]));
    const chain = resolveChain(leaf.id, (id) => byId.get(id));
    if (!chain.ok) fail("delegation", "delegation.chain_invalid", `Delegation chain ${chain.reason}`, `delegation_chain_${chain.reason}`, `at ${chain.at}`, [leaf.id], { reason: chain.reason, at: chain.at });
    else {
      chainIds = chain.chain.map((d) => d.id);
      effective = computeEffectiveAuthority(chain.chain, now);
      const badLink = chain.chain.find((d) => d.status !== "active" || (d.not_after && Date.parse(d.not_after) <= t) || (d.not_before && Date.parse(d.not_before) > t));
      if (badLink) fail("delegation", badLink.status === "active" ? "delegation.link_outside_window" : badLink.status === "expired" ? "delegation.link_expired" : "delegation.link_revoked", `Delegation ${badLink.status === "active" ? "outside validity window" : badLink.status}`, `delegation_${badLink.status === "active" ? "expired" : badLink.status}`, undefined, [badLink.id], { link: badLink.id, status: badLink.status });
      else { delegationValid = true; ev.push({ step: "delegation", status: "pass", title: `Delegation chain valid (${chain.chain.length} link${chain.chain.length > 1 ? "s" : ""})`, refs: chainIds, code: "delegation.valid", params: { links: chain.chain.length } }); }
    }
  } else {
    effective = await deps.getAgentCapabilities(agent.id);
    ev.push({ step: "delegation", status: "warn", title: "No delegation — using directly assigned capabilities", refs: [agent.id], code: "delegation.none", params: {} });
    reasons.push("no_delegation");
  }

  }

  // 9. capability + constraints
  const requested = { action: req.action, resource: req.resource ?? "*", constraints: undefined };
  const covering = effective.filter((c) => c.action === req.action && (req.resource === undefined || capabilityCovered({ ...c, constraints: undefined }, requested)));
  if (covering.length === 0) fail("capability", "capability.missing", `Capability ${req.action} not granted`, "capability_missing", req.resource ? `for ${req.resource}` : undefined, undefined, { action: req.action, resource: req.resource ?? null });
  else {
    const reqConstraints: Record<string, unknown> = {};
    if (req.amount !== undefined) reqConstraints.max_value = req.amount;
    if (req.currency) reqConstraints.currency = req.currency;
    const region = typeof req.context?.region === "string" ? req.context.region : undefined;
    if (region) reqConstraints.region = [region];
    const within = covering.find((c) => constraintsTighter(c.constraints, { ...c.constraints, ...reqConstraints }));
    if (!within) {
      const lim = covering[0].constraints;
      const limits = lim ? Object.entries(lim).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("|") : String(v)}`).join(", ") : undefined;
      fail("constraints", "constraints.violated", "Request exceeds capability constraints", "constraint_violated", limits, undefined, { limits: limits ?? null });
    } else if (typeof within.constraints?.max_total === "number" && req.amount !== undefined && deps.spentSoFar) {
      // Lifetime budget: what this authority has already been allowed to spend, plus this request, must fit under max_total.
      const spent = await deps.spentSoFar({ delegationId: leaf?.id ?? null, agentId: agent.id, action: req.action, currency: req.currency ?? null });
      const left = within.constraints.max_total - spent;
      if (req.amount > left) fail("constraints", "constraints.budget_exhausted", "Budget exhausted", "budget_exceeded", `${spent} of ${within.constraints.max_total} ${req.currency ?? ""} already spent; ${left} left`.trim(), undefined, { spent, total: within.constraints.max_total, left, currency: req.currency ?? null });
      else { authorized = true; remainingLimit = left - req.amount; ev.push({ step: "capability", status: "pass", title: `Capability ${req.action} granted`, detail: within.resource, code: "capability.granted", params: { action: req.action, resource: within.resource } }); ev.push({ step: "constraints", status: "pass", title: "Constraints satisfied", detail: `budget ${spent + req.amount} of ${within.constraints.max_total} ${req.currency ?? ""} used`.trim(), code: "constraints.budget_ok", params: { used: spent + req.amount, total: within.constraints.max_total, left: remainingLimit, currency: req.currency ?? null } }); }
    } else { authorized = true; if (typeof within.constraints?.max_value === "number" && req.amount !== undefined) remainingLimit = within.constraints.max_value - req.amount; const limits = within.constraints ? Object.entries(within.constraints).map(([k, v]) => `${k} ${Array.isArray(v) ? v.join("|") : String(v)}`).join(" · ") : null; ev.push({ step: "capability", status: "pass", title: `Capability ${req.action} granted`, detail: within.resource, code: "capability.granted", params: { action: req.action, resource: within.resource } }); ev.push({ step: "constraints", status: "pass", title: "Constraints satisfied", detail: limits ?? "none", code: "constraints.satisfied", params: { limits } }); }
  }

  // 10. revocation
  // Every link of the chain is consulted: revoking a root delegation invalidates every descendant immediately.
  let revokedRef: string | null = null;
  if (federation && !deps.peerAttestationStatus) {
    // The attestation was issued by the peer; its revocation list is theirs. Without a status resolver (v0.1) short lifetimes are the only bound, and the evidence says so.
    ev.push({ step: "revocation", status: "warn", title: "Peer revocation not consulted", detail: `Attestation is short-lived (expires in ${attState.expires_in ?? "?"}s); ${federation.name}'s revocation list is not queried in v0.1.`, code: "revocation.peer_unchecked", params: { peer: federation.name, expires_in: attState.expires_in } }); reasons.push("revocation_remote_unchecked");
  } else if (federation) {
    // §12.1 (v0.2): the issuing peer is asked about this jti. Unreachable is a refusal unless the federation record allows a stale window the attestation is still inside.
    const jti = attState.jti!; const st = await deps.peerAttestationStatus!(federation.issuer, jti);
    if (st === "active") ev.push({ step: "revocation", status: "pass", title: `Peer revocation checked with ${federation.name} — none found`, refs: [jti], code: "revocation.peer_none", params: { peer: federation.name, jti } });
    else if (st === "revoked") { revoked = true; fail("revocation", "revocation.peer_revoked", `Attestation revoked by ${federation.name}`, "revoked", undefined, [jti], { peer: federation.name, jti }); }
    else {
      const age = Math.max(0, Math.floor(t / 1000) - attIat);
      if (peerStaleOk > 0 && age <= peerStaleOk) { ev.push({ step: "revocation", status: "warn", title: `${federation.name} unreachable — attestation accepted inside the stale window`, detail: `issued ${age}s ago; stale window ${peerStaleOk}s`, refs: [jti], code: "revocation.peer_unreachable_stale_ok", params: { peer: federation.name, age, stale_ok: peerStaleOk } }); reasons.push("revocation_remote_unreachable"); }
      else { revoked = true; fail("revocation", "revocation.peer_unreachable", `${federation.name} unreachable — revocation status unknown`, "revocation_remote_unreachable", `issued ${age}s ago; stale window ${peerStaleOk}s`, [jti], { peer: federation.name, age, stale_ok: peerStaleOk }); }
    }
  } else {
  if (await deps.isRevoked("agent", agent.id)) revokedRef = agent.id;
  else if (cred && (await deps.isRevoked("credential", cred.id))) revokedRef = cred.id;
  else for (const id of chainIds.length ? chainIds : leaf ? [leaf.id] : []) if (await deps.isRevoked("delegation", id)) { revokedRef = id; break; }
  revoked = revokedRef !== null;
  if (revoked) fail("revocation", revokedRef === agent.id ? "revocation.agent" : revokedRef === cred?.id ? "revocation.credential" : "revocation.delegation", revokedRef === agent.id ? "Agent is revoked" : revokedRef === cred?.id ? "Credential is revoked" : "A delegation in the chain is revoked", "revoked", undefined, [revokedRef!], { ref: revokedRef! });
  else ev.push({ step: "revocation", status: "pass", title: "Revocation checked — none found", code: "revocation.none", params: {} });
  }

  // 11. attestation (evidence only in v0.1)
  const atts = (await deps.getAttestations(agent.id)).filter((a) => a.verified && (!a.expires_at || Date.parse(a.expires_at) > t));
  if (atts.length) ev.push({ step: "attestation", status: "pass", title: `Runtime attested (${atts.map((a) => a.kind).join(", ")})`, refs: atts.map((a) => a.id), code: "attestation.present", params: { kinds: atts.map((a) => a.kind).join(", ") } });
  else ev.push({ step: "attestation", status: "skipped", title: "No runtime attestation", detail: "Not required by policy.", code: "attestation.none", params: {} });

  // 11b. effect path (§15, v0.2): can the effect happen without this decision? The caller declares how it is enforced; the evidence shows it on every decision.
  const effectPath = req.context?.effect_path;
  if (effectPath === "custody") ev.push({ step: "enforcement", status: "pass", title: "Effect path: the enforcement point holds the effect credential", detail: "the agent never holds it, so the effector is reachable only through a decision", code: "enforcement.custody", params: { path: "custody" } });
  else if (effectPath === "attested") ev.push({ step: "enforcement", status: "pass", title: "Effect path: the effector verifies the attestation", detail: "the effector executes only with an attestation bound to this request", code: "enforcement.attested", params: { path: "attested" } });
  else { const path = effectPath === "none" ? "none" : "undeclared"; ev.push({ step: "enforcement", status: "warn", title: "A direct path to the effector may exist", detail: `effect path ${path}; this decision relies on deployment isolation`, code: "enforcement.none", params: { path } }); }

  // 12. policy
  pol = await deps.getPolicy();
  let policyEffect: "allow" | "deny" | "require_approval" = "allow";
  if (pol) {
    const out = evaluate(pol.doc, {
      action: req.action, resource: req.resource, amount: req.amount, currency: req.currency,
      region: typeof req.context?.region === "string" ? req.context.region : undefined,
      risk_tier: agent.risk_tier, agent_labels: agent.labels, delegation_depth: chainIds.length, attestations: atts.map((a) => a.kind), time: now,
    });
    policyEffect = out.effect; reasons.push(...out.reasons);
    if (out.effect === "require_approval" && attState.valid && attApproval?.bound && attState.jti) {
      // §9.2: the presented attestation carries the approval this policy asks for, for this very request — the permit is honoured (and, if single-use, spent below).
      policyEffect = "allow"; reasons.push("human_approved_by_attestation");
      ev.push({ step: "policy", status: "pass", title: "Policy's approval requirement is met by a human-approved attestation", detail: `${out.fired.length ? `fired: ${out.fired.join(", ")}; ` : ""}approval ${attApproval.approval_id ?? "?"} carried by ${attState.jti}`, refs: [...(pol.version_id ? [pol.version_id] : []), attState.jti], code: "policy.approved_by_attestation", params: { fired: out.fired.length ? out.fired.join(", ") : null, version: pol.version_id, jti: attState.jti, approval_id: attApproval.approval_id } });
    } else
    ev.push({ step: "policy", status: out.effect === "allow" ? "pass" : out.effect === "deny" ? "fail" : "warn", title: out.effect === "allow" ? "Policy allows" : out.effect === "deny" ? "Policy denies" : "Policy requires human approval", detail: out.fired.length ? `fired: ${out.fired.join(", ")}` : "no rule fired", refs: pol.version_id ? [pol.version_id] : undefined, code: out.effect === "allow" ? "policy.allow" : out.effect === "deny" ? "policy.deny" : "policy.require_approval", params: { fired: out.fired.length ? out.fired.join(", ") : null, version: pol.version_id } });
    if (out.effect === "deny") hardFail = true;
  } else ev.push({ step: "policy", status: "skipped", title: "No active policy", code: "policy.none", params: {} });

  // 13. decide
  let decision: Decision = hardFail ? "DENY" : policyEffect === "require_approval" ? "REQUIRE_APPROVAL" : "ALLOW";

  // 14. single-use attestation (§9.2): the permit is spent only when the effect is about to be allowed, and atomically, so a replay finds it spent.
  if (decision === "ALLOW" && attState.valid && attState.use === "single" && attState.jti) {
    if (!deps.consumeAttestation) { fail("single_use", "single_use.no_store", "Single-use attestation cannot be consumed here", "attestation_invalid:no_consume_store", `No consumption store: single-use attestation ${attState.jti} is refused where its use cannot be recorded`, [attState.jti], { jti: attState.jti }); decision = "DENY"; }
    else if ((await deps.consumeAttestation(attState.jti, attExp)) === "seen") { fail("single_use", "single_use.consumed", "Attestation already used", "attestation_invalid:consumed", `Single-use attestation ${attState.jti} was consumed by an earlier request`, [attState.jti], { jti: attState.jti }); decision = "DENY"; }
    else { attState.consumed = true; reasons.push("attestation_consumed"); ev.push({ step: "single_use", status: "pass", title: "Single-use attestation consumed", detail: `${attState.jti} cannot be presented again`, refs: [attState.jti], code: "single_use.recorded", params: { jti: attState.jti } }); }
  }
  if (decision === "ALLOW") reasons.unshift("identity_verified", "authority_valid");
  return finish(decision);

  function finish(decision: Decision): VerifyResult {
    return {
      decision, reasons: [...new Set(reasons)], evidence: ev,
      agent: agent ? { id: agent.id, verified: agent.lifecycle === "active" } : null,
      principal: principal ? { id: principal.id, verified: true } : null,
      delegation: { valid: delegationValid, chain_length: chainIds.length, chain: chainIds },
      authorization: { capability: req.action, valid: authorized, remaining_limit: authorized ? remainingLimit : null },
      revocation: { checked: true, valid: !revoked },
      policy_version: pol?.version_id ?? null, policy_hash: pol?.hash ?? null,
      proof: proofState, attestation: attState, federation,
    };
  }
}

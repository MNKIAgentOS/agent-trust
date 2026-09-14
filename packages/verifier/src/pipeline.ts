import { verifyRequestProof } from "./proof";
import { verifyAttestation } from "./credential";
import { resourceContains } from "./delegation/attenuate";
import type { CapSet, Delegation, Decision, VerifyRequest } from "./types";
import { capabilityCovered, constraintsTighter } from "./delegation/attenuate";
import { computeEffectiveAuthority, resolveChain } from "./delegation/chain";
import { evaluate } from "./policy/evaluate";
import type { PolicyDoc } from "./policy/schema";

export type EvidenceStatus = "pass" | "warn" | "fail" | "skipped";
export interface EvidenceItem { step: string; status: EvidenceStatus; title: string; detail?: string; refs?: string[] }

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
}

/** Transport facts about the request the proof must be bound to. */
export interface RequestBinding { proof: string | null; htm: string; htu: string; bodyHash: string }
export interface VerifyOptions { now: Date; /** Proof binding; omit when the caller is not a signed transport (console). */ request?: RequestBinding; /** Deny unsigned requests (organization security default). */ requireProof?: boolean }

export interface VerifyResult {
  decision: Decision;
  reasons: string[];
  evidence: EvidenceItem[];
  agent: { id: string; verified: boolean } | null;
  principal: { id: string; verified: boolean } | null;
  delegation: { valid: boolean; chain_length: number; chain: string[] };
  authorization: { capability: string; valid: boolean };
  revocation: { checked: true; valid: boolean };
  policy_version: string | null;
  policy_hash: string | null;
  proof: { present: boolean; verified: boolean; kid: string | null; alg: string | null };
  attestation: { present: boolean; valid: boolean; jti: string | null; expires_in: number | null };
}

/**
 * The verification pipeline (spec §8, steps 3–13). Pure: no I/O beyond `deps`,
 * no clock beyond `opts.now`. Every step appends one evidence row; the decision
 * is derived from the evidence, never from a score.
 */
export async function verify(req: VerifyRequest, deps: VerifierDeps, opts: VerifyOptions): Promise<VerifyResult> {
  const ev: EvidenceItem[] = []; const reasons: string[] = [];
  let hardFail = false;
  const fail = (step: string, title: string, reason: string, detail?: string, refs?: string[]) => { ev.push({ step, status: "fail", title, detail, refs }); reasons.push(reason); hardFail = true; };
  const now = opts.now; const t = now.getTime();
  // State is declared up front: finish() closes over it and may run from an early return.
  let cred: CredentialInfo | null = null; let principal: PrincipalInfo | null = null; let leaf: Delegation | null = null;
  let effective: CapSet = []; let chainIds: string[] = []; let delegationValid = false; let authorized = false; let revoked = false;
  let pol: ActivePolicy | null = null;
  const proofState: VerifyResult["proof"] = { present: !!opts.request?.proof, verified: false, kid: null, alg: null };
  const attState: VerifyResult["attestation"] = { present: !!req.attestation, valid: false, jti: null, expires_in: null };

  ev.push({ step: "request", status: "pass", title: "Request parsed", detail: `${req.action}${req.resource ? ` on ${req.resource}` : ""}${req.amount !== undefined ? ` · ${req.amount} ${req.currency ?? ""}`.trimEnd() : ""}` });

  // 3. agent identity
  const agent = await deps.getAgent(req.agent);
  if (!agent) {
    fail("identity", "Agent unknown", "agent_unknown", `No agent matches "${req.agent}"`);
    return finish("DENY");
  }
  if (agent.lifecycle !== "active") fail("identity", `Agent is ${agent.lifecycle}`, `agent_${agent.lifecycle}`, undefined, [agent.id]);
  else ev.push({ step: "identity", status: "pass", title: "Agent identity resolved", detail: agent.stable_id, refs: [agent.id] });

  // 4. credential
  cred = await deps.getActiveCredential(agent.id);
  if (!cred) fail("credential", "No active credential", "credential_missing", undefined, [agent.id]);
  else if (cred.not_after && Date.parse(cred.not_after) <= t) fail("credential", "Credential expired", "credential_expired", `expired ${cred.not_after}`, [cred.id]);
  else if (deps.isTrustedIssuer && !(await deps.isTrustedIssuer(cred.issuer ?? null))) fail("credential", "Credential issuer not trusted", "credential_issuer_untrusted", cred.issuer ? `issuer ${cred.issuer} is not a configured trust domain` : "credential has no issuer", [cred.id]);
  else ev.push({ step: "credential", status: "pass", title: `Credential fresh (${cred.kind})`, detail: cred.not_after ? `valid until ${cred.not_after.slice(0, 10)}` : undefined, refs: [cred.id] });

  // 4b. request proof-of-possession (detached JWS bound to method, URL and body hash)
  if (opts.request?.proof) {
    const r = opts.request;
    const out = await verifyRequestProof({ proof: r.proof!, htm: r.htm, htu: r.htu, bodyHash: r.bodyHash, now,
      resolveKey: async (kid) => (deps.getCredentialKey ? (await deps.getCredentialKey(agent.id, kid))?.jwk ?? null : null),
      seenJti: deps.seenJti ? (jti, exp) => deps.seenJti!(jti, exp) : undefined });
    if (!out.ok) fail("proof", "Request signature invalid", `proof_invalid:${out.reason}`, out.reason, out.kid ? [out.kid] : undefined);
    else if (out.claims.iss !== agent.id && out.claims.iss !== agent.stable_id) fail("proof", "Request signed by a different agent", "proof_invalid:issuer", `iss ${out.claims.iss}`, out.kid ? [out.kid] : undefined);
    else { proofState.verified = true; proofState.kid = out.kid; proofState.alg = out.alg; reasons.push("request_signed"); ev.push({ step: "proof", status: "pass", title: `Request signature verified (${out.alg})`, detail: out.kid ? `kid ${out.kid}` : undefined, refs: out.kid ? [out.kid] : undefined }); }
  } else if (opts.requireProof) {
    fail("proof", "Unsigned request", "request_unsigned", "This organization requires signed requests");
  } else {
    ev.push({ step: "proof", status: "warn", title: "Request not signed", detail: "No Agent-Proof header — possession of the agent key was not proven." }); reasons.push("request_unsigned");
  }

  // 4c. presented Agent Authorization Attestation (signed by an organization key)
  if (req.attestation) {
    if (!deps.getOrgKey) fail("attestation_token", "Attestation cannot be verified", "attestation_invalid:no_resolver");
    else {
      const a = await verifyAttestation(req.attestation, (kid, iss) => deps.getOrgKey!(kid, iss), now);
      if (!a.ok) fail("attestation_token", "Authorization attestation invalid", `attestation_invalid:${a.reason}`, a.reason);
      else if (a.payload.sub !== agent.id && a.payload.sub !== agent.stable_id) fail("attestation_token", "Attestation issued to a different agent", "attestation_invalid:subject", `sub ${a.payload.sub}`);
      else if (a.payload.atp.action !== req.action) fail("attestation_token", "Attestation covers a different action", "attestation_invalid:action", `attested ${a.payload.atp.action}`);
      else if (a.payload.atp.resource && req.resource && !resourceContains(a.payload.atp.resource, req.resource)) fail("attestation_token", "Attestation does not cover this resource", "attestation_invalid:resource", `attested ${a.payload.atp.resource}`);
      else if (deps.isAttestationRevoked && (await deps.isAttestationRevoked(a.payload.jti))) fail("attestation_token", "Attestation revoked", "attestation_invalid:revoked", undefined, [a.payload.jti]);
      else { attState.valid = true; attState.jti = a.payload.jti; attState.expires_in = a.expires_in; reasons.push("attestation_valid"); ev.push({ step: "attestation_token", status: "pass", title: `Authorization attestation valid (expires in ${a.expires_in}s)`, detail: `issued by ${a.payload.iss} for ${a.payload.atp.action}${a.payload.atp.human_approval?.approved ? " · human-approved" : ""}`, refs: [a.payload.jti] }); }
    }
  }

  // 5. principal
  principal = agent.owner_principal_id ? await deps.getPrincipal(agent.owner_principal_id) : null;
  if (principal) ev.push({ step: "principal", status: "pass", title: `Principal binding active (${principal.display_name})`, refs: [principal.id] });
  else { ev.push({ step: "principal", status: "warn", title: "No delegating principal", detail: "Authority is not bound to a human or service owner." }); reasons.push("principal_unbound"); }

  // 6–8. delegation chain → effective authority
  leaf = await deps.getLeafDelegation(agent.id, req.delegation_id);
  if (leaf) {
    const anc = await deps.getDelegationAncestry(leaf.id);
    const byId = new Map(anc.map((d) => [d.id, d]));
    const chain = resolveChain(leaf.id, (id) => byId.get(id));
    if (!chain.ok) fail("delegation", `Delegation chain ${chain.reason}`, `delegation_chain_${chain.reason}`, `at ${chain.at}`, [leaf.id]);
    else {
      chainIds = chain.chain.map((d) => d.id);
      effective = computeEffectiveAuthority(chain.chain, now);
      const badLink = chain.chain.find((d) => d.status !== "active" || (d.not_after && Date.parse(d.not_after) <= t) || (d.not_before && Date.parse(d.not_before) > t));
      if (badLink) fail("delegation", `Delegation ${badLink.status === "active" ? "outside validity window" : badLink.status}`, `delegation_${badLink.status === "active" ? "expired" : badLink.status}`, undefined, [badLink.id]);
      else { delegationValid = true; ev.push({ step: "delegation", status: "pass", title: `Delegation chain valid (${chain.chain.length} link${chain.chain.length > 1 ? "s" : ""})`, refs: chainIds }); }
    }
  } else {
    effective = await deps.getAgentCapabilities(agent.id);
    ev.push({ step: "delegation", status: "warn", title: "No delegation — using directly assigned capabilities", refs: [agent.id] });
    reasons.push("no_delegation");
  }

  // 9. capability + constraints
  const requested = { action: req.action, resource: req.resource ?? "*", constraints: undefined };
  const covering = effective.filter((c) => c.action === req.action && (req.resource === undefined || capabilityCovered({ ...c, constraints: undefined }, requested)));
  if (covering.length === 0) fail("capability", `Capability ${req.action} not granted`, "capability_missing", req.resource ? `for ${req.resource}` : undefined);
  else {
    const reqConstraints: Record<string, unknown> = {};
    if (req.amount !== undefined) reqConstraints.max_value = req.amount;
    if (req.currency) reqConstraints.currency = req.currency;
    const region = typeof req.context?.region === "string" ? req.context.region : undefined;
    if (region) reqConstraints.region = [region];
    const within = covering.find((c) => constraintsTighter(c.constraints, { ...c.constraints, ...reqConstraints }));
    if (!within) {
      const lim = covering[0].constraints;
      fail("constraints", "Request exceeds capability constraints", "constraint_violated", lim ? Object.entries(lim).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("|") : String(v)}`).join(", ") : undefined);
    } else { authorized = true; ev.push({ step: "capability", status: "pass", title: `Capability ${req.action} granted`, detail: within.resource }); ev.push({ step: "constraints", status: "pass", title: "Constraints satisfied", detail: within.constraints ? Object.entries(within.constraints).map(([k, v]) => `${k} ${Array.isArray(v) ? v.join("|") : String(v)}`).join(" · ") : "none" }); }
  }

  // 10. revocation
  revoked = (await deps.isRevoked("agent", agent.id)) || (cred ? await deps.isRevoked("credential", cred.id) : false) || (leaf ? await deps.isRevoked("delegation", leaf.id) : false);
  if (revoked) fail("revocation", "Subject is revoked", "revoked", undefined, [agent.id]);
  else ev.push({ step: "revocation", status: "pass", title: "Revocation checked — none found" });

  // 11. attestation (evidence only in v0.1)
  const atts = (await deps.getAttestations(agent.id)).filter((a) => a.verified && (!a.expires_at || Date.parse(a.expires_at) > t));
  if (atts.length) ev.push({ step: "attestation", status: "pass", title: `Runtime attested (${atts.map((a) => a.kind).join(", ")})`, refs: atts.map((a) => a.id) });
  else ev.push({ step: "attestation", status: "skipped", title: "No runtime attestation", detail: "Not required by policy." });

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
    ev.push({ step: "policy", status: out.effect === "allow" ? "pass" : out.effect === "deny" ? "fail" : "warn", title: out.effect === "allow" ? "Policy allows" : out.effect === "deny" ? "Policy denies" : "Policy requires human approval", detail: out.fired.length ? `fired: ${out.fired.join(", ")}` : "no rule fired", refs: pol.version_id ? [pol.version_id] : undefined });
    if (out.effect === "deny") hardFail = true;
  } else ev.push({ step: "policy", status: "skipped", title: "No active policy" });

  // 13. decide
  const decision: Decision = hardFail ? "DENY" : policyEffect === "require_approval" ? "REQUIRE_APPROVAL" : "ALLOW";
  if (decision === "ALLOW") reasons.unshift("identity_verified", "authority_valid");
  return finish(decision);

  function finish(decision: Decision): VerifyResult {
    return {
      decision, reasons: [...new Set(reasons)], evidence: ev,
      agent: agent ? { id: agent.id, verified: agent.lifecycle === "active" } : null,
      principal: principal ? { id: principal.id, verified: true } : null,
      delegation: { valid: delegationValid, chain_length: chainIds.length, chain: chainIds },
      authorization: { capability: req.action, valid: authorized },
      revocation: { checked: true, valid: !revoked },
      policy_version: pol?.version_id ?? null, policy_hash: pol?.hash ?? null,
      proof: proofState, attestation: attState,
    };
  }
}

import { describe, it, expect } from "vitest";
import { resourceContains } from "../src/delegation/attenuate";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { verifyDelegationChain, verifyRequestProof, verifyAttestation, verifyApprovalJwt, verify, type VerifierDeps, type AgentInfo, type CredentialInfo, type PrincipalInfo, type AttestationInfo, type ActivePolicy } from "../src/index";
import type { Delegation, CapSet, VerifyRequest } from "../src/types";

interface CryptoVector { id: string; level: number; title: string; now: string; keys: Record<string, Record<string, JsonWebKey>>; case?: Record<string, unknown> & { kind: string }; world?: { agent: AgentInfo | null; credential: CredentialInfo | null; principals: PrincipalInfo[]; delegations: Delegation[]; capabilities: CapSet; revoked: string[]; attestations: AttestationInfo[]; policy: ActivePolicy | null; peers?: { entity_id: string; name: string; trust_level: 1 | 2; stale_ok_seconds?: number }[]; consumed?: string[]; peer_status?: Record<string, "active" | "revoked" | "unreachable"> }; request_hash?: string; audience?: string; request?: VerifyRequest; expect: Record<string, unknown> }

const dir = join(process.cwd(), "conformance", "crypto");
const vectors: CryptoVector[] = readdirSync(dir).filter((f) => f.endsWith(".json")).sort().map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")));
/** v0.2 single-use: a consumption store pre-seeded with the vector's `consumed` jtis. */
const consumeStore = (seed: string[]) => { const seen = new Set(seed); return async (jti: string) => { if (seen.has(jti)) return "seen" as const; seen.add(jti); return "first" as const; }; };
const resolver = (keys: CryptoVector["keys"]) => async (kid: string, iss: string) => keys[iss]?.[kid] ?? null;

describe("conformance levels 2–3 (signed objects, federation)", () => {
  it("has the reference set", () => { expect(vectors.filter((v) => v.level === 2).length).toBeGreaterThanOrEqual(12); expect(vectors.filter((v) => v.level === 3).length).toBeGreaterThanOrEqual(5); });
  for (const v of vectors) {
    it(`${v.id} ${v.title}`, async () => {
      const now = new Date(v.now); const e = v.expect;
      if (v.case?.kind === "delegation_chain") { const r = await verifyDelegationChain(v.case.tokens as string[], resolver(v.keys), now); expect(r.ok).toBe(e.ok); if (r.ok) { expect(r.chain).toEqual(e.chain); expect(r.subject).toBe(e.subject); expect(r.effective).toEqual(e.effective); } else { expect(r).toMatchObject({ at: e.at, reason: e.reason }); } return; }
      if (v.case?.kind === "request_proof") { const c = v.case as unknown as { proof: string; agent_keys: Record<string, JsonWebKey>; htm: string; htu: string; body_hash: string }; const r = await verifyRequestProof({ proof: c.proof, resolveKey: async (kid) => (kid ? c.agent_keys[kid] ?? null : null), htm: c.htm, htu: c.htu, bodyHash: c.body_hash, now }); expect(r.ok).toBe(e.ok); if (r.ok) { expect(r.claims.iss).toBe(e.iss); expect(r.alg).toBe(e.alg); } else expect(r.reason).toBe(e.reason); return; }
      if (v.case?.kind === "approval") { const r = await verifyApprovalJwt(v.case.token as string, resolver(v.keys), now); expect(r.ok).toBe(e.ok); if (r.ok) { expect(r.header.kid).toBe(e.kid); expect(r.payload.jti).toBe(e.jti); expect(r.payload.atp.status).toBe(e.status); expect(r.payload.atp.device ?? null).toBe(e.device ?? null); expect(r.payload.atp.device_proof_hash ?? null).toBe(e.device_proof_hash ?? null); } else expect(r.reason).toBe(e.reason); return; }
      if (v.case?.kind === "attestation") { const r = await verifyAttestation(v.case.token as string, resolver(v.keys), now); expect(r.ok).toBe(e.ok); if (r.ok) { expect(r.payload.sub).toBe(e.sub); expect(r.payload.atp.action).toBe(e.action); expect(r.expires_in).toBe(e.expires_in); if (e.use !== undefined) expect(r.payload.atp.use).toBe(e.use); } else expect(r.reason).toBe(e.reason); return; }
      // level 3: full pipeline with peers
      const w = v.world!; const revoked = new Set(w.revoked);
      const deps: VerifierDeps = {
        getAgent: async (ref) => (w.agent && (ref === w.agent.id || ref === w.agent.stable_id) ? w.agent : null),
        getActiveCredential: async () => w.credential, getPrincipal: async (id) => w.principals.find((p) => p.id === id) ?? null,
        getLeafDelegation: async (agentId, delegationId) => w.delegations.find((d) => (delegationId ? d.id === delegationId : d.subject_agent_id === agentId)) ?? null,
        getDelegationAncestry: async () => w.delegations, getAgentCapabilities: async () => w.capabilities,
    getCoveringDelegation: async (agentId, action, resource) => w.delegations.find((d) => d.subject_agent_id === agentId && d.status === "active" && d.capabilities.some((c) => c.action === action && (!resource || resourceContains(c.resource, resource)))) ?? null,
 isRevoked: async (_t, id) => revoked.has(id), getAttestations: async () => w.attestations, getPolicy: async () => w.policy,
        ...(w.consumed ? { consumeAttestation: consumeStore(w.consumed) } : {}),
        ...(w.peer_status ? { peerAttestationStatus: async (_iss: string, jti: string) => w.peer_status![jti] ?? "active" } : {}),
        getOrgKey: resolver(v.keys), getFederatedIssuer: async (iss) => { const p = (w.peers ?? []).find((x) => x.entity_id === iss); return p ? { name: p.name, trust_level: p.trust_level, stale_ok_seconds: p.stale_ok_seconds } : null; },
      };
      const r = await verify(v.request!, deps, { now, requestHash: v.request_hash, audience: v.audience });
      expect(r.decision).toBe(e.decision);
      for (const reason of (e.reasons_include as string[]) ?? []) expect(r.reasons).toContain(reason);
      for (const [step, status] of Object.entries((e.evidence as Record<string, string>) ?? {})) expect(r.evidence.find((x) => x.step === step)?.status, `${v.id} step ${step}`).toBe(status);
    });
  }
});

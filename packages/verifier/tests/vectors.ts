/** Shared harness: every pipeline-level conformance vector (levels 1 and 3) run through verify(). Not a test file. */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { verify, type VerifierDeps, type AgentInfo, type CredentialInfo, type PrincipalInfo, type AttestationInfo, type ActivePolicy, type EvidenceItem } from "../src/pipeline";
import type { Delegation, CapSet, VerifyRequest } from "../src/types";
import { resourceContains } from "../src/delegation/attenuate";

interface World { agent: AgentInfo | null; credential: CredentialInfo | null; principals: PrincipalInfo[]; delegations: Delegation[]; capabilities: CapSet; revoked: string[]; attestations: AttestationInfo[]; policy: ActivePolicy | null; peers?: { entity_id: string; name: string; trust_level: 1 | 2; stale_ok_seconds?: number }[]; consumed?: string[]; peer_status?: Record<string, "active" | "revoked" | "unreachable"> }
interface Vector { id: string; now: string; world?: World; request?: VerifyRequest; keys?: Record<string, Record<string, JsonWebKey>>; request_hash?: string; audience?: string }

/** The in-memory world of a vector (levels 1 and 3), as in conformance.test.ts / conformance.crypto.test.ts. */
export function depsFrom(w: World, keys?: Vector["keys"]): VerifierDeps {
  const revoked = new Set(w.revoked);
  return {
    getAgent: async (ref) => (w.agent && (ref === w.agent.id || ref === w.agent.stable_id) ? w.agent : null),
    getActiveCredential: async () => w.credential,
    getPrincipal: async (id) => w.principals.find((p) => p.id === id) ?? null,
    getLeafDelegation: async (agentId, delegationId) => w.delegations.find((d) => (delegationId ? d.id === delegationId : d.subject_agent_id === agentId && d.parent_id !== null)) ?? w.delegations.find((d) => d.subject_agent_id === agentId) ?? null,
    getDelegationAncestry: async () => w.delegations,
    getAgentCapabilities: async () => w.capabilities,
    getCoveringDelegation: async (agentId, action, resource) => w.delegations.find((d) => d.subject_agent_id === agentId && d.status === "active" && d.capabilities.some((c) => c.action === action && (!resource || resourceContains(c.resource, resource)))) ?? null,
    isRevoked: async (_t, id) => revoked.has(id),
    getAttestations: async () => w.attestations,
    getPolicy: async () => w.policy,
    ...(w.consumed ? { consumeAttestation: (() => { const seen = new Set(w.consumed); return async (jti: string) => { if (seen.has(jti)) return "seen" as const; seen.add(jti); return "first" as const; }; })() } : {}),
    ...(keys ? {
      getOrgKey: async (kid: string, iss: string) => keys[iss]?.[kid] ?? null,
      getFederatedIssuer: async (iss: string) => { const p = (w.peers ?? []).find((x) => x.entity_id === iss); return p ? { name: p.name, trust_level: p.trust_level, stale_ok_seconds: p.stale_ok_seconds } : null; },
      ...(w.peer_status ? { peerAttestationStatus: async (_iss: string, jti: string) => w.peer_status![jti] ?? "active" } : {}),
    } : {}),
  };
}

/** Every pipeline-level vector (conformance/vectors + the level-3 crypto vectors), run through verify(). */
export async function evidenceFromVectors(): Promise<{ id: string; evidence: EvidenceItem[] }[]> {
  const out: { id: string; evidence: EvidenceItem[] }[] = [];
  for (const sub of ["vectors", "crypto"]) {
    const dir = join(process.cwd(), "conformance", sub);
    for (const f of readdirSync(dir).filter((x) => x.endsWith(".json")).sort()) {
      const v: Vector = JSON.parse(readFileSync(join(dir, f), "utf8"));
      if (!v.world || !v.request) continue;
      const r = await verify(v.request, depsFrom(v.world, v.keys), { now: new Date(v.now), requestHash: v.request_hash, audience: v.audience });
      out.push({ id: v.id, evidence: r.evidence });
    }
  }
  return out;
}

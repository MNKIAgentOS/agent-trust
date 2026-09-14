import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { verify, type VerifierDeps, type AgentInfo, type CredentialInfo, type PrincipalInfo, type AttestationInfo, type ActivePolicy } from "../src/pipeline";
import type { Delegation, CapSet, VerifyRequest } from "../src/types";

interface Vector { id: string; title: string; now: string; world: { agent: AgentInfo | null; credential: CredentialInfo | null; principals: PrincipalInfo[]; delegations: Delegation[]; capabilities: CapSet; revoked: string[]; attestations: AttestationInfo[]; policy: ActivePolicy | null }; request: VerifyRequest; expect: { decision: string; reasons_include?: string[]; reasons_exact?: string[]; evidence?: Record<string, string> } }

/** The same in-memory world any implementation builds from a vector. */
function depsFrom(w: Vector["world"]): VerifierDeps {
  const revoked = new Set(w.revoked);
  return {
    getAgent: async (ref) => (w.agent && (ref === w.agent.id || ref === w.agent.stable_id) ? w.agent : null),
    getActiveCredential: async () => w.credential,
    getPrincipal: async (id) => w.principals.find((p) => p.id === id) ?? null,
    getLeafDelegation: async (agentId, delegationId) => w.delegations.find((d) => (delegationId ? d.id === delegationId : d.subject_agent_id === agentId && d.parent_id !== null)) ?? w.delegations.find((d) => d.subject_agent_id === agentId) ?? null,
    getDelegationAncestry: async () => w.delegations,
    getAgentCapabilities: async () => w.capabilities,
    isRevoked: async (_t, id) => revoked.has(id),
    getAttestations: async () => w.attestations,
    getPolicy: async () => w.policy,
  };
}

const dir = join(process.cwd(), "conformance", "vectors");
const vectors: Vector[] = readdirSync(dir).filter((f) => f.endsWith(".json")).sort().map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")));

describe("conformance vectors", () => {
  it("has at least the reference set", () => expect(vectors.length).toBeGreaterThanOrEqual(14));
  for (const v of vectors) {
    it(`${v.id} ${v.title}`, async () => {
      const r = await verify(v.request, depsFrom(v.world), { now: new Date(v.now) });
      expect(r.decision).toBe(v.expect.decision);
      for (const reason of v.expect.reasons_include ?? []) expect(r.reasons).toContain(reason);
      if (v.expect.reasons_exact) expect(r.reasons).toEqual(v.expect.reasons_exact);
      for (const [step, status] of Object.entries(v.expect.evidence ?? {})) expect(r.evidence.find((e) => e.step === step)?.status, `${v.id} step ${step}`).toBe(status);
    });
  }
});

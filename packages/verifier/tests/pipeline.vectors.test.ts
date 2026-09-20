import { describe, it, expect } from "vitest";
import { verify, type VerifierDeps, type AgentInfo } from "../src/pipeline";
import type { Delegation } from "../src/types";
import type { PolicyDoc } from "../src/policy/schema";

// In-memory world — the shape of the future conformance/vectors/*.json fixtures.
const NOW = new Date("2026-09-14T12:00:00Z");
const POLICY: PolicyDoc = { version: 1, rules: [
  { id: "procurement-approval", match: { action: "purchase.create" }, conditions: [{ kind: "amount_gt", value: 3000 }], effect: "require_approval" },
  { id: "prod-namespace-delete", match: { action: "k8s.delete_namespace" }, effect: "require_approval" },
  { id: "critical-needs-attestation", match: { risk_tier: ["critical"] }, conditions: [{ kind: "requires_attestation" }], effect: "allow" },
  { id: "no-refunds-out-of-hours", match: { action: "stripe.refund" }, conditions: [{ kind: "time_window", start: "18:00", end: "08:00" }], effect: "deny" },
] };
function world(over: Partial<{ agent: Partial<AgentInfo>; cred: { status: string; not_after: string | null } | null; delegations: Delegation[]; revoked: string[]; policy: PolicyDoc | null; caps: { action: string; resource: string; constraints?: Record<string, unknown> }[] }> = {}): VerifierDeps {
  const agent: AgentInfo = { id: "agt_1", stable_id: "spiffe://acme/agent/procurement-7821", lifecycle: "active", risk_tier: "low", owner_principal_id: "prn_1", labels: { department: "Finance" }, ...over.agent };
  const dels = over.delegations ?? [
    { id: "dlg_root", parent_id: null, subject_agent_id: "agt_1", status: "active", not_after: "2027-01-01T00:00:00Z", capabilities: [{ action: "purchase.create", resource: "supplier:*", constraints: { max_value: 5000, currency: "EUR", region: ["EU"] } }, { action: "supplier.search", resource: "supplier:*" }] },
  ];
  const revoked = new Set(over.revoked ?? []);
  return {
    getAgent: async (ref) => (ref === agent.id || ref === agent.stable_id ? agent : null),
    getActiveCredential: async () => (over.cred === null ? null : { id: "crd_1", kind: "jwt_svid", status: "active", not_after: "2027-03-15T00:00:00Z", ...over.cred }),
    getPrincipal: async (id) => (id === "prn_1" ? { id, display_name: "Maria Chen", kind: "user" } : null),
    getLeafDelegation: async (agentId, delegationId) => dels.find((d) => (delegationId ? d.id === delegationId : d.subject_agent_id === agentId && d.parent_id !== null)) ?? dels.find((d) => d.subject_agent_id === agentId) ?? null,
    getDelegationAncestry: async () => dels,
    getAgentCapabilities: async () => over.caps ?? [],
    isRevoked: async (_t, id) => revoked.has(id),
    getAttestations: async () => [],
    getPolicy: async () => (over.policy === null ? null : { version_id: "pv_17", hash: "h17", doc: over.policy ?? POLICY }),
  };
}
const req = (amount?: number, action = "purchase.create", resource = "supplier:123") => ({ agent: "agt_1", action, resource, amount, currency: amount ? "EUR" : undefined, context: { region: "EU" } });
const step = (r: Awaited<ReturnType<typeof verify>>, s: string) => r.evidence.find((e) => e.step === s)?.status;

describe("verify() vectors", () => {
  it("V00 trusted-issuer dep: untrusted credential issuer fails step 4, trusted passes, absent dep is ignored", async () => {
    const w = world(); const cred = { id: "crd_1", kind: "jwt_svid", status: "active", not_after: "2027-03-15T00:00:00Z", issuer: "internal-ca.acme.corp" };
    const deps = { ...w, getActiveCredential: async () => cred, isTrustedIssuer: async (i: string | null) => i === "spiffe://acme.corp" };
    const denied = await verify(req(2450), deps, { now: NOW });
    expect(denied.decision).toBe("DENY"); expect(denied.reasons).toContain("credential_issuer_untrusted"); expect(step(denied, "credential")).toBe("fail");
    const ok = await verify(req(2450), { ...deps, isTrustedIssuer: async () => true }, { now: NOW });
    expect(ok.decision).toBe("ALLOW");
    expect((await verify(req(2450), { ...w, getActiveCredential: async () => cred }, { now: NOW })).decision).toBe("ALLOW");
  });
  it("V01 happy path: ALLOW with every step passing", async () => {
    const r = await verify(req(2450), world(), { now: NOW });
    expect(r.decision).toBe("ALLOW");
    expect(r.evidence.map((e) => [e.step, e.status])).toEqual([["request", "pass"], ["identity", "pass"], ["credential", "pass"], ["proof", "warn"], ["principal", "pass"], ["delegation", "pass"], ["capability", "pass"], ["constraints", "pass"], ["revocation", "pass"], ["attestation", "skipped"], ["enforcement", "warn"], ["policy", "pass"]]);
    expect(r.reasons).toContain("identity_verified"); expect(r.delegation).toMatchObject({ valid: true, chain_length: 1 }); expect(r.policy_version).toBe("pv_17");
  });
  it("V02 amount above approval threshold: REQUIRE_APPROVAL, everything else passes", async () => {
    const r = await verify(req(3200), world(), { now: NOW });
    expect(r.decision).toBe("REQUIRE_APPROVAL"); expect(step(r, "policy")).toBe("warn"); expect(r.reasons).toContain("policy:procurement-approval:require_approval");
  });
  it("V03 amount above capability limit: DENY on constraints (policy never reached as allow)", async () => {
    const r = await verify(req(9000), world(), { now: NOW });
    expect(r.decision).toBe("DENY"); expect(step(r, "constraints")).toBe("fail"); expect(r.reasons).toContain("constraint_violated");
  });
  it("V04 unknown agent: DENY immediately", async () => {
    const r = await verify({ ...req(100), agent: "agt_ghost" }, world(), { now: NOW });
    expect(r.decision).toBe("DENY"); expect(r.reasons).toEqual(["agent_unknown"]); expect(r.agent).toBeNull();
  });
  it("V05 suspended agent: DENY with identity failing", async () => {
    const r = await verify(req(100), world({ agent: { lifecycle: "suspended" } }), { now: NOW });
    expect(r.decision).toBe("DENY"); expect(step(r, "identity")).toBe("fail"); expect(r.reasons).toContain("agent_suspended");
  });
  it("V06 capability not granted: DENY", async () => {
    const r = await verify(req(undefined, "vault.read_secret", "vault:secret/db"), world(), { now: NOW });
    expect(r.decision).toBe("DENY"); expect(r.reasons).toContain("capability_missing");
  });
  it("V07 expired credential: DENY", async () => {
    const r = await verify(req(100), world({ cred: { status: "active", not_after: "2026-01-01T00:00:00Z" } }), { now: NOW });
    expect(r.decision).toBe("DENY"); expect(r.reasons).toContain("credential_expired");
  });
  it("V08 revoked delegation: DENY on revocation", async () => {
    const r = await verify(req(100), world({ revoked: ["dlg_root"] }), { now: NOW });
    expect(r.decision).toBe("DENY"); expect(step(r, "revocation")).toBe("fail"); expect(r.revocation.valid).toBe(false);
  });
  it("V09 expired delegation link: DENY", async () => {
    const r = await verify(req(100), world({ delegations: [{ id: "dlg_root", parent_id: null, subject_agent_id: "agt_1", status: "active", not_after: "2026-09-01T00:00:00Z", capabilities: [{ action: "purchase.create", resource: "supplier:*" }] }] }), { now: NOW });
    expect(r.decision).toBe("DENY"); expect(r.reasons).toContain("delegation_expired");
  });
  it("V10 attenuated chain: child cannot exceed parent even if its own grant says so", async () => {
    const chain: Delegation[] = [
      { id: "root", parent_id: null, subject_agent_id: "agt_parent", status: "active", capabilities: [{ action: "purchase.create", resource: "supplier:*", constraints: { max_value: 1000 } }] },
      { id: "leaf", parent_id: "root", subject_agent_id: "agt_1", status: "active", capabilities: [{ action: "purchase.create", resource: "supplier:*", constraints: { max_value: 5000 } }] },
    ];
    const r = await verify(req(2000), world({ delegations: chain, policy: null }), { now: NOW });
    expect(r.decision).toBe("DENY"); expect(r.reasons).toContain("capability_missing"); expect(r.delegation.chain).toEqual(["root", "leaf"]);
  });
  it("V11 no delegation: falls back to direct capabilities with a warning", async () => {
    const r = await verify(req(500), world({ delegations: [], caps: [{ action: "purchase.create", resource: "supplier:*", constraints: { max_value: 1000 } }] }), { now: NOW });
    expect(r.decision).toBe("ALLOW"); expect(step(r, "delegation")).toBe("warn"); expect(r.reasons).toContain("no_delegation");
  });
  it("V12 unbound principal is a warning, not a denial", async () => {
    const r = await verify(req(100), world({ agent: { owner_principal_id: null } }), { now: NOW });
    expect(r.decision).toBe("ALLOW"); expect(step(r, "principal")).toBe("warn"); expect(r.principal).toBeNull();
  });
  it("V13 policy deny wins over an otherwise valid request (out-of-hours refund)", async () => {
    const w = world({ delegations: [{ id: "d", parent_id: null, subject_agent_id: "agt_1", status: "active", capabilities: [{ action: "stripe.refund", resource: "stripe:*" }] }] });
    expect((await verify(req(undefined, "stripe.refund", "stripe:r_1"), w, { now: new Date("2026-09-14T22:00:00Z") })).decision).toBe("DENY");
    expect((await verify(req(undefined, "stripe.refund", "stripe:r_1"), w, { now: new Date("2026-09-14T10:00:00Z") })).decision).toBe("ALLOW");
  });
  it("V14 is deterministic", async () => {
    const a = await verify(req(3200), world(), { now: NOW }); const b = await verify(req(3200), world(), { now: NOW });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});

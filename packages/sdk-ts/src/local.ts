/**
 * Local mode: run the exact verifier the control plane runs, in-process, against a JSON "world" — the same
 * shape as the conformance vectors (`conformance/vectors/*.json` → `world`). No account, no network.
 * `demoWorld()` is the 15-second story: an invoice agent may spend up to €5,000; €47,000 is denied, €420
 * allowed, and anything above €3,000 needs a human.
 */
import { verify, parseVerifyRequest, resourceContains, type VerifierDeps, type VerifyResult, type VerifyRequest, type Delegation, type CapSet } from "mnki-verifier";
import type { AgentInfo, CredentialInfo, PrincipalInfo, AttestationInfo, ActivePolicy } from "mnki-verifier";

export interface LocalWorld {
  agent: AgentInfo | null;
  /** Extra names the agent answers to (the hosted verifier also resolves by name). */
  agentAliases?: string[];
  credential?: CredentialInfo | null;
  principals?: PrincipalInfo[];
  delegations?: Delegation[];
  capabilities?: CapSet;
  revoked?: string[];
  attestations?: AttestationInfo[];
  policy?: ActivePolicy | null;
  /** Organization keys by issuer then kid, for delegation credentials / attestations presented offline. */
  keys?: Record<string, Record<string, JsonWebKey>>;
  peers?: { entity_id: string; name: string; trust_level: 1 | 2 }[];
  /** Optional lifetime budgets already spent: `${authorityId}|${action}|${currency}` → amount. */
  spent?: Record<string, number>;
}

/** Build verifier dependencies from a world object (pure, synchronous data). */
export function depsFromWorld(w: LocalWorld): VerifierDeps {
  const revoked = new Set(w.revoked ?? []); const dels = w.delegations ?? [];
  return {
    getAgent: async (ref) => (w.agent && (ref === w.agent.id || ref === w.agent.stable_id || (w.agentAliases ?? []).includes(ref)) ? w.agent : null),
    getActiveCredential: async () => w.credential ?? null,
    getPrincipal: async (id) => (w.principals ?? []).find((p) => p.id === id) ?? null,
    getLeafDelegation: async (agentId, delegationId) => (dels.find((d) => (delegationId ? d.id === delegationId : d.subject_agent_id === agentId && d.parent_id !== null)) ?? dels.find((d) => d.subject_agent_id === agentId)) ?? null,
    // §17: among the agent's active delegations, the one whose authority covers the action and resource.
    getCoveringDelegation: async (agentId, action, resource) => dels.find((d) => d.subject_agent_id === agentId && d.status === "active" && d.capabilities.some((c) => c.action === action && (!resource || resourceContains(c.resource, resource)))) ?? null,
    getDelegationAncestry: async () => dels,
    getAgentCapabilities: async () => w.capabilities ?? [],
    isRevoked: async (_t, id) => revoked.has(id),
    getAttestations: async () => w.attestations ?? [],
    getPolicy: async () => w.policy ?? null,
    getOrgKey: async (kid, iss) => w.keys?.[iss]?.[kid] ?? null,
    getFederatedIssuer: async (iss) => { const p = (w.peers ?? []).find((x) => x.entity_id === iss); return p ? { name: p.name, trust_level: p.trust_level } : null; },
    ...(w.spent ? { spentSoFar: async (authorityId: string, action: string, currency: string) => w.spent?.[`${authorityId}|${action}|${currency}`] ?? 0 } : {}),
  } as VerifierDeps;
}

export type LocalVerifyResult = { ok: true; result: VerifyResult } | { ok: false; code: string };
/** Verify a request against a world, exactly as the hosted verify endpoint would (minus the ledger). */
export async function localVerify(world: LocalWorld, req: unknown, now = new Date()): Promise<LocalVerifyResult> {
  const parsed = parseVerifyRequest(req); if (!parsed.ok) return { ok: false, code: `invalid_${parsed.code}` };
  return { ok: true, result: await verify(parsed.request as VerifyRequest, depsFromWorld(world), { now }) };
}

/** The demo world: Accounts Receivable delegates `refund.create` up to €5,000 to invoice-agent; refunds above €3,000 need approval. */
export function demoWorld(now = new Date()): LocalWorld {
  const y = new Date(now.getTime() + 365 * 86400000).toISOString();
  return {
    agent: { id: "agt_invoice", stable_id: "spiffe://acme.example/agent/invoice-agent", lifecycle: "active", risk_tier: "medium", owner_principal_id: "prn_ar", labels: { department: "Finance", framework: "openai-agents" } },
    agentAliases: ["invoice-agent"],
    credential: { id: "crd_invoice", kind: "jwt_svid", status: "active", not_after: y, issuer: "internal-ca.acme.example" },
    principals: [{ id: "prn_ar", display_name: "Accounts Receivable", kind: "team" }],
    delegations: [{ id: "dlg_ar_invoice", parent_id: null, subject_agent_id: "agt_invoice", status: "active", not_after: y, capabilities: [
      { action: "refund.create", resource: "customer:*", constraints: { max_value: 5000, currency: "EUR" } },
      { action: "invoice.read", resource: "invoice:*" }, { action: "crm.read", resource: "crm:*" },
    ] }],
    capabilities: [], revoked: [], attestations: [],
    policy: { version_id: "pv_demo", hash: "demo", doc: { version: 1, rules: [
      { id: "large-refunds-need-a-human", description: "Refunds above €3,000 require approval", match: { action: "refund.create" }, conditions: [{ kind: "amount_gt", value: 3000 }], effect: "require_approval" },
      { id: "no-database-writes", description: "Agents never write to the database directly", match: { action: "database.write" }, effect: "deny" },
    ] } },
  };
}

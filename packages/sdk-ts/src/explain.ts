/**
 * Turn a decision (hosted or local) into the six answers a developer asks: which rule matched, which
 * principal, which delegation limited it, which capability was missing, which condition failed, and what
 * would change the outcome. Pure: derived from `reasons` and the evidence steps, no network.
 */
import type { Evidence } from "./index";

export interface DecisionLike { decision: string; reasons: string[]; evidence: Evidence[]; authorization?: { capability?: string; remaining_limit?: number | null } | null; principal?: { id: string } | null; delegation?: { chain?: string[]; chain_length?: number } | null }
export interface Explanation {
  decision: string;
  matched_rule: { id: string; effect: string } | null;
  principal: string | null;
  limiting_delegation: string | null;
  missing_capability: string | null;
  failing_condition: string | null;
  blocking_step: string | null;
  what_would_change: string[];
  summary: string;
}

const step = (d: DecisionLike, s: string) => d.evidence.find((e) => e.step === s);
export function explain(d: DecisionLike): Explanation {
  const reasons = d.reasons ?? [];
  const policy = reasons.map((r) => /^policy:([^:]+):(allow|deny|require_approval)$/.exec(r)).find(Boolean);
  const matched_rule = policy ? { id: policy[1], effect: policy[2] } : null;
  const capStep = step(d, "capability"), conStep = step(d, "constraints"), delStep = step(d, "delegation");
  // Prefer the machine-readable `params` (servers that set `code`); fall back to parsing the English title for older servers.
  const missing_capability = reasons.includes("capability_missing") ? (typeof capStep?.params?.action === "string" && capStep.code ? capStep.params.action : capStep?.title.replace(/^Capability /, "").replace(/ not granted$/, "") ?? "capability") : null;
  const failing_condition = reasons.includes("constraint_violated") || reasons.includes("budget_exceeded") ? (conStep?.code === "constraints.violated" && typeof conStep.params?.limits === "string" ? conStep.params.limits : conStep?.code === "constraints.budget_exhausted" && conStep.params && typeof conStep.params.spent === "number" ? `${conStep.params.spent} of ${conStep.params.total} ${conStep.params.currency ?? ""} already spent; ${conStep.params.left} left`.trim() : conStep?.detail ?? conStep?.title ?? "constraint") : null;
  const limiting_delegation = (conStep?.refs?.[0] ?? delStep?.refs?.[0]) ?? (d.delegation?.chain?.length ? d.delegation.chain[d.delegation.chain.length - 1] : null);
  const failing = d.evidence.find((e) => e.status === "fail"); const blocking_step = failing?.step ?? (d.decision === "REQUIRE_APPROVAL" ? "policy" : null);
  const what: string[] = [];
  for (const r of reasons) {
    if (r === "agent_unknown") what.push("Register the agent (mnki identity create) or use its id / stable id.");
    else if (/^agent_(pending|suspended|revoked|retired)$/.test(r)) what.push(`The agent is ${r.slice(6)}; an admin must ${r === "agent_pending" ? "activate it" : "restore it"}.`);
    else if (r === "credential_missing" || r === "credential_expired") what.push("Rotate the agent's credential (mnki identity create, or /v1/agents/{id}/rotate).");
    else if (r === "credential_issuer_untrusted") what.push("Add the credential's issuer as a trust anchor for the organisation.");
    else if (r === "request_unsigned") what.push("Sign requests with the agent key (Agent-Proof); required by this organisation.");
    else if (r.startsWith("proof_invalid")) what.push("Fix the request proof: same method, URL and body hash, fresh iat/jti, the agent's registered key.");
    else if (r === "principal_unbound") what.push("Bind the agent to a principal (owner) or issue a root delegation from one.");
    else if (r === "no_delegation") what.push("Issue a delegation to the agent covering this action, or grant a direct capability.");
    else if (r.startsWith("delegation_chain_") || r.startsWith("delegation_")) what.push("Repair the delegation chain: every link active, in its validity window, no wider than its parent.");
    else if (r === "capability_missing") what.push(`Grant the capability ${missing_capability ?? ""} (with the resource pattern) in the delegation.`.replace("  ", " "));
    else if (r === "constraint_violated") what.push("Lower the amount / change currency or region to within the capability constraints, or widen the delegation.");
    else if (r === "budget_exceeded") what.push("The lifetime budget (max_total) is spent; issue a new delegation with a fresh budget.");
    else if (r === "revoked") what.push("A revocation applies (agent, credential or delegation); lift it or issue new authority.");
    else if (r.startsWith("attestation_invalid")) what.push("Present a current attestation issued for this agent, action and resource.");
    else if (r === "federation_level_insufficient") what.push("Raise the peer organisation to trust level 2, or register the agent locally.");
  }
  if (matched_rule?.effect === "deny") what.push(`Change or remove policy rule "${matched_rule.id}", or change the request so it no longer matches.`);
  if (matched_rule?.effect === "require_approval") what.push(`Rule "${matched_rule.id}" escalates this: a human approves it, or the request stays under the rule's threshold.`);
  const summary = d.decision === "ALLOW" ? "Allowed: identity, authority, constraints and policy all passed." : d.decision === "REQUIRE_APPROVAL" ? `Needs a human: ${matched_rule ? `rule "${matched_rule.id}"` : "policy"} requires approval.` : `Denied at the ${blocking_step ?? "policy"} step: ${failing?.title ?? matched_rule?.id ?? reasons[0] ?? "policy"}.`;
  return { decision: d.decision, matched_rule, principal: d.principal?.id ?? step(d, "principal")?.refs?.[0] ?? null, limiting_delegation: limiting_delegation ?? null, missing_capability, failing_condition, blocking_step, what_would_change: [...new Set(what)], summary };
}

/**
 * Error taxonomy shared by the SDK, the guard, the adapters and the MCP proxy. `code` is stable and
 * machine-readable; `status` is the HTTP status when the control plane answered, 0 for local conditions.
 */
import type { Evidence } from "./index";

export type MnkiErrorCode =
  | "unauthenticated" | "invalid_api_key" | "insufficient_scope" | "rate_limited" | "quota_exceeded" | "org_suspended"
  | "agent_unknown" | "agent_pending" | "agent_suspended" | "agent_revoked" | "agent_retired"
  | "denied" | "approval_required" | "approval_rejected" | "approval_expired" | "approval_timeout"
  | "network" | "degraded" | "invalid_request" | "unknown";

export class MnkiError extends Error {
  constructor(public readonly code: MnkiErrorCode, message: string, public readonly status = 0, public readonly detail?: unknown) { super(message); this.name = "MnkiError"; }
}

/** The action was verified and refused. `evidence` is the ✓/⚠/✕ list (fail and warn rows first). */
export class Denied extends MnkiError {
  constructor(public readonly decision: { decision_id?: string; reasons: string[]; evidence: Evidence[]; decision: string }, message = `denied: ${decision.reasons.filter((r) => !r.endsWith("_verified") && r !== "authority_valid").join(", ") || "policy"}`) {
    super("denied", message, 403, decision); this.name = "Denied";
  }
  get reasons(): string[] { return this.decision.reasons; }
  get evidence(): Evidence[] { return [...this.decision.evidence].sort((a, b) => rank(a.status) - rank(b.status)); }
}
const rank = (s: Evidence["status"]) => (s === "fail" ? 0 : s === "warn" ? 1 : s === "pass" ? 2 : 3);

/** A human must decide; thrown when the guard is configured to `throw` or the wait ended without approval. */
export class ApprovalRequired extends MnkiError {
  constructor(public readonly approvalId: string | null, public readonly decisionId: string, public readonly approvalStatus: "pending" | "rejected" | "expired" | "timeout", public readonly reasons: string[] = []) {
    super(approvalStatus === "pending" ? "approval_required" : approvalStatus === "rejected" ? "approval_rejected" : approvalStatus === "expired" ? "approval_expired" : "approval_timeout", `approval ${approvalStatus}${approvalId ? ` (${approvalId})` : ""}`, 202, { approval_id: approvalId, decision_id: decisionId });
    this.name = "ApprovalRequired";
  }
}

/** Map a control-plane error (status + code) onto the taxonomy. */
export function fromApi(status: number, code: string, detail?: unknown): MnkiError {
  const known: Record<string, MnkiErrorCode> = { unauthenticated: "unauthenticated", invalid_api_key: "invalid_api_key", insufficient_scope: "insufficient_scope", rate_limited: "rate_limited", plan_limit_reached: "quota_exceeded", org_suspended: "org_suspended", invalid_agent: "invalid_request", invalid_action: "invalid_request", registry_unavailable: "degraded" };
  const m = /^agent_(pending|suspended|revoked|retired)$/.exec(code);
  const c: MnkiErrorCode = known[code] ?? (m ? (`agent_${m[1]}` as MnkiErrorCode) : code.startsWith("invalid_") ? "invalid_request" : status === 0 ? "network" : "unknown");
  return new MnkiError(c, `${code} (${status})`, status, detail);
}

/**
 * The verifier behind the proxy: the SDK guard in the chosen mode, mapping `tools/call` to Agent Trust
 * requests exactly like the hosted gateway (`mcp:tools/call:<tool>` on `mcp://<server>/tools/<tool>`, an
 * arguments hash in the context, amount/currency from the arguments with a per-tool override map).
 */
import { createGuard, Denied, ApprovalRequired, MnkiError, type AgentIdentity, type GuardMode, type GuardRecord, type VerifyInput } from "mnki-sdk";
import type { Verifier, VerifyOutcome } from "./proxy";

export const JSONRPC_APPROVAL_REQUIRED = -32001;
export const JSONRPC_DENIED = -32003;
export const JSONRPC_QUOTA_EXCEEDED = -32005;
export const JSONRPC_UNREACHABLE = -32006;

export interface VerifierOptions {
  baseUrl: string; apiKey: string; agent: string; server: string; mode: GuardMode; identity?: AgentIdentity;
  /** `tool → { amount: argName, currency: argName }` — which argument carries the spend. Defaults `amount|value` / `currency`. */
  amountMap?: Record<string, { amount?: string; currency?: string; resource?: string }>;
  approval?: { timeoutMs?: number; wait?: boolean };
  onDecision?: (r: GuardRecord) => void | Promise<void>;
  onError?: (kind: "unreachable" | "quota" | "error", detail: string) => void;
  fetch?: typeof fetch;
}
/** "create_payment=amount:currency,transfer=value:ccy,export=resource:path" → map */
export function parseAmountMap(spec: string | undefined): NonNullable<VerifierOptions["amountMap"]> {
  const out: NonNullable<VerifierOptions["amountMap"]> = {};
  for (const entry of (spec ?? "").split(",").map((s) => s.trim()).filter(Boolean)) {
    const [tool, rhs = ""] = entry.split("="); const [amount, currency] = rhs.split(":"); if (!tool) continue;
    out[tool.trim()] = { ...(amount ? { amount: amount.trim() } : {}), ...(currency ? { currency: currency.trim() } : {}) };
  }
  return out;
}

export function createVerifier(o: VerifierOptions): Verifier {
  const mapArgs = (tool: string, args: unknown): Partial<Pick<VerifyInput, "amount" | "currency" | "resource" | "context">> => {
    const a = (args ?? {}) as Record<string, unknown>; const m = o.amountMap?.[tool] ?? {};
    const amountRaw = m.amount ? a[m.amount] : (a.amount ?? a.value);
    const amount = typeof amountRaw === "number" ? amountRaw : typeof amountRaw === "string" && /^\d+(\.\d+)?$/.test(amountRaw) ? Number(amountRaw) : undefined;
    const curRaw = m.currency ? a[m.currency] : a.currency;
    const currency = typeof curRaw === "string" && /^[A-Z]{3}$/.test(curRaw) ? curRaw : undefined;
    return { ...(amount !== undefined ? { amount } : {}), ...(currency ? { currency } : {}), resource: `mcp://${o.server}/tools/${tool}`, context: { mcp: { server: o.server, tool, ...(m.resource && typeof a[m.resource] === "string" ? { target: a[m.resource] } : {}) }, effect_path: "none" } };   // §15: the agent process and the server share a machine; only the hosted gateway can claim custody
  };
  const guard = createGuard({ client: { baseUrl: o.baseUrl, apiKey: o.apiKey, fetch: o.fetch }, agent: o.agent, identity: o.identity, mode: o.mode, actionPrefix: "mcp:tools/call:", mapArgs, onApproval: o.approval?.wait === false ? "throw" : "wait", approval: { timeoutMs: o.approval?.timeoutMs }, onDecision: o.onDecision });
  return {
    mode: o.mode,
    async check(tool, args): Promise<VerifyOutcome> {
      try { await guard.check(tool, args); return { allowed: true }; }
      catch (e) {
        if (e instanceof Denied) return { allowed: false, error: { code: JSONRPC_DENIED, message: "denied by Agent Trust", data: { decision_id: e.decision.decision_id, reasons: e.reasons, evidence: e.evidence.filter((x) => x.status === "fail" || x.status === "warn") } } };
        if (e instanceof ApprovalRequired) return { allowed: false, error: { code: JSONRPC_APPROVAL_REQUIRED, message: e.approvalStatus === "pending" ? "human approval required" : `approval ${e.approvalStatus}`, data: { approval_id: e.approvalId, decision_id: e.decisionId, status: e.approvalStatus, poll_url: e.approvalId ? `/api/v1/approvals/${e.approvalId}/status` : null, reasons: e.reasons } } };
        if (e instanceof MnkiError && e.code === "quota_exceeded") { o.onError?.("quota", e.message); return { allowed: false, error: { code: JSONRPC_QUOTA_EXCEEDED, message: "verification quota exceeded — manage the plan on the web console", data: { code: e.code } } }; }
        const detail = e instanceof Error ? e.message : String(e); o.onError?.("unreachable", detail);
        // The control plane is unreachable or answered unexpectedly: enforce fails closed, observe/warn fail open.
        if (o.mode === "enforce" || o.mode === "require_approval") return { allowed: false, error: { code: JSONRPC_UNREACHABLE, message: "Agent Trust unreachable — call refused in enforce mode", data: { detail } } };
        return { allowed: true };
      }
    },
  };
}

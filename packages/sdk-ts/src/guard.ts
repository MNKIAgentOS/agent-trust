/**
 * `guard()` — verify a tool call before it runs. One core, two backends (local world or the hosted control
 * plane), four modes: `observe` (log only), `warn` (run, surface evidence), `require_approval` (escalate where
 * policy says so, never hard-deny), `enforce`. Framework adapters are thin wrappers over `check()` / `wrap()`.
 */
import { bodyHash } from "mnki-verifier";
import { AgentTrustClient, AgentIdentity, AgentTrustError, type Decision, type VerifyInput, type GrantExecution, type GrantRecord, type GrantDecision, type GrantResult } from "./index";
import { ApprovalRequired, Denied, MnkiError, fromApi } from "./errors";
import { localVerify, type LocalWorld } from "./local";

export type GuardMode = "observe" | "warn" | "require_approval" | "enforce";
export interface GuardRecord { at: string; mode: GuardMode; tool: string; action: string; resource?: string; decision: string; enforced: boolean; reasons: string[]; evidence: Decision["evidence"]; decision_id?: string; approval_id?: string | null; tags: string[] }
export interface GuardOptions {
  /** Hosted verification (an `AgentTrustClient` or its options) — omit for local mode. */
  client?: AgentTrustClient | { baseUrl: string; apiKey: string; fetch?: typeof fetch };
  /** Local mode: the world to verify against (see `demoWorld()`). */
  world?: LocalWorld;
  /** Agent id, stable id or name as known to the world / organisation. */
  agent: string;
  /** Signs hosted requests (Agent-Proof). Optional; unsigned requests carry a `request_unsigned` warning. */
  identity?: AgentIdentity;
  mode?: GuardMode;
  /** Prefix for tool actions, e.g. `tool:` → `tool:refund.create`. Use "" when tool names already are actions. */
  actionPrefix?: string;
  /** Map tool arguments to amount / currency / resource / context (defaults read `amount|value`, `currency`, `resource|customer_id|id`). */
  mapArgs?: (tool: string, args: unknown) => Partial<Pick<VerifyInput, "amount" | "currency" | "resource" | "context">>;
  onApproval?: "wait" | "throw";
  approval?: { timeoutMs?: number; initialDelayMs?: number; maxDelayMs?: number };
  /** Called for every decision (observe mode writes its shadow log through this). */
  onDecision?: (r: GuardRecord) => void | Promise<void>;
  now?: () => Date;
}
export interface GuardResult { allowed: boolean; decision: string; reasons: string[]; evidence: Decision["evidence"]; decision_id?: string; approval_id?: string | null; enforced: boolean; attestation?: string }

const defaultMap: NonNullable<GuardOptions["mapArgs"]> = (_tool, args) => {
  const a = (args ?? {}) as Record<string, unknown>; const out: Partial<VerifyInput> = {};
  const amount = typeof a.amount === "number" ? a.amount : typeof a.value === "number" ? a.value : typeof a.amount === "string" && /^\d+(\.\d+)?$/.test(a.amount) ? Number(a.amount) : undefined;
  if (amount !== undefined) out.amount = amount;
  if (typeof a.currency === "string" && /^[A-Z]{3}$/.test(a.currency)) out.currency = a.currency;
  const res = [a.resource, a.customer_id, a.customerId, a.id].find((v) => typeof v === "string") as string | undefined; if (res) out.resource = res;
  const ctx: Record<string, unknown> = {};
  if (typeof a.region === "string") ctx.region = a.region;
  // Receiver-side facts travel as arguments so any mapper sees them: the A2A caller (adapters/a2a) and the §15 effect path.
  if (a.a2a && typeof a.a2a === "object") ctx.a2a = a.a2a;
  if (a.effect_path === "custody" || a.effect_path === "attested" || a.effect_path === "none") ctx.effect_path = a.effect_path;
  if (Object.keys(ctx).length) out.context = ctx;
  return out;
};
const stable = (v: unknown): string => JSON.stringify(v, (_k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x as object).sort().map((k) => [k, (x as Record<string, unknown>)[k]])) : x));
const tagsFor = (d: { decision: string; reasons: string[] }): string[] => {
  const t: string[] = []; const r = d.reasons;
  if (d.decision === "DENY") t.push("would_deny"); if (d.decision === "REQUIRE_APPROVAL") t.push("approval_required");
  if (r.includes("agent_unknown") || r.some((x) => x.startsWith("credential_"))) t.push("missing_identity");
  if (r.includes("no_delegation") || r.some((x) => x.startsWith("delegation_"))) t.push("missing_delegation");
  if (r.includes("capability_missing") || r.includes("constraint_violated") || r.includes("budget_exceeded")) t.push("excess_capability");
  if (r.some((x) => x.startsWith("policy:") && !x.endsWith(":allow"))) t.push("policy_mismatch");
  return t;
};

export class Guard {
  readonly mode: GuardMode; private readonly client: AgentTrustClient | null;
  constructor(private readonly o: GuardOptions) {
    this.mode = o.mode ?? "enforce";
    this.client = o.client ? (o.client instanceof AgentTrustClient ? o.client : new AgentTrustClient(o.client)) : null;
    if (!this.client && !o.world) throw new MnkiError("invalid_request", "guard needs either `client` (hosted) or `world` (local)");
  }
  private input(tool: string, args: unknown): VerifyInput {
    const mapped = (this.o.mapArgs ?? defaultMap)(tool, args);
    return { agent: this.o.agent, action: `${this.o.actionPrefix ?? "tool:"}${tool}`, ...mapped, context: { ...(mapped.context ?? {}), tool, arguments_hash: undefined as unknown as string } };
  }
  /** Verify one tool call. Resolves when the call may proceed; throws `Denied` / `ApprovalRequired` when it may not (mode permitting). */
  async check(tool: string, args: unknown = {}): Promise<GuardResult> {
    const input = this.input(tool, args); input.context = { ...input.context, arguments_hash: await bodyHash(stable(args ?? {})) };
    let d: Decision;
    if (this.client) {
      try { d = await this.client.verify(input, { identity: this.o.identity }); }
      catch (e) { if (e instanceof AgentTrustError) throw fromApi(e.status, e.code, e.detail); throw new MnkiError("network", e instanceof Error ? e.message : String(e)); }
    } else {
      const r = await localVerify(this.o.world!, input, this.o.now?.() ?? new Date());
      if (!r.ok) throw new MnkiError("invalid_request", r.code);
      d = { ...(r.result as unknown as Decision), request_id: "local", decision_id: `local_${Date.now().toString(36)}`, approval_id: r.result.decision === "REQUIRE_APPROVAL" ? "local_pending" : null, latency_ms: 0 };
    }
    const enforced = this.mode === "enforce" || (this.mode === "require_approval" && d.decision === "REQUIRE_APPROVAL");
    const rec: GuardRecord = { at: new Date().toISOString(), mode: this.mode, tool, action: input.action, resource: input.resource, decision: d.decision, enforced, reasons: d.reasons, evidence: d.evidence, decision_id: d.decision_id, approval_id: d.approval_id, tags: tagsFor(d) };
    await this.o.onDecision?.(rec);
    const base: GuardResult = { allowed: d.decision === "ALLOW", decision: d.decision, reasons: d.reasons, evidence: d.evidence, decision_id: d.decision_id, approval_id: d.approval_id, enforced };
    if (d.decision === "ALLOW" || !enforced) return { ...base, allowed: true };
    if (d.decision === "DENY") throw new Denied(d);
    // REQUIRE_APPROVAL
    if (!this.client || (this.o.onApproval ?? "wait") === "throw" || !d.approval_id) throw new ApprovalRequired(d.approval_id, d.decision_id, "pending", d.reasons);
    const status = await this.client.waitForApproval(d.approval_id, this.o.approval);
    if (status !== "approved") throw new ApprovalRequired(d.approval_id, d.decision_id, status, d.reasons);
    const att = await this.client.attestations.issue(d.decision_id).catch(() => null);
    return { ...base, allowed: true, attestation: att?.token };
  }
  /**
   * Access broker: perform one operation on a connection through Agent Trust instead of calling the provider with a
   * credential of your own. Verified, granted once and executed by the broker; waits for a human approval like `check`.
   */
  async access(connection: string, operation: string, params: Record<string, string | number | boolean> = {}): Promise<{ grant: GrantRecord; decision: GrantDecision; result: GrantResult }> {
    if (!this.client) throw new MnkiError("invalid_request", "guard.access needs a hosted client");
    const input = { agent: this.o.agent, connection, operation, params };
    let r: GrantExecution;
    try { r = await this.client.grants.execute(input, { identity: this.o.identity }); }
    catch (e) { if (e instanceof AgentTrustError) throw fromApi(e.status, e.code, e.detail); throw new MnkiError("network", e instanceof Error ? e.message : String(e)); }
    const rec = (d: GrantDecision, enforced: boolean): GuardRecord => ({ at: new Date().toISOString(), mode: this.mode, tool: `${connection}/${operation}`, action: `access:${operation}`, resource: connection, decision: d.decision, enforced, reasons: d.reasons, evidence: d.evidence as Decision["evidence"], decision_id: d.decision_id, approval_id: d.approval_id, tags: tagsFor(d) });
    if (r.status === "executed") { await this.o.onDecision?.(rec(r.decision, true)); return r; }
    await this.o.onDecision?.(rec(r.decision, true));
    if ((this.o.onApproval ?? "wait") === "throw") throw new ApprovalRequired(r.approval_id, r.decision.decision_id, "pending", r.decision.reasons);
    const status = await this.client.waitForApproval(r.approval_id, this.o.approval);
    if (status !== "approved") throw new ApprovalRequired(r.approval_id, r.decision.decision_id, status, r.decision.reasons);
    let again: GrantExecution;
    try { again = await this.client.grants.execute({ ...input, approval_id: r.approval_id }, { identity: this.o.identity }); }
    catch (e) { if (e instanceof AgentTrustError) throw fromApi(e.status, e.code, e.detail); throw new MnkiError("network", e instanceof Error ? e.message : String(e)); }
    if (again.status !== "executed") throw new ApprovalRequired(again.approval_id, again.decision.decision_id, "pending", again.decision.reasons);
    return again;
  }
  /** Wrap a tool implementation: the call runs only after `check` resolves. */
  wrap<A extends unknown[], R>(tool: string, fn: (...args: A) => R | Promise<R>): (...args: A) => Promise<R> {
    return async (...args: A) => { await this.check(tool, args[0]); return fn(...args); };
  }
}
export const createGuard = (o: GuardOptions): Guard => new Guard(o);

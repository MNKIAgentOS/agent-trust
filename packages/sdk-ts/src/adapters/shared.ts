/**
 * Shared by every framework adapter: the guard surface an adapter needs, and how a refusal is handed back to
 * the framework — as a thrown error (`throw`) or as a structured tool result the model can read and explain
 * (`result`, the default: aborting a whole agent run because one call was refused is rarely what people want).
 */
import { ApprovalRequired, Denied, MnkiError } from "../errors";
import type { GuardResult } from "../guard";

export interface GuardLike { check(tool: string, args?: unknown): Promise<GuardResult>; readonly mode: string }
export type OnRefused = "throw" | "result";
export interface AdapterOptions {
  /** `result` (default): the tool returns `{ error, reasons, evidence, … }`; `throw`: `Denied` / `ApprovalRequired` propagate. */
  onRefused?: OnRefused;
  /** Only guard these tools (default: all). */
  only?: string[];
  /** Never guard these tools. */
  skip?: string[];
  /** Rename tools before verification (e.g. strip a framework prefix). */
  toolName?: (name: string) => string;
}
export interface RefusalResult { error: "denied" | "approval_required" | "approval_rejected" | "approval_expired" | "approval_timeout" | "verification_failed"; message: string; reasons: string[]; evidence?: { step: string; status: string; title: string; detail?: string }[]; decision_id?: string; approval_id?: string | null }

export const wanted = (name: string, o: AdapterOptions): boolean => !(o.skip ?? []).includes(name) && (!o.only || o.only.includes(name));

/** Turn a guard error into the structured result the model sees. Anything that is not a refusal is re-thrown. */
export function refusal(e: unknown): RefusalResult {
  if (e instanceof Denied) return { error: "denied", message: e.message, reasons: e.reasons, evidence: e.evidence.filter((x) => x.status !== "pass").map(({ step, status, title, detail }) => ({ step, status, title, detail })), decision_id: e.decision.decision_id };
  if (e instanceof ApprovalRequired) return { error: e.code as RefusalResult["error"], message: e.message, reasons: e.reasons, decision_id: e.decisionId, approval_id: e.approvalId };
  if (e instanceof MnkiError) return { error: "verification_failed", message: `${e.code}: ${e.message}`, reasons: [e.code] };
  throw e;
}
/** Run `check`, then `fn`; a refusal either throws or becomes `RefusalResult` per `onRefused`. */
export async function guarded<T>(guard: GuardLike, tool: string, args: unknown, fn: () => Promise<T>, o: AdapterOptions): Promise<T | RefusalResult> {
  try { await guard.check(tool, args); } catch (e) { if ((o.onRefused ?? "result") === "throw") throw e; return refusal(e); }
  return fn();
}
export const parseJsonArgs = (input: unknown): unknown => { if (typeof input !== "string") return input ?? {}; try { return JSON.parse(input); } catch { return { input }; } };

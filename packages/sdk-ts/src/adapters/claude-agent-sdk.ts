/**
 * Claude Agent SDK — `@anthropic-ai/claude-agent-sdk`. A `PreToolUse` hook that verifies every tool call
 * (Bash, Edit, MCP tools `mcp__<server>__<tool>`, …) before Claude runs it. The hook answers with the SDK's
 * permission decision: `deny` with the evidence as the reason, `ask` when a human must decide and the guard
 * is not configured to wait, `allow` otherwise. Type-only: the SDK is never imported.
 *
 *   import { preToolUse } from "mnki-sdk/claude-agent-sdk";
 *   query({ prompt, options: { hooks: { PreToolUse: [{ hooks: [preToolUse(guard)] }] } } });
 */
import { ApprovalRequired, Denied, MnkiError } from "../errors";
import { wanted, type AdapterOptions, type GuardLike } from "./shared";

export interface PreToolUseInput { hook_event_name?: string; tool_name: string; tool_input: unknown; session_id?: string; tool_use_id?: string }
export interface PreToolUseOutput { continue?: boolean; decision?: "approve" | "block"; reason?: string; hookSpecificOutput?: { hookEventName: "PreToolUse"; permissionDecision: "allow" | "deny" | "ask"; permissionDecisionReason?: string; updatedInput?: unknown } }
export type PreToolUseHook = (input: PreToolUseInput, toolUseId: string | undefined, ctx?: { signal?: AbortSignal }) => Promise<PreToolUseOutput>;
export interface ClaudeAdapterOptions extends Omit<AdapterOptions, "onRefused"> {
  /** What to answer when the control plane cannot be reached (default `deny` — fail closed; observe/warn modes never refuse anyway). */
  onError?: "deny" | "ask" | "allow";
}

/** `mcp__github__create_issue` → `{ server: "github", tool: "create_issue" }`; anything else is a built-in tool. */
export function parseToolName(name: string): { server: string | null; tool: string } {
  const m = /^mcp__([^_]+(?:_[^_]+)*)__(.+)$/.exec(name); return m ? { server: m[1], tool: m[2] } : { server: null, tool: name };
}
const summarize = (reasons: string[], evidence: { status: string; title: string; detail?: string }[]): string => {
  const rows = evidence.filter((e) => e.status === "fail" || e.status === "warn").map((e) => `${e.status === "fail" ? "✕" : "⚠"} ${e.title}${e.detail ? ` — ${e.detail}` : ""}`);
  return `Agent Trust: ${reasons.filter((r) => !r.endsWith("_verified") && r !== "authority_valid").join(", ") || "refused"}${rows.length ? `\n${rows.join("\n")}` : ""}`;
};
export function preToolUse(guard: GuardLike, o: ClaudeAdapterOptions = {}): PreToolUseHook {
  return async (input) => {
    if (!wanted(input.tool_name, o)) return {};
    const name = o.toolName ? o.toolName(input.tool_name) : input.tool_name;
    const answer = (permissionDecision: "allow" | "deny" | "ask", reason?: string): PreToolUseOutput => ({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision, ...(reason ? { permissionDecisionReason: reason } : {}) }, ...(permissionDecision === "deny" ? { decision: "block", reason } : {}) });
    try { await guard.check(name, input.tool_input ?? {}); return answer("allow"); }
    catch (e) {
      if (e instanceof Denied) return answer("deny", summarize(e.reasons, e.evidence));
      if (e instanceof ApprovalRequired) return e.approvalStatus === "pending" ? answer("ask", `Agent Trust: a human must approve this action${e.approvalId ? ` (approval ${e.approvalId})` : ""}.`) : answer("deny", `Agent Trust: approval ${e.approvalStatus}.`);
      if (e instanceof MnkiError) { const d = o.onError ?? "deny"; return answer(d, `Agent Trust: verification failed (${e.code}).`); }
      throw e;
    }
  };
}

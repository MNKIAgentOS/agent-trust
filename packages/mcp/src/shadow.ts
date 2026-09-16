/** The shadow log (observe / warn modes): one JSON line per decision in ~/.mnki/shadow/<server>.ndjson, and its summary. */
import { appendFileSync, mkdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { GuardRecord } from "mnki-sdk";

export const shadowLogPath = (server: string): string => join(process.env.MNKI_HOME ?? join(homedir(), ".mnki"), "shadow", `${server.replace(/[^a-z0-9._-]+/gi, "_")}.ndjson`);
export function appendShadow(server: string, r: GuardRecord): void {
  const p = shadowLogPath(server); mkdirSync(join(p, ".."), { recursive: true });
  appendFileSync(p, JSON.stringify({ at: r.at, mode: r.mode, tool: r.tool, action: r.action, decision: r.decision, enforced: r.enforced, reasons: r.reasons, tags: r.tags, decision_id: r.decision_id }) + "\n");
}
export interface ShadowSummary { server: string; calls: number; wouldAllow: number; wouldDeny: number; approvalRequired: number; missingIdentity: number; missingDelegation: number; excessCapability: number; policyMismatch: number; byTool: Record<string, { calls: number; deny: number; approval: number }>; suggestions: string[] }
export function summarizeShadow(server: string, lines: string[]): ShadowSummary {
  const s: ShadowSummary = { server, calls: 0, wouldAllow: 0, wouldDeny: 0, approvalRequired: 0, missingIdentity: 0, missingDelegation: 0, excessCapability: 0, policyMismatch: 0, byTool: {}, suggestions: [] };
  const missingCaps = new Set<string>();
  for (const line of lines) {
    let r: { tool: string; decision: string; tags?: string[]; reasons?: string[] }; try { r = JSON.parse(line); } catch { continue; }
    s.calls++; const t = (s.byTool[r.tool] ??= { calls: 0, deny: 0, approval: 0 }); t.calls++;
    if (r.decision === "ALLOW") s.wouldAllow++; else if (r.decision === "DENY") { s.wouldDeny++; t.deny++; } else if (r.decision === "REQUIRE_APPROVAL") { s.approvalRequired++; t.approval++; }
    for (const tag of r.tags ?? []) { if (tag === "missing_identity") s.missingIdentity++; if (tag === "missing_delegation") s.missingDelegation++; if (tag === "excess_capability") { s.excessCapability++; if ((r.reasons ?? []).includes("capability_missing")) missingCaps.add(r.tool); } if (tag === "policy_mismatch") s.policyMismatch++; }
  }
  if (s.missingIdentity) s.suggestions.push("Register the agent and rotate a credential before enforcing (mnki identity create).");
  if (s.missingDelegation) s.suggestions.push("Issue a delegation to the agent covering the tools it uses (mnki delegate --cap \"mcp:tools/call:<tool>=mcp://<server>/tools/<tool>\").");
  if (missingCaps.size) s.suggestions.push(`Grant capabilities for: ${[...missingCaps].map((t) => `mcp:tools/call:${t}`).join(", ")}.`);
  if (s.excessCapability > missingCaps.size) s.suggestions.push("Some calls exceed constraints (amount, currency, region); widen the delegation or accept the denial.");
  if (s.policyMismatch) s.suggestions.push("Policy rules fire on these calls; review them with `mnki policy explain` before enforcing.");
  if (s.calls && !s.wouldDeny && !s.approvalRequired) s.suggestions.push("Every observed call would have been allowed — safe to switch to --mode enforce.");
  return s;
}
export function readShadow(server: string): string[] { const p = shadowLogPath(server); return existsSync(p) ? readFileSync(p, "utf8").split("\n").filter(Boolean) : []; }

/**
 * `mnki policy test <policy.json> --cases <cases.json>` — run policy cases through the verifier's policy engine.
 * `mnki policy explain <decision.json | --last>` — the six answers (rule, principal, delegation, capability, condition, what would change).
 * `mnki verify --local` writes the last local decision to ~/.mnki/last-decision.json for `--last`.
 */
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { parsePolicyDoc, simulate, type PolicyInput } from "mnki-verifier";
import { explain, type Explanation } from "mnki-sdk";
import { configDir } from "./config";

export interface PolicyCase { name?: string; action: string; resource?: string; amount?: number; currency?: string; region?: string; risk_tier?: "low" | "medium" | "high" | "critical"; agent_labels?: Record<string, string>; delegation_depth?: number; attestations?: string[]; at?: string; expect?: "allow" | "deny" | "require_approval" }
export interface PolicyTestResult { name: string; effect: string; fired: string[]; expected?: string; ok: boolean }

export function policyTest(docJson: unknown, cases: PolicyCase[]): { ok: boolean; results: PolicyTestResult[] } | { ok: false; error: string } {
  const p = parsePolicyDoc(docJson); if (!p.ok) return { ok: false, error: p.error };
  const inputs: PolicyInput[] = cases.map((c) => ({ action: c.action, resource: c.resource, amount: c.amount, currency: c.currency, region: c.region, risk_tier: c.risk_tier ?? "medium", agent_labels: c.agent_labels ?? {}, delegation_depth: c.delegation_depth ?? 1, attestations: c.attestations ?? [], time: c.at ? new Date(c.at) : new Date() }));
  const out = simulate(p.doc, inputs);
  const results = out.map((o, i) => ({ name: cases[i].name ?? `${cases[i].action}${cases[i].amount !== undefined ? ` ${cases[i].amount} ${cases[i].currency ?? ""}` : ""}`.trim(), effect: o.effect, fired: o.fired, expected: cases[i].expect, ok: cases[i].expect === undefined || cases[i].expect === o.effect }));
  return { ok: results.every((r) => r.ok), results };
}
export const lastDecisionPath = () => join(configDir(), "last-decision.json");
export function explainFile(pathOrLast: string): Explanation {
  const path = pathOrLast === "--last" ? lastDecisionPath() : pathOrLast;
  if (!existsSync(path)) throw new Error(pathOrLast === "--last" ? "no local decision yet — run `mnki verify --local …` first" : `${path} not found`);
  return explain(JSON.parse(readFileSync(path, "utf8")));
}
export function formatExplanation(x: Explanation): string {
  const line = (k: string, v: unknown) => `  ${k.padEnd(22)} ${v === null || v === undefined ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v)}`;
  return [`${x.decision} — ${x.summary}`, line("matched rule", x.matched_rule ? `${x.matched_rule.id} → ${x.matched_rule.effect}` : null), line("principal", x.principal), line("limiting delegation", x.limiting_delegation), line("missing capability", x.missing_capability), line("failing condition", x.failing_condition), line("blocking step", x.blocking_step), ...(x.what_would_change.length ? ["  what would change it:", ...x.what_would_change.map((w) => `    · ${w}`)] : [])].join("\n");
}

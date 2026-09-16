/**
 * `mnki demo` — the 15-second story with no account and no network: the same verifier the control plane
 * runs, against a bundled world. Prints the evidence list for each decision and what would change it.
 */
import { createGuard, demoWorld, explain, Denied, ApprovalRequired, type Evidence } from "mnki-sdk";

const mark = { pass: "✓", warn: "⚠", fail: "✕", skipped: "·" } as const;
const printEvidence = (ev: Evidence[], out: (s: string) => void) => { for (const e of ev) out(`    ${mark[e.status]} ${e.title}${e.detail ? `  — ${e.detail}` : ""}`); };

export async function runDemo(out: (s: string) => void = console.log, opts: { json?: boolean } = {}): Promise<{ denied: boolean; allowed: boolean; escalated: boolean }> {
  const world = demoWorld(); const guard = createGuard({ world, agent: "invoice-agent", actionPrefix: "" });
  const results = { denied: false, allowed: false, escalated: false }; const json: unknown[] = [];
  const show = (title: string, req: Record<string, unknown>) => out(`\n${title}\n  ${JSON.stringify(req)}`);
  out("AGENT      invoice-agent (spiffe://acme.example/agent/invoice-agent)\nREPRESENTS Accounts Receivable\nAUTHORITY  refund.create on customer:* up to €5,000 · invoice.read · crm.read\nPOLICY     refunds above €3,000 require a human · database.write is denied");
  show("1 · Refund €47,000 to customer:4711", { action: "refund.create", customer_id: "customer:4711", amount: 47000, currency: "EUR" });
  try { await guard.check("refund.create", { customer_id: "customer:4711", amount: 47000, currency: "EUR" }); }
  catch (e) { if (e instanceof Denied) { results.denied = true; out("  DENY"); printEvidence(e.evidence, out); const x = explain(e.decision); out(`  → ${x.summary}`); for (const w of x.what_would_change) out(`    · ${w}`); json.push({ case: 1, decision: "DENY", reasons: e.reasons, explain: x }); } else throw e; }
  show("2 · Refund €420 to customer:4711", { action: "refund.create", customer_id: "customer:4711", amount: 420, currency: "EUR" });
  const ok = await guard.check("refund.create", { customer_id: "customer:4711", amount: 420, currency: "EUR" }); results.allowed = ok.allowed;
  out("  ALLOW"); printEvidence(ok.evidence, out); json.push({ case: 2, decision: ok.decision, reasons: ok.reasons });
  show("3 · Refund €3,200 to customer:4711", { action: "refund.create", customer_id: "customer:4711", amount: 3200, currency: "EUR" });
  try { await guard.check("refund.create", { customer_id: "customer:4711", amount: 3200, currency: "EUR" }); }
  catch (e) { if (e instanceof ApprovalRequired) { results.escalated = true; out("  REQUIRE_APPROVAL — a human decides (in the cloud: a push to the phone, Face ID, signed record)"); out(`  → ${e.reasons.join(", ")}`); json.push({ case: 3, decision: "REQUIRE_APPROVAL", reasons: e.reasons }); } else throw e; }
  out("\nThat was the whole product in three calls: identity, bounded authority, evidence for every decision.\nNext: `mnki init` (local identity + policy) or `mnki init --url https://mnki.com --key at_…` to govern real agents. `npm i mnki-sdk` · `pip install mnki`.");
  if (opts.json) out(JSON.stringify(json, null, 2));
  return results;
}

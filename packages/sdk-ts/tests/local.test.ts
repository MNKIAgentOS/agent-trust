import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createGuard, demoWorld, localVerify, explain, Denied, ApprovalRequired, type LocalWorld } from "../src/index";

const dir = join(process.cwd(), "conformance", "vectors");
const vectors = readdirSync(dir).filter((f) => f.endsWith(".json")).sort().map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")) as { id: string; now: string; world: LocalWorld; request: Record<string, unknown>; expect: { decision: string; reasons_include?: string[]; evidence?: Record<string, string> } });

describe("local mode = the hosted verifier, in-process", () => {
  it("passes every level-1 conformance vector through localVerify", async () => {
    for (const v of vectors) {
      const r = await localVerify(v.world, v.request, new Date(v.now));
      expect(r.ok, v.id).toBe(true); if (!r.ok) continue;
      expect(r.result.decision, v.id).toBe(v.expect.decision);
      for (const reason of v.expect.reasons_include ?? []) expect(r.result.reasons, v.id).toContain(reason);
      for (const [step, status] of Object.entries(v.expect.evidence ?? {})) expect(r.result.evidence.find((e) => e.step === step)?.status, `${v.id} ${step}`).toBe(status);
    }
  });
  it("tells the 15-second story: €47,000 denied, €420 allowed, €3,200 needs a human, database writes denied by policy", async () => {
    const world = demoWorld(); const records: string[] = [];
    const guard = createGuard({ world, agent: "invoice-agent", actionPrefix: "", onDecision: (r) => { records.push(`${r.tool}:${r.decision}`); } });
    await expect(guard.check("refund.create", { customer_id: "customer:123", amount: 47000, currency: "EUR" })).rejects.toBeInstanceOf(Denied);
    const ok = await guard.check("refund.create", { customer_id: "customer:123", amount: 420, currency: "EUR" });
    expect(ok.allowed).toBe(true); expect(ok.evidence.find((e) => e.step === "constraints")?.status).toBe("pass");
    await expect(guard.check("refund.create", { customer_id: "customer:123", amount: 3200, currency: "EUR" })).rejects.toBeInstanceOf(ApprovalRequired);
    await expect(guard.check("database.write", { table: "users" })).rejects.toMatchObject({ reasons: expect.arrayContaining(["policy:no-database-writes:deny"]) });
    expect(records).toEqual(["refund.create:DENY", "refund.create:ALLOW", "refund.create:REQUIRE_APPROVAL", "database.write:DENY"]);
  });
  it("observe mode never blocks and tags what would have happened; warn allows; enforce blocks", async () => {
    const world = demoWorld(); const seen: { decision: string; enforced: boolean; tags: string[] }[] = [];
    const observe = createGuard({ world, agent: "agt_invoice", actionPrefix: "", mode: "observe", onDecision: (r) => { seen.push({ decision: r.decision, enforced: r.enforced, tags: r.tags }); } });
    expect((await observe.check("refund.create", { amount: 47000, currency: "EUR", customer_id: "customer:1" })).allowed).toBe(true);
    expect((await observe.check("crm.delete", {})).allowed).toBe(true);
    expect(seen[0]).toMatchObject({ decision: "DENY", enforced: false, tags: expect.arrayContaining(["would_deny", "excess_capability"]) });
    expect(seen[1].tags).toContain("excess_capability");
    const warn = createGuard({ world, agent: "agt_invoice", actionPrefix: "", mode: "warn" });
    expect((await warn.check("refund.create", { amount: 47000, currency: "EUR", customer_id: "customer:1" })).allowed).toBe(true);
    const ra = createGuard({ world, agent: "agt_invoice", actionPrefix: "", mode: "require_approval" });
    expect((await ra.check("refund.create", { amount: 47000, currency: "EUR", customer_id: "customer:1" })).allowed).toBe(true); // deny is not enforced in this mode
    await expect(ra.check("refund.create", { amount: 3200, currency: "EUR", customer_id: "customer:1" })).rejects.toBeInstanceOf(ApprovalRequired);
  });
  it("wrap() runs the tool only after the check passes", async () => {
    const guard = createGuard({ world: demoWorld(), agent: "agt_invoice", actionPrefix: "" }); let ran = 0;
    const refund = guard.wrap("refund.create", async (a: { amount: number; currency: string; customer_id: string }) => { ran++; return `refunded ${a.amount}`; });
    expect(await refund({ amount: 100, currency: "EUR", customer_id: "customer:1" })).toBe("refunded 100");
    await expect(refund({ amount: 99999, currency: "EUR", customer_id: "customer:1" })).rejects.toBeInstanceOf(Denied);
    expect(ran).toBe(1);
  });
  it("explain answers the six questions for every denied or escalated vector", async () => {
    for (const v of vectors) {
      const r = await localVerify(v.world, v.request, new Date(v.now)); if (!r.ok) continue;
      const x = explain(r.result);
      expect(x.summary.length, v.id).toBeGreaterThan(10);
      if (r.result.decision !== "ALLOW") { expect(x.what_would_change.length, v.id).toBeGreaterThan(0); expect(x.blocking_step, v.id).not.toBeNull(); }
      if (r.result.reasons.some((s) => s.startsWith("policy:"))) expect(x.matched_rule, v.id).not.toBeNull();
    }
    const r = await localVerify(demoWorld(), { agent: "agt_invoice", action: "refund.create", resource: "customer:1", amount: 47000, currency: "EUR" });
    if (!r.ok) throw new Error(r.code);
    const x = explain(r.result);
    expect(x).toMatchObject({ decision: "DENY", blocking_step: "constraints", failing_condition: expect.stringMatching(/max_value|5000|47000/), limiting_delegation: "dlg_ar_invoice" });
    expect(x.what_would_change.join(" ")).toMatch(/Lower the amount/);
  });
});

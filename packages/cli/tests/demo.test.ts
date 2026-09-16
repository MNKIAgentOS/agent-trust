import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runDemo } from "../src/demo";
import { policyTest, formatExplanation } from "../src/policy";
import { main } from "../src/main";

describe("mnki demo / local mode / policy tooling", () => {
  it("demo tells the story offline: deny, allow, escalate", async () => {
    const lines: string[] = [];
    const r = await runDemo((s) => lines.push(s));
    expect(r).toEqual({ denied: true, allowed: true, escalated: true });
    const text = lines.join("\n");
    expect(text).toMatch(/DENY[\s\S]*✕ Request exceeds capability constraints/); expect(text).toMatch(/ALLOW/); expect(text).toMatch(/REQUIRE_APPROVAL/); expect(text).toMatch(/Lower the amount/);
  });
  it("policy test runs cases through the policy engine and reports expectations", () => {
    const doc = { version: 1, rules: [{ id: "big", match: { action: "refund.create" }, conditions: [{ kind: "amount_gt", value: 3000 }], effect: "require_approval" }, { id: "nodb", match: { action: "database.write" }, effect: "deny" }] };
    const r = policyTest(doc, [{ action: "refund.create", amount: 420, currency: "EUR", expect: "allow" }, { action: "refund.create", amount: 9000, currency: "EUR", expect: "require_approval" }, { action: "database.write", expect: "allow" }]);
    if (!("results" in r)) throw new Error(r.error);
    expect(r.ok).toBe(false); expect(r.results.map((x) => `${x.effect}:${x.ok}`)).toEqual(["allow:true", "require_approval:true", "deny:false"]); expect(r.results[1].fired).toEqual(["big"]);
    expect(policyTest({ version: 2 }, [])).toMatchObject({ ok: false });
  });
  it("mnki init (local) then verify --local and policy explain --last work with no account", async () => {
    const home = mkdtempSync(join(tmpdir(), "mnki-local-")); const cwd = process.cwd(); process.env.MNKI_HOME = home; process.env.MNKI_TELEMETRY = "0"; process.chdir(home);
    const logs: string[] = []; const orig = console.log; console.log = (...a: unknown[]) => { logs.push(a.join(" ")); };
    try {
      await main(["init", "--name", "refund-bot"]);
      expect(logs.join("\n")).toMatch(/Local mode ready/);
      await main(["verify", "--local", "--agent", "refund-bot", "--action", "refund.create", "--amount", "420", "--currency", "EUR", "--resource", "customer:1"]);
      expect(logs.join("\n")).toMatch(/Decision: ALLOW/); expect(process.exitCode ?? 0).toBe(0);
      await main(["verify", "--local", "--agent", "refund-bot", "--action", "refund.create", "--amount", "99999", "--currency", "EUR", "--resource", "customer:1"]);
      expect(logs.join("\n")).toMatch(/Decision: DENY/); expect(process.exitCode).toBe(1); process.exitCode = 0;
      logs.length = 0; await main(["policy", "explain", "--last"]);
      expect(logs.join("\n")).toMatch(/DENY — Denied at the constraints step/); expect(logs.join("\n")).toMatch(/limiting delegation\s+dlg_local/);
      writeFileSync(join(home, "cases.json"), JSON.stringify([{ action: "refund.create", amount: 100, expect: "allow" }]));
      logs.length = 0; await main(["policy", "test", join(home, "mnki.policy.json"), "--cases", join(home, "cases.json")]);
      expect(logs.join("\n")).toMatch(/1\/1 cases as expected/);
    } finally { console.log = orig; process.chdir(cwd); delete process.env.MNKI_HOME; delete process.env.MNKI_TELEMETRY; rmSync(home, { recursive: true, force: true }); }
    expect(formatExplanation({ decision: "ALLOW", matched_rule: null, principal: null, limiting_delegation: null, missing_capability: null, failing_condition: null, blocking_step: null, what_would_change: [], summary: "ok" })).toMatch(/ALLOW — ok/);
  });
});

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { evaluate, simulate } from "../src/policy/evaluate";
import { parsePolicyDoc, type PolicyDoc, type PolicyInput } from "../src/policy/schema";

const base: PolicyInput = { action: "purchase.create", resource: "supplier:1", amount: 100, currency: "EUR", risk_tier: "low", agent_labels: {}, delegation_depth: 1, attestations: [], time: new Date("2026-09-14T12:00:00Z") };
const doc: PolicyDoc = { version: 1, rules: [
  { id: "a", match: { action: "purchase.*" }, conditions: [{ kind: "amount_gt", value: 1000 }], effect: "require_approval" },
  { id: "d", match: { action: "purchase.create", resource: "supplier:9*" }, effect: "deny" },
  { id: "l", match: { agent_labels: { department: "Finance" } }, effect: "allow" },
] };

describe("policy evaluate", () => {
  it("applies precedence deny > require_approval > allow and reports fired rules", () => {
    expect(evaluate(doc, base)).toEqual({ effect: "allow", fired: [], reasons: ["policy:default:allow"] });
    expect(evaluate(doc, { ...base, amount: 5000 })).toMatchObject({ effect: "require_approval", fired: ["a"] });
    expect(evaluate(doc, { ...base, amount: 5000, resource: "supplier:99" })).toMatchObject({ effect: "deny", fired: ["a", "d"] });
    expect(evaluate({ ...doc, default: "deny" }, base)).toMatchObject({ effect: "deny", fired: [] });
  });
  it("missing_attestation and delegation_depth_gt express org-wide guardrails", () => {
    const guard: PolicyDoc = { version: 1, rules: [
      { id: "org-default:attestation", match: { risk_tier: ["high", "critical"] }, conditions: [{ kind: "missing_attestation" }], effect: "require_approval" },
      { id: "org-default:max-depth", conditions: [{ kind: "delegation_depth_gt", value: 2 }], effect: "deny" },
    ] };
    expect(evaluate(guard, { ...base, risk_tier: "critical" })).toMatchObject({ effect: "require_approval", fired: ["org-default:attestation"] });
    expect(evaluate(guard, { ...base, risk_tier: "critical", attestations: ["tee"] })).toMatchObject({ effect: "allow", fired: [] });
    expect(evaluate(guard, { ...base, risk_tier: "critical", attestations: ["tee"], delegation_depth: 3 })).toMatchObject({ effect: "deny", fired: ["org-default:max-depth"] });
    expect(evaluate({ version: 1, rules: [{ id: "k", conditions: [{ kind: "missing_attestation", attestation: "tee" }], effect: "deny" }] }, { ...base, attestations: ["self"] })).toMatchObject({ effect: "deny" });
  });
  it("matches labels, risk tiers and wrapping time windows", () => {
    expect(evaluate(doc, { ...base, agent_labels: { department: "Finance" } }).fired).toEqual(["l"]);
    const tw: PolicyDoc = { version: 1, rules: [{ id: "night", conditions: [{ kind: "time_window", start: "22:00", end: "06:00" }], effect: "deny" }] };
    expect(evaluate(tw, { ...base, time: new Date("2026-09-14T23:30:00Z") }).effect).toBe("deny");
    expect(evaluate(tw, { ...base, time: new Date("2026-09-14T12:00:00Z") }).effect).toBe("allow");
    expect(evaluate({ version: 1, rules: [{ id: "r", match: { risk_tier: ["critical"] }, effect: "deny" }] }, { ...base, risk_tier: "critical" }).effect).toBe("deny");
  });
  it("is deterministic and rule-order independent for the winning effect", () => {
    fc.assert(fc.property(fc.integer({ min: 0, max: 10000 }), fc.shuffledSubarray(doc.rules, { minLength: doc.rules.length }), (amount, rules) => {
      const a = evaluate(doc, { ...base, amount }); const b = evaluate({ ...doc, rules }, { ...base, amount });
      return a.effect === b.effect;
    }));
  });
  it("simulate runs many inputs; parsePolicyDoc rejects malformed docs without throwing", () => {
    expect(simulate(doc, [base, { ...base, amount: 5000 }]).map((o) => o.effect)).toEqual(["allow", "require_approval"]);
    expect(parsePolicyDoc({ version: 1, rules: [{ id: "x", effect: "allow" }] })).toMatchObject({ ok: true });
    expect(parsePolicyDoc({ version: 2, rules: [] })).toEqual({ ok: false, error: "version" });
    expect(parsePolicyDoc({ version: 1, rules: [{ effect: "allow" }] })).toEqual({ ok: false, error: "rules[0].id" });
    expect(parsePolicyDoc("nope")).toEqual({ ok: false, error: "not_object" });
  });
});

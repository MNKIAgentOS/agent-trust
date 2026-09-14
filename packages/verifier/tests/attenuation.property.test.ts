import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { attenuate, isSubset, capabilityCovered, resourceContains } from "../src/delegation/attenuate";
import { computeEffectiveAuthority } from "../src/delegation/chain";
import type { CapSet, Delegation } from "../src/types";

// Small alphabet so overlaps are common and the properties actually bite.
const action = fc.constantFrom("purchase.create", "supplier.search", "invoice.approve");
const resource = fc.tuple(fc.constantFrom("supplier:", "erp/", "s3://bkt/"), fc.constantFrom("", "a", "ab", "abc"), fc.boolean())
  .map(([root, tail, glob]) => `${root}${tail}${glob ? "*" : ""}`);
const constraints = fc.record({
  max_value: fc.option(fc.integer({ min: 0, max: 100 }), { nil: undefined }),
  region: fc.option(fc.subarray(["EU", "US", "UK"], { minLength: 1 }), { nil: undefined }),
}, { requiredKeys: [] });
const capability = fc.record({ action, resource, constraints: fc.option(constraints, { nil: undefined }) }, { requiredKeys: ["action", "resource"] });
const capSet = fc.array(capability, { minLength: 0, maxLength: 5 }) as fc.Arbitrary<CapSet>;

const link = (id: string, parent: string | null, caps: CapSet, status: Delegation["status"] = "active"): Delegation =>
  ({ id, parent_id: parent, subject_agent_id: "agt", capabilities: caps, status });
const NOW = new Date("2026-09-14T12:00:00Z");

describe("attenuation invariants", () => {
  it("attenuate(parent, c) is always a subset of parent", () => {
    fc.assert(fc.property(capSet, capSet, (p, c) => isSubset(attenuate(p, c), p)));
  });
  it("attenuate never invents authority: result ⊆ requested", () => {
    fc.assert(fc.property(capSet, capSet, (p, c) => attenuate(p, c).every((x) => c.includes(x))));
  });
  it("attenuate is idempotent", () => {
    fc.assert(fc.property(capSet, capSet, (p, c) => { const once = attenuate(p, c); return JSON.stringify(attenuate(p, once)) === JSON.stringify(once); }));
  });
  it("a chain never widens the root's authority, however long", () => {
    fc.assert(fc.property(capSet, fc.array(capSet, { minLength: 0, maxLength: 6 }), (root, rest) => {
      const chain = [link("d0", null, root), ...rest.map((c, i) => link(`d${i + 1}`, `d${i}`, c))];
      return isSubset(computeEffectiveAuthority(chain, NOW), root);
    }));
  });
  it("an expired or revoked link anywhere yields no authority", () => {
    fc.assert(fc.property(capSet, capSet, fc.constantFrom<Delegation["status"]>("expired", "revoked"), (root, c, bad) => {
      const chain = [link("d0", null, root), link("d1", "d0", c, bad), link("d2", "d1", c)];
      return computeEffectiveAuthority(chain, NOW).length === 0;
    }));
  });
});

describe("containment rules (examples)", () => {
  it("resource globs", () => {
    expect(resourceContains("supplier:*", "supplier:123")).toBe(true);
    expect(resourceContains("supplier:*", "supplier:1*")).toBe(true);
    expect(resourceContains("supplier:123", "supplier:*")).toBe(false);
    expect(resourceContains("supplier:123", "supplier:124")).toBe(false);
    expect(resourceContains("*", "anything")).toBe(true);
  });
  it("constraints must tighten", () => {
    const p = { action: "purchase.create", resource: "supplier:*", constraints: { max_value: 5000, currency: "EUR", region: ["EU", "UK"] } };
    expect(capabilityCovered(p, { ...p, constraints: { max_value: 3200, currency: "EUR", region: ["EU"] } })).toBe(true);
    expect(capabilityCovered(p, { ...p, constraints: { max_value: 9000, currency: "EUR", region: ["EU"] } })).toBe(false);
    expect(capabilityCovered(p, { ...p, constraints: { max_value: 100, currency: "USD", region: ["EU"] } })).toBe(false);
    expect(capabilityCovered(p, { ...p, constraints: { max_value: 100, currency: "EUR", region: ["US"] } })).toBe(false);
    expect(capabilityCovered(p, { ...p, constraints: undefined })).toBe(false); // dropping a limit is widening
  });
});

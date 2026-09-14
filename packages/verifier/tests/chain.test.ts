import { describe, it, expect } from "vitest";
import { resolveChain, computeEffectiveAuthority, linkValidAt } from "../src/delegation/chain";
import type { Delegation } from "../src/types";

const cap = (resource: string, max_value?: number) => ({ action: "purchase.create", resource, constraints: max_value === undefined ? undefined : { max_value } });
const mk = (id: string, parent: string | null, caps: ReturnType<typeof cap>[], extra: Partial<Delegation> = {}): Delegation =>
  ({ id, parent_id: parent, subject_agent_id: "agt", capabilities: caps, status: "active", ...extra });
const store = (ds: Delegation[]) => (id: string) => ds.find((d) => d.id === id);
const NOW = new Date("2026-09-14T12:00:00Z");

describe("resolveChain", () => {
  it("returns root → leaf", () => {
    const r = resolveChain("d3", store([mk("d1", null, []), mk("d2", "d1", []), mk("d3", "d2", [])]));
    expect(r).toMatchObject({ ok: true }); if (r.ok) expect(r.chain.map((d) => d.id)).toEqual(["d1", "d2", "d3"]);
  });
  it("detects cycles, missing parents and excessive depth", () => {
    expect(resolveChain("a", store([mk("a", "b", []), mk("b", "a", [])]))).toEqual({ ok: false, reason: "cycle", at: "a" });
    expect(resolveChain("x", store([mk("x", "ghost", [])]))).toEqual({ ok: false, reason: "missing", at: "ghost" });
    const deep = Array.from({ length: 10 }, (_, i) => mk(`d${i}`, i === 0 ? null : `d${i - 1}`, []));
    expect(resolveChain("d9", store(deep))).toMatchObject({ ok: false, reason: "depth" });
  });
});

describe("computeEffectiveAuthority", () => {
  it("attenuates through the chain", () => {
    const chain = [mk("root", null, [cap("supplier:*", 5000)]), mk("child", "root", [cap("supplier:1*", 3200), cap("erp/*", 10)])];
    expect(computeEffectiveAuthority(chain, NOW)).toEqual([cap("supplier:1*", 3200)]);
  });
  it("respects validity windows", () => {
    const d = mk("d", null, [cap("x")], { not_after: "2026-09-14T11:00:00Z" });
    expect(linkValidAt(d, NOW)).toBe(false);
    expect(computeEffectiveAuthority([d], NOW)).toEqual([]);
    expect(linkValidAt(mk("e", null, [], { not_before: "2026-09-14T13:00:00Z" }), NOW)).toBe(false);
  });
});

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { parseVerifyRequest } from "../src/parse";

describe("parseVerifyRequest", () => {
  it("never throws on arbitrary input and always returns a typed result", () => {
    fc.assert(fc.property(fc.anything(), (x) => {
      const r = parseVerifyRequest(x);
      return r.ok === true ? typeof r.request.agent === "string" && typeof r.request.action === "string" : typeof r.code === "string";
    }));
  });
  it("accepts a well-formed request and drops unknown keys", () => {
    const r = parseVerifyRequest({ agent: " agt_1 ", action: "purchase.create", resource: "supplier:123", amount: 3200, currency: "EUR", context: { po: 7 }, junk: true });
    expect(r).toEqual({ ok: true, request: { agent: "agt_1", action: "purchase.create", resource: "supplier:123", amount: 3200, currency: "EUR", context: { po: 7 } } });
  });
  it("rejects the specific bad field", () => {
    expect(parseVerifyRequest({ action: "x" })).toEqual({ ok: false, code: "agent" });
    expect(parseVerifyRequest({ agent: "a", action: "x", amount: -1 })).toEqual({ ok: false, code: "amount" });
    expect(parseVerifyRequest({ agent: "a", action: "x", currency: "eur" })).toEqual({ ok: false, code: "currency" });
    expect(parseVerifyRequest({ agent: "a", action: "x", context: [] })).toEqual({ ok: false, code: "context" });
  });
});

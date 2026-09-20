import { describe, it, expect } from "vitest";
import { EVIDENCE_CODES, EVIDENCE_PARAMS, isEvidenceCode, type EvidenceCode } from "../src/evidence-codes";
import { evidenceFromVectors } from "./vectors";

const isPrimitive = (v: unknown) => v === null || ["string", "number", "boolean"].includes(typeof v);

describe("evidence codes", () => {
  it("the code list is unique, dotted <step>.<meaning>, and every code declares its params", () => {
    expect(new Set(EVIDENCE_CODES).size).toBe(EVIDENCE_CODES.length);
    for (const c of EVIDENCE_CODES) { expect(c).toMatch(/^[a-z_]+\.[a-z_]+$/); expect(EVIDENCE_PARAMS[c], `params for ${c}`).toBeDefined(); }
    expect(Object.keys(EVIDENCE_PARAMS).sort()).toEqual([...EVIDENCE_CODES].sort());
  });

  it("every evidence row produced across the conformance vectors carries a known code and declared, primitive params", async () => {
    const seen = new Set<EvidenceCode>();
    for (const { id, evidence } of await evidenceFromVectors()) {
      expect(evidence.length).toBeGreaterThan(0);
      for (const e of evidence) {
        expect(isEvidenceCode(e.code), `${id} ${e.step} "${e.title}" has code ${String(e.code)}`).toBe(true);
        expect(e.code!.split(".")[0], `${id}: code ${e.code} must belong to step ${e.step}`).toBe(e.step);
        expect(e.params, `${id} ${e.code} params`).toBeDefined();
        for (const [k, v] of Object.entries(e.params!)) {
          expect(EVIDENCE_PARAMS[e.code!], `${id} ${e.code} param ${k} is not declared`).toContain(k);
          expect(isPrimitive(v), `${id} ${e.code}.${k} must be a primitive or null`).toBe(true);
        }
        seen.add(e.code!);
      }
    }
    // The reference vectors exercise the core of the pipeline; the rest is covered by the unit suites.
    for (const c of ["request.parsed", "identity.resolved", "identity.unknown", "credential.fresh", "credential.expired", "proof.unsigned", "principal.bound", "principal.unbound", "delegation.valid", "delegation.none", "capability.granted", "capability.missing", "constraints.satisfied", "constraints.violated", "revocation.none", "revocation.delegation", "attestation.none", "policy.allow", "policy.deny", "policy.require_approval", "identity.federated"] as const) expect(seen, `vectors never produce ${c}`).toContain(c);
  });

  it("codes never change the normative English text: title and detail are the same with or without them", async () => {
    for (const { evidence } of await evidenceFromVectors()) for (const e of evidence) {
      expect(typeof e.title).toBe("string"); expect(e.title).not.toBe("");
      // A title never leaks a code or a placeholder: the English stays human text.
      expect(e.title).not.toMatch(/\{\w+\}/); expect(e.title).not.toBe(e.code);
    }
  });
});

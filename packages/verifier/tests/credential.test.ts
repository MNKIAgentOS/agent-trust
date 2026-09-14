import { describe, it, expect } from "vitest";
import { generateAgentKey } from "../src/proof";
import { issueDelegationCredential, verifyDelegationChain, issueAttestation, verifyAttestation, decodeJwt, verifyJwt, DELEGATION_TYP } from "../src/credential";
import type { CapSet } from "../src/types";

const NOW = new Date("2026-09-14T12:00:00Z");
const ROOT: CapSet = [{ action: "purchase.create", resource: "supplier:*", constraints: { max_value: 5000, currency: "EUR", region: ["EU"] } }, { action: "supplier.search", resource: "supplier:*" }];
const CHILD: CapSet = [{ action: "purchase.create", resource: "supplier:1*", constraints: { max_value: 1200, currency: "EUR", region: ["EU"] } }];

describe("signed delegation credentials + authorization attestations", () => {
  it("issues a root and child credential and verifies the chain offline against the org JWKS", async () => {
    const org = await generateAgentKey("ES256"); const resolve = async (kid: string, iss: string) => (kid === "org-1" && iss === "org_acme" ? org.publicJwk : null);
    const base = { privateKey: org.privateKey, alg: "ES256" as const, kid: "org-1", orgId: "org_acme", now: NOW };
    const root = await issueDelegationCredential({ ...base, delegationId: "dlg_root", subjectAgentId: "agt_parent", issuer: { type: "principal", id: "prn_alice" }, capabilities: ROOT, effective: ROOT, parentId: null, parentToken: null, depth: 0, notAfter: "2027-01-01T00:00:00Z" });
    const child = await issueDelegationCredential({ ...base, delegationId: "dlg_child", subjectAgentId: "agt_child", issuer: { type: "agent", id: "agt_parent" }, capabilities: CHILD, effective: CHILD, parentId: "dlg_root", parentToken: root, depth: 1, task: "supplier research" });
    expect(decodeJwt(root)?.header).toMatchObject({ alg: "ES256", typ: DELEGATION_TYP, kid: "org-1" });
    const ok = await verifyDelegationChain([root, child], resolve, NOW);
    expect(ok).toMatchObject({ ok: true, chain: ["dlg_root", "dlg_child"], subject: "agt_child", root_issuer: { type: "principal", id: "prn_alice" } });
    if (ok.ok) expect(ok.effective[0].constraints).toMatchObject({ max_value: 1200 });
    // Broken links: wrong parent hash, a child wider than its parent, wrong issuer, unknown key, expiry.
    const forgedParent = await issueDelegationCredential({ ...base, delegationId: "dlg_root", subjectAgentId: "agt_parent", issuer: { type: "principal", id: "prn_alice" }, capabilities: ROOT, effective: ROOT, parentId: null, parentToken: null, depth: 0, notAfter: "2027-06-01T00:00:00Z" });
    expect(await verifyDelegationChain([forgedParent, child], resolve, NOW)).toMatchObject({ ok: false, at: 1, reason: "parent_hash" });
    const wide: CapSet = [{ action: "purchase.create", resource: "supplier:*", constraints: { max_value: 9000, currency: "EUR", region: ["EU"] } }];
    const wider = await issueDelegationCredential({ ...base, delegationId: "dlg_w", subjectAgentId: "agt_child", issuer: { type: "agent", id: "agt_parent" }, capabilities: wide, effective: wide, parentId: "dlg_root", parentToken: root, depth: 1 });
    expect(await verifyDelegationChain([root, wider], resolve, NOW)).toMatchObject({ ok: false, at: 1, reason: "exceeds_parent" });
    const wrongIssuer = await issueDelegationCredential({ ...base, delegationId: "dlg_x", subjectAgentId: "agt_child", issuer: { type: "agent", id: "agt_other" }, capabilities: CHILD, effective: CHILD, parentId: "dlg_root", parentToken: root, depth: 1 });
    expect(await verifyDelegationChain([root, wrongIssuer], resolve, NOW)).toMatchObject({ ok: false, at: 1, reason: "issuer_must_be_parent_subject" });
    expect(await verifyDelegationChain([root, child], async () => null, NOW)).toMatchObject({ ok: false, at: 0, reason: "unknown_key" });
    expect(await verifyDelegationChain([root, child], resolve, new Date("2027-02-01T00:00:00Z"))).toMatchObject({ ok: false, at: 0, reason: "expired" });
    expect(await verifyDelegationChain([child], resolve, NOW)).toMatchObject({ ok: false, at: 0, reason: "root_expected" });
  });
  it("issues a short-lived attestation that verifies, then expires; typ confusion is rejected", async () => {
    const org = await generateAgentKey("EdDSA"); const resolve = async () => org.publicJwk;
    const token = await issueAttestation({ privateKey: org.privateKey, alg: "EdDSA", kid: "org-ed", orgId: "org_acme", attestationId: "aat_1", agentId: "agt_1", ttlSeconds: 600, now: NOW,
      claims: { v: 1, principal: "prn_alice", organization: "org_acme", action: "purchase.create", resource: "supplier:123", decision: "ALLOW", capabilities: CHILD, delegation_chain: ["dlg_root"], human_approval: null, decision_id: "dec_1", request_hash: "abc", policy_version: "pv_1" } });
    const ok = await verifyAttestation(token, resolve, NOW);
    expect(ok).toMatchObject({ ok: true, expires_in: 600 }); if (ok.ok) expect(ok.payload.atp.action).toBe("purchase.create");
    expect(await verifyAttestation(token, resolve, new Date(NOW.getTime() + 601_000))).toMatchObject({ ok: false, reason: "expired" });
    // An attestation token is not a delegation credential.
    expect(await verifyJwt(token, DELEGATION_TYP, resolve, NOW)).toMatchObject({ ok: false, reason: "typ" });
  });
});

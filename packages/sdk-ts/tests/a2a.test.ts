import { describe, it, expect } from "vitest";
import { generateAgentKey, issueAttestation } from "mnki-verifier";
import { AgentIdentity, createGuard, decodeJwt, type LocalWorld } from "../src/index";
import { signTaskRequest, verifyBeforeAccept, readAgentCard, refusalToJsonRpc, AGENT_TRUST_EXTENSION, type AgentCard } from "../src/adapters/a2a";

/** Two organisations, both local: Acme's invoice agent asks Globex's quote agent for a quote. */
const NOW = new Date("2026-09-16T12:00:00Z"); const y = "2027-09-16T00:00:00Z";
const globexWorld: LocalWorld = { agent: { id: "agt_quote", stable_id: "spiffe://globex/agent/quote", lifecycle: "active", risk_tier: "low", owner_principal_id: "prn_sales", labels: {} }, credential: { id: "crd_q", kind: "jwt_svid", status: "active", not_after: y }, principals: [{ id: "prn_sales", display_name: "Sales", kind: "team" }],
  delegations: [{ id: "dlg_q", parent_id: null, subject_agent_id: "agt_quote", status: "active", not_after: y, capabilities: [{ action: "a2a:quote.create", resource: "*", constraints: { max_value: 10000, currency: "EUR" } }] }], policy: { version_id: "pv", hash: "h", doc: { version: 1, rules: [{ id: "big-quotes", match: { action: "a2a:quote.create" }, conditions: [{ kind: "amount_gt", value: 5000 }], effect: "require_approval" }] } } };

describe("A2A: sign on the caller side, verify before accept on the receiver side", async () => {
  const acmeKey = await generateAgentKey("ES256"); const jwks = { keys: [{ ...acmeKey.publicJwk, kid: "org-acme-1" }] };
  const caller = await AgentIdentity.create("agt_invoice", "ES256", "k-invoice");
  const issue = (over: Partial<Parameters<typeof issueAttestation>[0]["claims"]> = {}, sub = "agt_invoice", orgId = "org_acme") => issueAttestation({ privateKey: acmeKey.privateKey, alg: "ES256", kid: "org-acme-1", orgId, attestationId: "aat_1", agentId: sub, ttlSeconds: 600, now: NOW, claims: { v: 1, principal: "prn_ar", organization: orgId, action: "a2a:quote.create", resource: null, decision: "ALLOW", capabilities: [{ action: "a2a:quote.create", resource: "*" }], delegation_chain: ["dlg_a"], human_approval: null, decision_id: "dec_1", request_hash: null, policy_version: null, ...over } });
  const card: AgentCard = { name: "invoice-agent", provider: { organization: "Acme" }, capabilities: { extensions: [{ uri: AGENT_TRUST_EXTENSION, params: { agent_id: "agt_invoice", stable_id: "spiffe://acme/agent/invoice", public_id: "pub_acmeinvoice0000000000", organization: "org_acme", organization_name: "Acme", jwks_url: "https://acme.test/api/v1/orgs/org_acme/jwks", passport_url: "https://acme.test/agent/pub_acmeinvoice0000000000" } }] }, skills: [{ id: "invoice.read" }] };
  let passportState = "verified"; const fetched: string[] = [];
  const f = (async (url: string) => { fetched.push(url);
    if (url.endsWith("/jwks")) return new Response(JSON.stringify(jwks));
    if (url.includes("/agent-card")) return new Response(JSON.stringify(card));
    if (url.includes("/passport")) return new Response(JSON.stringify({ public_id: "pub_acmeinvoice0000000000", state: passportState, lifecycle: passportState === "revoked" ? "revoked" : "active", organization: { name: "Acme", verified: true } }));
    return new Response("nope", { status: 404 }); }) as unknown as typeof fetch;
  const guard = () => createGuard({ world: globexWorld, agent: "agt_quote", actionPrefix: "a2a:", now: () => NOW });

  it("the caller signs the task with Agent-Proof and attaches the attestation and card", async () => {
    const att = await issue(); const r = await signTaskRequest(caller, { url: "https://globex.test/a2a", body: { jsonrpc: "2.0", id: 1, method: "message/send", params: { skill: "quote.create", amount: 1200 } }, attestation: att, cardUrl: "https://acme.test/api/v1/agents/agt_invoice/agent-card" });
    expect(r.headers["agent-attestation"]).toBe(att); expect(r.headers["agent-id"]).toBe("agt_invoice"); expect(r.headers["agent-card"]).toMatch(/agent-card$/);
    const proof = decodeJwt<{ htm: string; htu: string; iss: string }>(r.headers["agent-proof"]); expect(proof?.payload).toMatchObject({ htm: "POST", htu: "https://globex.test/a2a", iss: "agt_invoice" }); expect(proof?.header.kid).toBe("k-invoice");
    expect(readAgentCard(card)?.jwks_url).toContain("/jwks"); expect(readAgentCard({ name: "plain" })).toBeNull();
  });
  it("the receiver verifies the attestation offline, checks standing, runs its own guard, and returns trust metadata without private evidence", async () => {
    const att = await issue(); const r = await signTaskRequest(caller, { url: "https://globex.test/a2a", body: {}, attestation: att, cardUrl: "https://acme.test/api/v1/agents/agt_invoice/agent-card" });
    const out = await verifyBeforeAccept(guard(), { skill: "quote.create", params: { amount: 1200, currency: "EUR" }, headers: r.headers }, { fetch: f, now: () => NOW });
    expect(out.accept).toBe(true); if (!out.accept) return;
    expect(out.trust.caller).toMatchObject({ agent_id: "agt_invoice", organization: "Acme", public_id: "pub_acmeinvoice0000000000" });
    expect(out.trust.attestation).toMatchObject({ present: true, valid: true, jti: "aat_1", action: "a2a:quote.create", principal: "prn_ar", organization: "org_acme", delegation_chain_length: 1, human_approved: false });
    expect(out.trust.standing).toMatchObject({ checked: true, state: "verified", organization_verified: true }); expect(out.trust.proof.present).toBe(true);
    expect(out.decision.decision).toBe("ALLOW"); expect(fetched.some((u) => u.endsWith("/api/v1/agents/pub/pub_acmeinvoice0000000000/passport"))).toBe(true);
    // Receiver policy still applies: a €7,000 quote needs Globex's approval regardless of Acme's attestation.
    const big = await verifyBeforeAccept(createGuard({ world: globexWorld, agent: "agt_quote", actionPrefix: "a2a:", now: () => NOW, onApproval: "throw" }), { skill: "quote.create", params: { amount: 7000, currency: "EUR" }, headers: r.headers, callerCard: card }, { fetch: f, now: () => NOW });
    expect(big).toMatchObject({ accept: false, reason: "approval_required" }); expect(refusalToJsonRpc(1, big as never).error.code).toBe(-32001);
  });
  it("refuses: missing card, card without the extension, bad signature, wrong subject/issuer/action, revoked caller, denied by the receiver's authority", async () => {
    const att = await issue(); const headers = (await signTaskRequest(caller, { url: "https://globex.test/a2a", body: {}, attestation: att })).headers;
    expect((await verifyBeforeAccept(guard(), { skill: "quote.create", headers }, { fetch: f })).reason).toBe("caller_card_missing");
    expect((await verifyBeforeAccept(guard(), { skill: "quote.create", headers, callerCard: { name: "x" } }, { fetch: f })).reason).toBe("caller_card_invalid");
    const otherKey = await generateAgentKey("ES256"); const forged = await issueAttestation({ privateKey: otherKey.privateKey, alg: "ES256", kid: "org-acme-1", orgId: "org_acme", attestationId: "aat_x", agentId: "agt_invoice", now: NOW, claims: { v: 1, principal: null, organization: "org_acme", action: "a2a:quote.create", resource: null, decision: "ALLOW", capabilities: [], delegation_chain: [], human_approval: null, decision_id: "d", request_hash: null, policy_version: null } });
    expect(await verifyBeforeAccept(guard(), { skill: "quote.create", headers: { ...headers, "agent-attestation": forged }, callerCard: card }, { fetch: f, now: () => NOW })).toMatchObject({ accept: false, reason: "attestation_invalid" });
    expect(await verifyBeforeAccept(guard(), { skill: "quote.create", headers: { ...headers, "agent-attestation": await issue({}, "agt_someone_else") }, callerCard: card }, { fetch: f, now: () => NOW })).toMatchObject({ accept: false, reason: "attestation_mismatch", detail: expect.stringMatching(/subject/) });
    expect(await verifyBeforeAccept(guard(), { skill: "quote.create", headers: { ...headers, "agent-attestation": await issue({ organization: "org_evil" }, "agt_invoice", "org_evil") }, callerCard: card }, { fetch: f, now: () => NOW })).toMatchObject({ accept: false, reason: "attestation_mismatch", detail: expect.stringMatching(/issued by org_evil/) });
    expect(await verifyBeforeAccept(guard(), { skill: "quote.create", headers: { ...headers, "agent-attestation": await issue({ action: "a2a:refund.create" }) }, callerCard: card }, { fetch: f, now: () => NOW })).toMatchObject({ accept: false, reason: "attestation_mismatch", detail: expect.stringMatching(/attested action/) });
    expect((await verifyBeforeAccept(guard(), { skill: "quote.create", headers: { "agent-proof": "x" }, callerCard: card }, { fetch: f, now: () => NOW, requireAttestation: true })).reason).toBe("attestation_required");
    passportState = "revoked"; expect((await verifyBeforeAccept(guard(), { skill: "quote.create", headers, callerCard: card }, { fetch: f, now: () => NOW })).reason).toBe("caller_revoked"); passportState = "verified";
    const denied = await verifyBeforeAccept(guard(), { skill: "invoice.delete", headers, callerCard: card }, { fetch: f, now: () => NOW, expectedAction: () => null });
    expect(denied).toMatchObject({ accept: false, reason: "denied", decision: { reasons: expect.arrayContaining(["capability_missing"]) } }); expect(refusalToJsonRpc("t1", denied as never).error.code).toBe(-32003);
    expect(JSON.stringify(denied)).not.toContain("evidence");
  });
});

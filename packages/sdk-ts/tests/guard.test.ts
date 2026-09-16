import { describe, it, expect } from "vitest";
import { AgentTrustClient, createGuard, Denied, ApprovalRequired, MnkiError, fromApi } from "../src/index";

const decision = (d: string, extra: Record<string, unknown> = {}) => ({ decision: d, reasons: d === "ALLOW" ? ["identity_verified", "authority_valid"] : ["policy:big-refunds:require_approval"], evidence: [{ step: "policy", status: d === "ALLOW" ? "pass" : "warn", title: "Policy" }], request_id: "req_1", decision_id: "dec_1", approval_id: d === "REQUIRE_APPROVAL" ? "apr_1" : null, latency_ms: 3, ...extra });
function fakeClient(script: { verify: () => unknown; status?: () => unknown; attest?: () => unknown }) {
  const calls: string[] = [];
  const fetcher = (async (url: string, init?: RequestInit) => {
    calls.push(`${init?.method ?? "GET"} ${new URL(url).pathname}`);
    if (url.endsWith("/v1/verify")) return new Response(JSON.stringify(script.verify()), { headers: { "content-type": "application/json" } });
    if (/\/v1\/approvals\/.+\/status$/.test(url)) return new Response(JSON.stringify(script.status?.() ?? { status: "pending" }));
    if (url.endsWith("/v1/attestations")) return new Response(JSON.stringify(script.attest?.() ?? { ok: true, id: "att_1", token: "eyJ.a.b", expires_at: "x", expires_in: 600 }), { status: 201 });
    return new Response(JSON.stringify({ error: "not_found" }), { status: 404 });
  }) as unknown as typeof fetch;
  return { client: new AgentTrustClient({ baseUrl: "https://console.test", apiKey: "at_verify_x", fetch: fetcher }), calls };
}

describe("connected guard", () => {
  it("allows on ALLOW, throws Denied with evidence on DENY", async () => {
    const { client, calls } = fakeClient({ verify: () => decision("ALLOW") });
    const g = createGuard({ client, agent: "agt_1" });
    const r = await g.check("refund.create", { amount: 100, currency: "EUR" });
    expect(r.allowed).toBe(true); expect(calls).toEqual(["POST /api/v1/verify"]);
    const deny = fakeClient({ verify: () => decision("DENY", { reasons: ["constraint_violated"], evidence: [{ step: "constraints", status: "fail", title: "Request exceeds capability constraints" }, { step: "identity", status: "pass", title: "ok" }] }) });
    const e = await createGuard({ client: deny.client, agent: "agt_1" }).check("refund.create", {}).catch((x) => x);
    expect(e).toBeInstanceOf(Denied); expect((e as Denied).evidence[0].status).toBe("fail"); expect((e as Denied).reasons).toEqual(["constraint_violated"]);
  });
  it("waits for approval with bounded backoff, then issues an attestation; rejected/expired/timeout become ApprovalRequired", async () => {
    let polls = 0; const { client, calls } = fakeClient({ verify: () => decision("REQUIRE_APPROVAL"), status: () => ({ id: "apr_1", decision_id: "dec_1", status: ++polls < 3 ? "pending" : "approved", expires_at: null, resolved_at: null }) });
    client.waitForApproval = ((id: string, o = {}) => AgentTrustClient.prototype.waitForApproval.call(client, id, { ...o, sleep: async () => {} })) as typeof client.waitForApproval;
    const r = await createGuard({ client, agent: "agt_1" }).check("refund.create", { amount: 3200, currency: "EUR" });
    expect(r.allowed).toBe(true); expect(r.attestation).toBe("eyJ.a.b"); expect(polls).toBe(3); expect(calls.filter((c) => c.includes("/status")).length).toBe(3);
    const rej = fakeClient({ verify: () => decision("REQUIRE_APPROVAL"), status: () => ({ id: "apr_1", decision_id: "dec_1", status: "rejected" }) });
    const e = await createGuard({ client: rej.client, agent: "agt_1" }).check("refund.create", {}).catch((x) => x);
    expect(e).toBeInstanceOf(ApprovalRequired); expect((e as ApprovalRequired).approvalStatus).toBe("rejected"); expect((e as MnkiError).code).toBe("approval_rejected");
    const t = fakeClient({ verify: () => decision("REQUIRE_APPROVAL"), status: () => ({ id: "apr_1", decision_id: "dec_1", status: "pending" }) });
    t.client.waitForApproval = ((id: string) => AgentTrustClient.prototype.waitForApproval.call(t.client, id, { timeoutMs: 5, sleep: async () => {} })) as typeof t.client.waitForApproval;
    const to = await createGuard({ client: t.client, agent: "agt_1" }).check("refund.create", {}).catch((x) => x);
    expect((to as ApprovalRequired).approvalStatus).toBe("timeout");
    const thrower = fakeClient({ verify: () => decision("REQUIRE_APPROVAL") });
    const th = await createGuard({ client: thrower.client, agent: "agt_1", onApproval: "throw" }).check("x", {}).catch((x) => x);
    expect((th as ApprovalRequired).approvalStatus).toBe("pending"); expect(thrower.calls).toEqual(["POST /api/v1/verify"]);
  });
  it("maps control-plane errors onto the taxonomy", async () => {
    const f = (async () => new Response(JSON.stringify({ error: "plan_limit_reached" }), { status: 402 })) as unknown as typeof fetch;
    const e = await createGuard({ client: { baseUrl: "https://c.test", apiKey: "k", fetch: f }, agent: "a" }).check("t", {}).catch((x) => x);
    expect(e).toBeInstanceOf(MnkiError); expect((e as MnkiError).code).toBe("quota_exceeded"); expect((e as MnkiError).status).toBe(402);
    expect(fromApi(403, "agent_suspended").code).toBe("agent_suspended"); expect(fromApi(400, "invalid_action").code).toBe("invalid_request"); expect(fromApi(429, "rate_limited").code).toBe("rate_limited");
  });
  it("signs the verify request when an identity is given", async () => {
    let headers: Record<string, string> = {};
    const f = (async (_u: string, init?: RequestInit) => { headers = Object.fromEntries(Object.entries((init?.headers ?? {}) as Record<string, string>)); return new Response(JSON.stringify(decision("ALLOW"))); }) as unknown as typeof fetch;
    const { AgentIdentity } = await import("../src/index"); const id = await AgentIdentity.create("agt_1");
    await createGuard({ client: { baseUrl: "https://c.test", apiKey: "k", fetch: f }, agent: "agt_1", identity: id }).check("t", { amount: 1 });
    expect(headers["agent-proof"]).toMatch(/^eyJ/);
  });
});

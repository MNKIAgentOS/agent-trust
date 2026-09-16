import { describe, it, expect } from "vitest";
import { AgentTrustClient, AgentIdentity, AgentTrustError } from "../src/index";
import { verifyRequestProof, bodyHash } from "mnki-verifier";

describe("Agent Trust SDK", () => {
  it("enrols an agent (register + key + rotate), signs verify requests, and surfaces API errors", async () => {
    const seen: { url: string; method: string; headers: Record<string, string>; body: string | undefined }[] = [];
    const fake: typeof fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      const h = new Headers(init?.headers as HeadersInit); const headers: Record<string, string> = {}; h.forEach((v, k) => { headers[k] = v; }); const rec = { url: String(url), method: init?.method ?? "GET", headers, body: init?.body as string | undefined }; seen.push(rec);
      if (rec.url.endsWith("/api/v1/agents") && rec.method === "POST") return Response.json({ ok: true, id: "agt_new", stableId: "agent-trust://org/agent/x" }, { status: 201 });
      if (rec.url.endsWith("/rotate")) return Response.json({ ok: true, credentialId: "crd_1", previousId: null }, { status: 201 });
      if (rec.url.endsWith("/api/v1/verify")) return Response.json({ decision: "ALLOW", reasons: ["request_signed"], evidence: [], request_id: "req_1", decision_id: "dec_1", approval_id: null });
      if (rec.url.includes("/api/v1/status/")) return Response.json({ error: "not_found" }, { status: 404 });
      return Response.json({ error: "unexpected" }, { status: 500 });
    }) as typeof fetch;
    const c = new AgentTrustClient({ baseUrl: "https://staging.mnki.com/", apiKey: "at_verify_x", fetch: fake });
    const { agentId, identity } = await c.agents.enrol({ name: "procurement-bot", riskTier: "low" });
    expect(agentId).toBe("agt_new"); expect(seen[1].url).toBe("https://staging.mnki.com/api/v1/agents/agt_new/rotate");
    expect(JSON.parse(seen[1].body!)).toMatchObject({ kind: "jwt_svid", kid: identity.kid, publicKeyJwk: { kty: "EC" } });
    const d = await c.verify({ agent: agentId, action: "purchase.create", amount: 10, currency: "EUR" }, { identity });
    expect(d.decision).toBe("ALLOW");
    const v = seen[2]; expect(v.headers.authorization).toBe("Bearer at_verify_x"); expect(v.headers["agent-proof"]).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
    const proof = await verifyRequestProof({ proof: v.headers["agent-proof"], resolveKey: async (kid) => (kid === identity.kid ? identity.publicJwk : null), htm: "POST", htu: "https://staging.mnki.com/api/v1/verify", bodyHash: await bodyHash(v.body!), now: new Date() });
    expect(proof.ok).toBe(true);
    // Identities round-trip through export/import and keep signing.
    const again = await AgentIdentity.import(await identity.export());
    expect((await verifyRequestProof({ proof: await again.signProof("POST", "https://x/y", "{}"), resolveKey: async () => identity.publicJwk, htm: "POST", htu: "https://x/y", bodyHash: await bodyHash("{}"), now: new Date() })).ok).toBe(true);
    await expect(c.status("agt_x")).rejects.toMatchObject({ status: 404, code: "not_found" } satisfies Partial<AgentTrustError>);
  });
});

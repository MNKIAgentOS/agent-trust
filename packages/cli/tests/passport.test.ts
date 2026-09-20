import { describe, it, expect } from "vitest";
import { setPassport, formatPassportResult, publishHint } from "../src/passport";

const cfg = { baseUrl: "https://console.test/", apiKey: "at_admin_x" };
const respond = (status: number, body: unknown, calls: { url: string; init: RequestInit }[] = []) => (async (url: string | URL | Request, init?: RequestInit) => { calls.push({ url: String(url), init: init ?? {} }); return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }); }) as unknown as typeof fetch;

describe("mnki passport publish|unpublish", () => {
  it("posts { public } to /api/agents/{id}/public with the API key and returns the console's answer", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const r = await setPassport(cfg, "agt_abc", true, respond(200, { status: "ok", public_id: "pub_x", is_public: true, org_opted_in: true, served: true, passport_url: "https://console.test/agent/pub_x", badge_url: "https://console.test/badge/pub_x.svg" }, calls));
    expect(calls[0].url).toBe("https://console.test/api/agents/agt_abc/public");
    expect(calls[0].init.method).toBe("POST"); expect((calls[0].init.headers as Record<string, string>).authorization).toBe("Bearer at_admin_x"); expect(JSON.parse(String(calls[0].init.body))).toEqual({ public: true });
    expect(r.public_id).toBe("pub_x");
    const text = formatPassportResult("agt_abc", true, r);
    expect(text).toContain("published"); expect(text).toContain("https://console.test/agent/pub_x"); expect(text).toContain("[![Agent Trust passport](https://console.test/badge/pub_x.svg)](https://console.test/agent/pub_x)"); expect(text).not.toContain("Not served yet");
    const calls2: { url: string; init: RequestInit }[] = [];
    await setPassport(cfg, "agt_abc", false, respond(200, { status: "ok", is_public: false }, calls2)); expect(JSON.parse(String(calls2[0].init.body))).toEqual({ public: false });
    expect(formatPassportResult("agt_abc", false, { status: "ok", is_public: false })).toContain("private again");
  });
  it("says plainly when the organisation has not opted in, treats 'unchanged' as success, and explains refusals", async () => {
    expect(formatPassportResult("agt_1", true, { status: "ok", public_id: "pub_y", org_opted_in: false, passport_url: "https://console.test/agent/pub_y", badge_url: "https://console.test/badge/pub_y.svg" })).toContain("Not served yet");
    expect(await setPassport(cfg, "agt_1", true, respond(409, { error: "unchanged" }))).toEqual({ status: "unchanged", is_public: true });
    expect(formatPassportResult("agt_1", true, { status: "unchanged" })).toContain("already public");
    await expect(setPassport(cfg, "agt_1", true, respond(403, { error: "insufficient_scope" }))).rejects.toThrow(/admin-scope key/);
    await expect(setPassport(cfg, "agt_1", true, respond(404, { error: "not_found" }))).rejects.toThrow(/no such agent/);
    await expect(setPassport(cfg, "nope", true, respond(200, {}))).rejects.toThrow(/usage: mnki passport publish/);
  });
  it("identity create prints the one-line hint", () => {
    expect(publishHint("agt_abc")).toBe("Publish a public passport for this agent: mnki passport publish agt_abc");
  });
});

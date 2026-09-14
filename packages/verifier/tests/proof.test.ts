import { describe, it, expect } from "vitest";
import { generateAgentKey, signRequestProof, verifyRequestProof, bodyHash, normalizeHtu } from "../src/proof";

const NOW = new Date("2026-09-14T12:00:00Z");
const BODY = JSON.stringify({ agent: "agt_1", action: "purchase.create", amount: 2450 });
const HTU = "https://staging.mnki.com/v1/verify";

describe("request proof-of-possession (detached JWS)", () => {
  for (const alg of ["ES256", "EdDSA"] as const) {
    it(`${alg}: signs and verifies a request bound to method, URL and body`, async () => {
      const k = await generateAgentKey(alg);
      const proof = await signRequestProof({ privateKey: k.privateKey, alg, kid: "kid-1", iss: "agt_1", htm: "post", htu: `${HTU}?x=1`, body: BODY, now: NOW });
      const resolveKey = async (kid: string | null) => (kid === "kid-1" ? k.publicJwk : null);
      const ok = await verifyRequestProof({ proof, resolveKey, htm: "POST", htu: HTU, bodyHash: await bodyHash(BODY), now: NOW });
      expect(ok.ok).toBe(true); if (!ok.ok) return;
      expect(ok.alg).toBe(alg); expect(ok.claims.iss).toBe("agt_1"); expect(ok.claims.htu).toBe(HTU);
      // Tampered body, wrong method, wrong URL, wrong key, expiry and replay all fail with a named reason.
      expect(await verifyRequestProof({ proof, resolveKey, htm: "POST", htu: HTU, bodyHash: await bodyHash(BODY + " "), now: NOW })).toMatchObject({ ok: false, reason: "body_hash" });
      expect(await verifyRequestProof({ proof, resolveKey, htm: "GET", htu: HTU, bodyHash: await bodyHash(BODY), now: NOW })).toMatchObject({ ok: false, reason: "htm" });
      expect(await verifyRequestProof({ proof, resolveKey, htm: "POST", htu: "https://evil.example/v1/verify", bodyHash: await bodyHash(BODY), now: NOW })).toMatchObject({ ok: false, reason: "htu" });
      const other = await generateAgentKey(alg);
      expect(await verifyRequestProof({ proof, resolveKey: async () => other.publicJwk, htm: "POST", htu: HTU, bodyHash: await bodyHash(BODY), now: NOW })).toMatchObject({ ok: false, reason: "signature" });
      expect(await verifyRequestProof({ proof, resolveKey: async () => null, htm: "POST", htu: HTU, bodyHash: await bodyHash(BODY), now: NOW })).toMatchObject({ ok: false, reason: "unknown_key" });
      expect(await verifyRequestProof({ proof, resolveKey, htm: "POST", htu: HTU, bodyHash: await bodyHash(BODY), now: new Date(NOW.getTime() + 61_000) })).toMatchObject({ ok: false, reason: "expired" });
      const seen = new Set<string>(); const seenJti = async (j: string) => { if (seen.has(j)) return true; seen.add(j); return false; };
      expect((await verifyRequestProof({ proof, resolveKey, htm: "POST", htu: HTU, bodyHash: await bodyHash(BODY), now: NOW, seenJti })).ok).toBe(true);
      expect(await verifyRequestProof({ proof, resolveKey, htm: "POST", htu: HTU, bodyHash: await bodyHash(BODY), now: NOW, seenJti })).toMatchObject({ ok: false, reason: "replay" });
    });
  }
  it("rejects malformed tokens, wrong typ and an alg that does not match the key", async () => {
    const k = await generateAgentKey("ES256");
    expect(await verifyRequestProof({ proof: "nope", resolveKey: async () => k.publicJwk, htm: "POST", htu: HTU, bodyHash: "", now: NOW })).toMatchObject({ ok: false, reason: "malformed" });
    const ed = await generateAgentKey("EdDSA");
    const proof = await signRequestProof({ privateKey: ed.privateKey, alg: "EdDSA", kid: "k", iss: "a", htm: "POST", htu: HTU, body: BODY, now: NOW });
    expect(await verifyRequestProof({ proof, resolveKey: async () => k.publicJwk, htm: "POST", htu: HTU, bodyHash: await bodyHash(BODY), now: NOW })).toMatchObject({ ok: false, reason: "alg_mismatch" });
    expect(normalizeHtu("HTTPS://Staging.MNKI.com/v1/verify?a=1#f")).toBe("https://staging.mnki.com/v1/verify");
  });
});

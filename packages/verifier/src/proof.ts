/**
 * Request proof-of-possession — a detached JWS the agent attaches to each
 * request (header `Agent-Proof`), modelled on DPoP (RFC 9449):
 *
 *   header  { alg: "ES256" | "EdDSA", typ: "agent-trust-proof+jwt", kid }
 *   payload { iss: <agent id>, htm, htu, iat, exp, jti, rh: b64url(sha256(body)) }
 *
 * Pure WebCrypto (Node ≥ 20, Workers, browsers). No new cryptography: JWS
 * with ES256 (ECDSA P-256 / SHA-256) or EdDSA (Ed25519).
 */

export type ProofAlg = "ES256" | "EdDSA";
export const PROOF_TYP = "agent-trust-proof+jwt";
const enc = new TextEncoder();

export function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = ""; for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
const b64urlJson = (o: unknown) => b64url(enc.encode(JSON.stringify(o)));

/** b64url(sha256(body)) — the `rh` claim. Hash the exact bytes on the wire. */
export async function bodyHash(body: string | Uint8Array | ArrayBuffer): Promise<string> {
  const bytes = typeof body === "string" ? enc.encode(body) : body instanceof Uint8Array ? body : new Uint8Array(body);
  return b64url(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
}

/** Normalise the target URI the way DPoP does: scheme + host (lower-case) + path, no query or fragment. */
export function normalizeHtu(u: string): string {
  try { const x = new URL(u); return `${x.protocol.toLowerCase()}//${x.host.toLowerCase()}${x.pathname}`; } catch { return u; }
}

const algParams = (alg: ProofAlg) => (alg === "ES256" ? ({ name: "ECDSA", hash: "SHA-256" } as EcdsaParams) : ({ name: "Ed25519" } as Algorithm));
const importParams = (alg: ProofAlg) => (alg === "ES256" ? ({ name: "ECDSA", namedCurve: "P-256" } as EcKeyImportParams) : ({ name: "Ed25519" } as Algorithm));

/** Generate an agent key pair. The public JWK is what gets registered as the credential's `public_key_jwk`. */
export async function generateAgentKey(alg: ProofAlg = "ES256"): Promise<{ alg: ProofAlg; privateKey: CryptoKey; publicJwk: JsonWebKey }> {
  const kp = (alg === "ES256"
    ? await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
    : await crypto.subtle.generateKey({ name: "Ed25519" } as Algorithm, true, ["sign", "verify"])) as CryptoKeyPair;
  const publicJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  delete publicJwk.key_ops; delete publicJwk.ext;
  return { alg, privateKey: kp.privateKey, publicJwk };
}

export function algForJwk(jwk: JsonWebKey): ProofAlg | null {
  if (jwk.kty === "EC" && jwk.crv === "P-256") return "ES256";
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") return "EdDSA";
  return null;
}

export interface SignProofInput { privateKey: CryptoKey; alg: ProofAlg; kid: string; iss: string; htm: string; htu: string; body: string | Uint8Array | ArrayBuffer; now?: Date; ttlSeconds?: number; jti?: string }

/** Produce the compact JWS for one request. */
export async function signRequestProof(i: SignProofInput): Promise<string> {
  const iat = Math.floor((i.now ?? new Date()).getTime() / 1000);
  const payload = { iss: i.iss, htm: i.htm.toUpperCase(), htu: normalizeHtu(i.htu), iat, exp: iat + (i.ttlSeconds ?? 60), jti: i.jti ?? b64url(crypto.getRandomValues(new Uint8Array(16))), rh: await bodyHash(i.body) };
  const signingInput = `${b64urlJson({ alg: i.alg, typ: PROOF_TYP, kid: i.kid })}.${b64urlJson(payload)}`;
  const sig = await crypto.subtle.sign(algParams(i.alg), i.privateKey, enc.encode(signingInput));
  return `${signingInput}.${b64url(sig)}`;
}

export interface ProofClaims { iss: string; htm: string; htu: string; iat: number; exp: number; jti: string; rh: string }
export interface VerifyProofInput {
  proof: string;
  /** Resolve the public key for the `kid` in the header (null when the header has none). */
  resolveKey: (kid: string | null) => Promise<JsonWebKey | null>;
  htm: string; htu: string; bodyHash: string; now: Date;
  /** Accept `iat` this far in the future (clock skew) and reject proofs older than `maxAgeSeconds`. */
  maxSkewSeconds?: number; maxAgeSeconds?: number;
  /** Replay guard: return true when this jti was already seen (and remember it until `exp`). */
  seenJti?: (jti: string, exp: number) => Promise<boolean>;
}
export type ProofResult = { ok: true; kid: string | null; alg: ProofAlg; claims: ProofClaims } | { ok: false; reason: string; kid?: string | null };

/** Verify a request proof. Never throws. */
export async function verifyRequestProof(i: VerifyProofInput): Promise<ProofResult> {
  const parts = i.proof.split(".");
  if (parts.length !== 3) return { ok: false, reason: "malformed" };
  let header: { alg?: string; typ?: string; kid?: string }; let claims: Partial<ProofClaims>;
  try { header = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0]))); claims = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1]))); } catch { return { ok: false, reason: "malformed" }; }
  const kid = typeof header.kid === "string" ? header.kid : null;
  if (header.typ !== PROOF_TYP) return { ok: false, reason: "typ", kid };
  if (header.alg !== "ES256" && header.alg !== "EdDSA") return { ok: false, reason: "alg", kid };
  const alg = header.alg as ProofAlg;
  const jwk = await i.resolveKey(kid);
  if (!jwk) return { ok: false, reason: "unknown_key", kid };
  if (algForJwk(jwk) !== alg) return { ok: false, reason: "alg_mismatch", kid };
  let key: CryptoKey;
  try { key = await crypto.subtle.importKey("jwk", jwk, importParams(alg), false, ["verify"]); } catch { return { ok: false, reason: "bad_key", kid }; }
  let valid = false;
  try { valid = await crypto.subtle.verify(algParams(alg), key, b64urlDecode(parts[2]) as BufferSource, enc.encode(`${parts[0]}.${parts[1]}`)); } catch { valid = false; }
  if (!valid) return { ok: false, reason: "signature", kid };
  const c = claims;
  if (typeof c.iss !== "string" || typeof c.htm !== "string" || typeof c.htu !== "string" || typeof c.iat !== "number" || typeof c.exp !== "number" || typeof c.jti !== "string" || typeof c.rh !== "string") return { ok: false, reason: "claims", kid };
  if (c.htm.toUpperCase() !== i.htm.toUpperCase()) return { ok: false, reason: "htm", kid };
  if (normalizeHtu(c.htu) !== normalizeHtu(i.htu)) return { ok: false, reason: "htu", kid };
  if (c.rh !== i.bodyHash) return { ok: false, reason: "body_hash", kid };
  const t = Math.floor(i.now.getTime() / 1000); const skew = i.maxSkewSeconds ?? 300; const maxAge = i.maxAgeSeconds ?? 300;
  if (c.iat > t + skew) return { ok: false, reason: "iat_future", kid };
  if (c.exp <= t) return { ok: false, reason: "expired", kid };
  if (t - c.iat > maxAge) return { ok: false, reason: "too_old", kid };
  if (i.seenJti && (await i.seenJti(c.jti, c.exp))) return { ok: false, reason: "replay", kid };
  return { ok: true, kid, alg, claims: c as ProofClaims };
}

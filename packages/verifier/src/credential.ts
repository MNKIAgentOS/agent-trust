/**
 * Portable, signed authority — two JWT profiles signed with an organization key
 * (ES256 / EdDSA, published as JWKS). Standard JWS; the Agent Trust semantics
 * live under the `atp` claim.
 *
 *   Delegation credential  typ "agent-trust-delegation+jwt"
 *     iss = issuing organization, sub = subject agent, jti = delegation id,
 *     atp = { v, issuer, capabilities, constraints, effective, parent, parent_hash, depth, task }
 *     A chain is verified offline: each link's parent_hash must equal
 *     b64url(sha256(parent token)) and each link's capabilities ⊆ parent effective.
 *
 *   Agent Authorization Attestation  typ "agent-trust-attestation+jwt"
 *     "what this agent may do right now, and who can prove it" — short-lived,
 *     issued from a decision, verifiable by any relying party holding the JWKS.
 */
import { b64url, b64urlDecode, bodyHash as sha256b64url, algForJwk, type ProofAlg } from "./proof";
import { attenuate, isSubset } from "./delegation/attenuate";
import type { CapSet, Constraints } from "./types";

export const DELEGATION_TYP = "agent-trust-delegation+jwt";
export const ATTESTATION_TYP = "agent-trust-attestation+jwt";
export const MAX_CHAIN = 8;
const enc = new TextEncoder(); const dec = new TextDecoder();
const b64urlJson = (o: unknown) => b64url(enc.encode(JSON.stringify(o)));
const signParams = (alg: ProofAlg) => (alg === "ES256" ? ({ name: "ECDSA", hash: "SHA-256" } as EcdsaParams) : ({ name: "Ed25519" } as Algorithm));
const importParams = (alg: ProofAlg) => (alg === "ES256" ? ({ name: "ECDSA", namedCurve: "P-256" } as EcKeyImportParams) : ({ name: "Ed25519" } as Algorithm));

export interface JwtHeader { alg: ProofAlg; typ: string; kid: string }
export interface SignJwtInput { privateKey: CryptoKey; alg: ProofAlg; kid: string; typ: string; payload: Record<string, unknown> }
export async function signJwt(i: SignJwtInput): Promise<string> {
  const input = `${b64urlJson({ alg: i.alg, typ: i.typ, kid: i.kid })}.${b64urlJson(i.payload)}`;
  return `${input}.${b64url(await crypto.subtle.sign(signParams(i.alg), i.privateKey, enc.encode(input)))}`;
}

export type KeyResolver = (kid: string, iss: string) => Promise<JsonWebKey | null>;
export type JwtResult<T> = { ok: true; header: JwtHeader; payload: T } | { ok: false; reason: string };

/** Decode without verifying — for reading `kid`/`iss` before key resolution. */
export function decodeJwt<T = Record<string, unknown>>(token: string): { header: JwtHeader; payload: T } | null {
  const p = token.split("."); if (p.length !== 3) return null;
  try { return { header: JSON.parse(dec.decode(b64urlDecode(p[0]))), payload: JSON.parse(dec.decode(b64urlDecode(p[1]))) }; } catch { return null; }
}

/** Verify signature, typ and time claims. Never throws. */
export async function verifyJwt<T extends { iss?: string; exp?: number; nbf?: number; iat?: number }>(token: string, typ: string, resolveKey: KeyResolver, now: Date, opts: { maxSkewSeconds?: number } = {}): Promise<JwtResult<T>> {
  const d = decodeJwt<T>(token); if (!d) return { ok: false, reason: "malformed" };
  const { header, payload } = d;
  if (header.typ !== typ) return { ok: false, reason: "typ" };
  if (header.alg !== "ES256" && header.alg !== "EdDSA") return { ok: false, reason: "alg" };
  if (typeof header.kid !== "string" || typeof payload.iss !== "string") return { ok: false, reason: "claims" };
  const jwk = await resolveKey(header.kid, payload.iss); if (!jwk) return { ok: false, reason: "unknown_key" };
  if (algForJwk(jwk) !== header.alg) return { ok: false, reason: "alg_mismatch" };
  let key: CryptoKey; try { key = await crypto.subtle.importKey("jwk", jwk, importParams(header.alg), false, ["verify"]); } catch { return { ok: false, reason: "bad_key" }; }
  const parts = token.split(".");
  let valid = false; try { valid = await crypto.subtle.verify(signParams(header.alg), key, b64urlDecode(parts[2]) as BufferSource, enc.encode(`${parts[0]}.${parts[1]}`)); } catch { valid = false; }
  if (!valid) return { ok: false, reason: "signature" };
  const t = Math.floor(now.getTime() / 1000); const skew = opts.maxSkewSeconds ?? 300;
  if (typeof payload.exp === "number" && payload.exp <= t) return { ok: false, reason: "expired" };
  if (typeof payload.nbf === "number" && payload.nbf > t + skew) return { ok: false, reason: "not_yet_valid" };
  if (typeof payload.iat === "number" && payload.iat > t + skew) return { ok: false, reason: "iat_future" };
  return { ok: true, header, payload };
}

// ---------- Delegation credential ----------
export interface DelegationClaims { v: 1; issuer: { type: "principal" | "agent"; id: string }; capabilities: CapSet; constraints?: Constraints | Record<string, unknown>; effective: CapSet; parent: string | null; parent_hash: string | null; depth: number; task?: string | null }
export interface DelegationJwt { iss: string; sub: string; jti: string; iat: number; nbf?: number; exp?: number; atp: DelegationClaims }
export interface IssueDelegationInput { privateKey: CryptoKey; alg: ProofAlg; kid: string; orgId: string; delegationId: string; subjectAgentId: string; issuer: DelegationClaims["issuer"]; capabilities: CapSet; constraints?: DelegationClaims["constraints"]; effective: CapSet; parentId: string | null; parentToken: string | null; depth: number; task?: string | null; notBefore?: string | null; notAfter?: string | null; now?: Date }

export async function issueDelegationCredential(i: IssueDelegationInput): Promise<string> {
  const iat = Math.floor((i.now ?? new Date()).getTime() / 1000);
  const payload: DelegationJwt = { iss: i.orgId, sub: i.subjectAgentId, jti: i.delegationId, iat,
    atp: { v: 1, issuer: i.issuer, capabilities: i.capabilities, constraints: i.constraints, effective: i.effective, parent: i.parentId, parent_hash: i.parentToken ? await sha256b64url(i.parentToken) : null, depth: i.depth, task: i.task ?? null } };
  if (i.notBefore) payload.nbf = Math.floor(Date.parse(i.notBefore) / 1000);
  if (i.notAfter) payload.exp = Math.floor(Date.parse(i.notAfter) / 1000);
  return signJwt({ privateKey: i.privateKey, alg: i.alg, kid: i.kid, typ: DELEGATION_TYP, payload: payload as unknown as Record<string, unknown> });
}

export type CredentialChainResult = { ok: true; effective: CapSet; chain: string[]; subject: string; root_issuer: DelegationClaims["issuer"] } | { ok: false; at: number; reason: string };

/** Verify a chain of delegation credentials root → leaf, offline, against the issuing organizations' JWKS. */
export async function verifyDelegationChain(tokens: string[], resolveKey: KeyResolver, now: Date): Promise<CredentialChainResult> {
  if (!tokens.length) return { ok: false, at: 0, reason: "empty" };
  if (tokens.length > MAX_CHAIN) return { ok: false, at: tokens.length, reason: "too_long" };
  let prev: { token: string; payload: DelegationJwt } | null = null; const chain: string[] = []; let effective: CapSet = []; let rootIssuer: DelegationClaims["issuer"] | null = null;
  for (let i = 0; i < tokens.length; i++) {
    const r = await verifyJwt<DelegationJwt>(tokens[i], DELEGATION_TYP, resolveKey, now);
    if (!r.ok) return { ok: false, at: i, reason: r.reason };
    const p = r.payload; const a = p.atp;
    if (!a || a.v !== 1 || !Array.isArray(a.capabilities) || !Array.isArray(a.effective) || typeof p.sub !== "string" || typeof p.jti !== "string") return { ok: false, at: i, reason: "claims" };
    if (i === 0) {
      if (a.parent !== null || a.depth !== 0) return { ok: false, at: i, reason: "root_expected" };
      if (a.issuer?.type !== "principal") return { ok: false, at: i, reason: "root_requires_principal" };
      effective = a.capabilities; rootIssuer = a.issuer;
      if (JSON.stringify(a.effective) !== JSON.stringify(effective)) return { ok: false, at: i, reason: "effective_mismatch" };
    } else {
      const pp = prev!.payload;
      if (a.parent !== pp.jti) return { ok: false, at: i, reason: "parent_link" };
      if (a.parent_hash !== (await sha256b64url(prev!.token))) return { ok: false, at: i, reason: "parent_hash" };
      if (a.depth !== pp.atp.depth + 1) return { ok: false, at: i, reason: "depth" };
      if (a.issuer?.type !== "agent" || a.issuer.id !== pp.sub) return { ok: false, at: i, reason: "issuer_must_be_parent_subject" };
      if (!isSubset(a.capabilities, effective)) return { ok: false, at: i, reason: "exceeds_parent" };
      effective = attenuate(effective, a.capabilities);
      if (JSON.stringify(a.effective) !== JSON.stringify(effective)) return { ok: false, at: i, reason: "effective_mismatch" };
    }
    chain.push(p.jti); prev = { token: tokens[i], payload: p };
  }
  return { ok: true, effective, chain, subject: prev!.payload.sub, root_issuer: rootIssuer! };
}

// ---------- Agent Authorization Attestation ----------
export interface AttestationClaims { v: 1; principal: string | null; organization: string; action: string; resource: string | null; decision: "ALLOW" | "REQUIRE_APPROVAL"; capabilities: CapSet; delegation_chain: string[]; human_approval: { required: boolean; approved: boolean; approver: string | null; approval_id: string | null } | null; decision_id: string; request_hash: string | null; policy_version: string | null }
export interface AttestationJwt { iss: string; sub: string; jti: string; iat: number; exp: number; aud?: string; atp: AttestationClaims }
export interface IssueAttestationInput { privateKey: CryptoKey; alg: ProofAlg; kid: string; orgId: string; attestationId: string; agentId: string; audience?: string | null; ttlSeconds?: number; now?: Date; claims: AttestationClaims }

export async function issueAttestation(i: IssueAttestationInput): Promise<string> {
  const iat = Math.floor((i.now ?? new Date()).getTime() / 1000);
  const payload: AttestationJwt = { iss: i.orgId, sub: i.agentId, jti: i.attestationId, iat, exp: iat + (i.ttlSeconds ?? 600), atp: i.claims };
  if (i.audience) payload.aud = i.audience;
  return signJwt({ privateKey: i.privateKey, alg: i.alg, kid: i.kid, typ: ATTESTATION_TYP, payload: payload as unknown as Record<string, unknown> });
}

export type AttestationResult = { ok: true; payload: AttestationJwt; expires_in: number } | { ok: false; reason: string };
export async function verifyAttestation(token: string, resolveKey: KeyResolver, now: Date): Promise<AttestationResult> {
  const r = await verifyJwt<AttestationJwt>(token, ATTESTATION_TYP, resolveKey, now);
  if (!r.ok) return r;
  const p = r.payload;
  if (!p.atp || p.atp.v !== 1 || typeof p.sub !== "string" || typeof p.jti !== "string" || typeof p.exp !== "number" || typeof p.atp.action !== "string") return { ok: false, reason: "claims" };
  return { ok: true, payload: p, expires_in: p.exp - Math.floor(now.getTime() / 1000) };
}

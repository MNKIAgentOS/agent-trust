/**
 * `agenttrust conformance --level N [--dir <conformance dir>]` — run the certification vectors against the
 * TypeScript verifier and print a report. Third-party implementations run the same fixtures with their own
 * runner; passing every vector of a level (and all lower levels) is what the level certifies.
 */
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { verify, verifyDelegationChain, verifyRequestProof, verifyAttestation, parseVerifyRequest, type VerifierDeps } from "mnki-verifier";

export interface ConformanceReport { level: number; passed: number; failed: number; failures: { id: string; title: string; detail: string }[] }

export function findConformanceDir(start = process.cwd()): string | null {
  let dir = start;
  for (let i = 0; i < 6; i++) { const c = join(dir, "conformance"); if (existsSync(join(c, "vectors"))) return c; const up = dirname(dir); if (up === dir) break; dir = up; }
  return null;
}

type Vec = { id: string; title: string; now: string; level?: number; keys?: Record<string, Record<string, JsonWebKey>>; case?: Record<string, unknown> & { kind: string }; world: Record<string, unknown> & { peers?: { entity_id: string; name: string; trust_level: 1 | 2 }[] }; request: Record<string, unknown>; expect: Record<string, unknown> };
const load = (dir: string): Vec[] => (existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith(".json")).sort().map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")) as Vec) : []);

function depsFrom(w: Vec["world"], keys: Vec["keys"]): VerifierDeps {
  const W = w as { agent: { id: string; stable_id: string } | null; credential: unknown; principals: { id: string }[]; delegations: { id: string; subject_agent_id: string; parent_id: string | null }[]; capabilities: unknown[]; revoked: string[]; attestations: unknown[]; policy: unknown; peers?: { entity_id: string; name: string; trust_level: 1 | 2 }[] };
  const revoked = new Set(W.revoked ?? []);
  return {
    getAgent: async (ref) => (W.agent && (ref === W.agent.id || ref === W.agent.stable_id) ? (W.agent as never) : null),
    getActiveCredential: async () => W.credential as never, getPrincipal: async (id) => (W.principals.find((p) => p.id === id) as never) ?? null,
    getLeafDelegation: async (agentId, delegationId) => ((W.delegations.find((d) => (delegationId ? d.id === delegationId : d.subject_agent_id === agentId && d.parent_id !== null)) ?? W.delegations.find((d) => d.subject_agent_id === agentId)) as never) ?? null,
    getDelegationAncestry: async () => W.delegations as never, getAgentCapabilities: async () => W.capabilities as never, isRevoked: async (_t, id) => revoked.has(id), getAttestations: async () => W.attestations as never, getPolicy: async () => W.policy as never,
    getOrgKey: async (kid, iss) => keys?.[iss]?.[kid] ?? null, getFederatedIssuer: async (iss) => { const p = (W.peers ?? []).find((x) => x.entity_id === iss); return p ? { name: p.name, trust_level: p.trust_level } : null; },
  };
}

async function runOne(v: Vec): Promise<string | null> {
  const now = new Date(v.now); const e = v.expect; const keys = v.keys ?? {};
  const resolver = async (kid: string, iss: string) => keys[iss]?.[kid] ?? null;
  const expectEq = (name: string, got: unknown, want: unknown) => (JSON.stringify(got) === JSON.stringify(want) ? null : `${name}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
  if (v.case?.kind === "delegation_chain") { const r = await verifyDelegationChain(v.case.tokens as string[], resolver, now); if (r.ok !== e.ok) return `ok=${r.ok} (${!r.ok ? r.reason : ""})`; return r.ok ? expectEq("chain", r.chain, e.chain) ?? expectEq("subject", r.subject, e.subject) : expectEq("reason", r.reason, e.reason) ?? expectEq("at", r.at, e.at); }
  if (v.case?.kind === "request_proof") { const c = v.case as unknown as { proof: string; agent_keys: Record<string, JsonWebKey>; htm: string; htu: string; body_hash: string }; const r = await verifyRequestProof({ proof: c.proof, resolveKey: async (kid) => (kid ? c.agent_keys[kid] ?? null : null), htm: c.htm, htu: c.htu, bodyHash: c.body_hash, now }); if (r.ok !== e.ok) return `ok=${r.ok}${!r.ok ? ` (${r.reason})` : ""}`; return r.ok ? expectEq("iss", r.claims.iss, e.iss) ?? expectEq("alg", r.alg, e.alg) : expectEq("reason", r.reason, e.reason); }
  if (v.case?.kind === "attestation") { const r = await verifyAttestation(v.case.token as string, resolver, now); if (r.ok !== e.ok) return `ok=${r.ok}${!r.ok ? ` (${r.reason})` : ""}`; return r.ok ? expectEq("sub", r.payload.sub, e.sub) ?? expectEq("expires_in", r.expires_in, e.expires_in) : expectEq("reason", r.reason, e.reason); }
  const parsed = parseVerifyRequest(v.request); if (!parsed.ok) return `request invalid: ${parsed.code}`;
  const r = await verify(parsed.request, depsFrom(v.world, keys), { now });
  if (r.decision !== e.decision) return `decision ${r.decision}, want ${e.decision} (${r.reasons.join(", ")})`;
  for (const reason of (e.reasons_include as string[]) ?? []) if (!r.reasons.includes(reason)) return `missing reason ${reason} (${r.reasons.join(", ")})`;
  if (e.reasons_exact) { const d = expectEq("reasons", r.reasons, e.reasons_exact); if (d) return d; }
  for (const [step, status] of Object.entries((e.evidence as Record<string, string>) ?? {})) { const got = r.evidence.find((x) => x.step === step)?.status; if (got !== status) return `step ${step}: ${got}, want ${status}`; }
  return null;
}

export async function runConformance(dir: string, level: number): Promise<ConformanceReport[]> {
  const sets: { level: number; vectors: Vec[] }[] = [{ level: 1, vectors: load(join(dir, "vectors")) }, { level: 2, vectors: load(join(dir, "crypto")).filter((v) => v.level === 2) }, { level: 3, vectors: load(join(dir, "crypto")).filter((v) => v.level === 3) }];
  const out: ConformanceReport[] = [];
  for (const s of sets.filter((x) => x.level <= level)) {
    const rep: ConformanceReport = { level: s.level, passed: 0, failed: 0, failures: [] };
    for (const v of s.vectors) { let detail: string | null; try { detail = await runOne(v); } catch (err) { detail = `threw: ${err instanceof Error ? err.message : String(err)}`; } if (detail) { rep.failed++; rep.failures.push({ id: v.id, title: v.title, detail }); } else rep.passed++; }
    out.push(rep);
  }
  return out;
}

export function formatReport(reports: ConformanceReport[], level: number): { text: string; ok: boolean } {
  const names = { 1: "Verifier", 2: "Credentials", 3: "Federation" } as const;
  const lines: string[] = []; let ok = true;
  for (const r of reports) { const pass = r.failed === 0 && r.passed > 0; if (!pass) ok = false; lines.push(`Level ${r.level} ${names[r.level as 1 | 2 | 3]}: ${pass ? "PASS" : "FAIL"} — ${r.passed} passed, ${r.failed} failed`); for (const f of r.failures) lines.push(`  ✕ ${f.id} ${f.title}\n      ${f.detail}`); }
  lines.push(ok ? `\nAgent Trust conformance: Level ${level} — all vectors reproduced. Badge: "Agent Trust Level ${level} · profile v0.1"` : `\nAgent Trust conformance: NOT conformant at level ${level}.`);
  return { text: lines.join("\n"), ok };
}

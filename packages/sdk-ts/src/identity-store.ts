/**
 * Node-only identity persistence: `MNKI_IDENTITY` (base64 or JSON of an ExportedIdentity) wins, else
 * `~/.mnki/identity.json` (0600). `ensureIdentity` enrols on first run. Subpath export so the core stays
 * runtime-neutral: `import { loadIdentity } from "mnki-sdk/identity-store"`.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { AgentIdentity, AgentTrustClient, type ExportedIdentity, type RegisterAgentInput } from "./index";

export interface IdentityStore { load(): Promise<ExportedIdentity | null>; save(e: ExportedIdentity): Promise<void> }
export const defaultIdentityPath = (): string => join(process.env.MNKI_HOME ?? join(homedir(), ".mnki"), "identity.json");

export function fileStore(path = defaultIdentityPath()): IdentityStore {
  return {
    async load() { const env = process.env.MNKI_IDENTITY; if (env) return JSON.parse(env.trim().startsWith("{") ? env : Buffer.from(env, "base64").toString("utf8")) as ExportedIdentity; return existsSync(path) ? (JSON.parse(readFileSync(path, "utf8")) as ExportedIdentity) : null; },
    async save(e) { mkdirSync(join(path, ".."), { recursive: true }); writeFileSync(path, JSON.stringify(e, null, 2)); try { chmodSync(path, 0o600); } catch { /* windows */ } },
  };
}
export async function loadIdentity(store: IdentityStore = fileStore()): Promise<AgentIdentity | null> { const e = await store.load(); return e ? AgentIdentity.import(e) : null; }
export async function saveIdentity(identity: AgentIdentity, store: IdentityStore = fileStore()): Promise<void> { await store.save(await identity.export()); }
/** Load the stored identity, or enrol a new agent with the control plane and store its key. */
export async function ensureIdentity(client: AgentTrustClient, agent: RegisterAgentInput, store: IdentityStore = fileStore()): Promise<{ identity: AgentIdentity; created: boolean }> {
  const existing = await loadIdentity(store); if (existing) return { identity: existing, created: false };
  const r = await client.agents.enrol(agent); await saveIdentity(r.identity, store); return { identity: r.identity, created: true };
}

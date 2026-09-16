/**
 * CLI configuration: `~/.mnki/config.json` (private keys inside — chmod 600). Env overrides `MNKI_HOME`,
 * `MNKI_URL`, `MNKI_API_KEY`. A config left by the old `agenttrust` CLI in `~/.agenttrust` is copied once.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync, copyFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { ExportedIdentity } from "mnki-sdk";

export interface Config { baseUrl: string; apiKey: string; identities: Record<string, ExportedIdentity>; telemetry?: boolean; mode?: "local" | "cloud" }

/** Resolved at call time so tests and `MNKI_HOME` changes take effect without re-importing. */
export const configDir = (): string => process.env.MNKI_HOME ?? join(homedir(), ".mnki");
export const configPath = (): string => join(configDir(), "config.json");
const legacyPath = (): string => join(process.env.AGENTTRUST_HOME ?? homedir(), ".agenttrust", "config.json");

function migrateLegacy(): void {
  const cfg = configPath(), legacy = legacyPath();
  if (existsSync(cfg) || !existsSync(legacy)) return;
  try { mkdirSync(configDir(), { recursive: true }); copyFileSync(legacy, cfg); chmodSync(cfg, 0o600); console.error(`Copied ${legacy} → ${cfg}`); } catch { /* best effort */ }
}

/** Stored config with environment overrides applied (env never persisted). */
export function loadConfig(): Config | null {
  migrateLegacy();
  const CONFIG = configPath();
  const stored = existsSync(CONFIG) ? (JSON.parse(readFileSync(CONFIG, "utf8")) as Config) : null;
  const url = process.env.MNKI_URL, key = process.env.MNKI_API_KEY;
  if (!stored && !(url && key)) return null;
  const base: Config = stored ?? { baseUrl: "", apiKey: "", identities: {} };
  return { ...base, identities: base.identities ?? {}, ...(url ? { baseUrl: url } : {}), ...(key ? { apiKey: key } : {}) };
}
export function saveConfig(c: Config): void {
  mkdirSync(configDir(), { recursive: true });
  writeFileSync(configPath(), JSON.stringify(c, null, 2));
  try { chmodSync(configPath(), 0o600); } catch { /* windows */ }
}
export const telemetryEnabled = (c: Config | null): boolean => process.env.MNKI_TELEMETRY !== "0" && c?.telemetry !== false;

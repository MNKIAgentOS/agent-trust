/**
 * Opt-in, anonymous product telemetry. One random install id, allow-listed event names, a tiny prop bag —
 * never arguments, agent names, hosts or URLs. Off with `MNKI_TELEMETRY=0` or `mnki telemetry off`.
 * Fire-and-forget: a failure never surfaces to the user.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { platform } from "node:os";
import { randomUUID } from "node:crypto";
import { configDir, loadConfig, telemetryEnabled } from "./config";

export const TELEMETRY_URL = process.env.MNKI_TELEMETRY_URL ?? "https://mnki.com/api/telemetry";
export type Props = Record<string, string | number | boolean>;

export function installId(): string {
  const p = join(configDir(), "install-id");
  if (existsSync(p)) return readFileSync(p, "utf8").trim();
  const id = `inst-${randomUUID()}`; mkdirSync(configDir(), { recursive: true }); writeFileSync(p, id); return id;
}
export function track(event: string, props: Props = {}, fetcher: typeof fetch = fetch): void {
  if (!telemetryEnabled(loadConfig())) return;
  try {
    const body = JSON.stringify({ install_id: installId(), event, props: { ...props, os: platform() }, source: "cli", version: process.env.npm_package_version ?? "dev" });
    void fetcher(TELEMETRY_URL, { method: "POST", headers: { "content-type": "application/json" }, body, signal: AbortSignal.timeout(1500) }).catch(() => undefined);
  } catch { /* never surface */ }
}

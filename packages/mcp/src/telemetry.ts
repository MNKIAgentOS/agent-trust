/** Opt-in, anonymous: proxy_decision / proxy_error with mode and decision only. Off with MNKI_TELEMETRY=0. */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";

const dir = () => process.env.MNKI_HOME ?? join(homedir(), ".mnki");
export function installId(): string { const p = join(dir(), "install-id"); if (existsSync(p)) return readFileSync(p, "utf8").trim(); const id = `inst-${randomUUID()}`; mkdirSync(dir(), { recursive: true }); writeFileSync(p, id); return id; }
export function track(enabled: boolean, event: "proxy_decision" | "proxy_error", props: Record<string, string | number | boolean>, fetcher: typeof fetch = fetch): void {
  if (!enabled) return;
  try { void fetcher(process.env.MNKI_TELEMETRY_URL ?? "https://mnki.com/api/telemetry", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ install_id: installId(), event, props, source: "mcp" }), signal: AbortSignal.timeout(1500) }).catch(() => undefined); } catch { /* never surface */ }
}

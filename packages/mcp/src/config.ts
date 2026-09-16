/** Proxy configuration from argv, environment and ~/.mnki/config.json (url/key). */
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { GuardMode } from "mnki-sdk";

export interface ProxyConfig {
  agent: string; server: string; mode: GuardMode; baseUrl: string; apiKey: string;
  upstream: { kind: "stdio"; command: string; args: string[] } | { kind: "http"; url: string; headers: Record<string, string> };
  identityFile?: string; amountMap?: string; approvalTimeoutMs: number; approvalWait: boolean; telemetry: boolean;
}
const MODES: GuardMode[] = ["observe", "warn", "require_approval", "enforce"];
export const USAGE = `mnki-mcp --agent <id> --server <name> (--upstream -- <command> [args…] | --upstream-url <url> [--upstream-header k=v]…)
         [--mode observe|warn|require_approval|enforce] [--url <console>] [--key <api key>] [--identity <file>]
         [--amount-map "tool=amountArg:currencyArg,…"] [--approval-timeout <s>] [--no-wait]
Env: MNKI_URL, MNKI_API_KEY, MNKI_IDENTITY, MNKI_HOME, MNKI_TELEMETRY=0. Config: ~/.mnki/config.json (from \`mnki init\`).`;

export function parseArgs(argv: string[], env: NodeJS.ProcessEnv = process.env): ProxyConfig {
  const get = (flag: string): string | undefined => { const i = argv.indexOf(flag); return i >= 0 ? argv[i + 1] : undefined; };
  const stored = (() => { const p = join(env.MNKI_HOME ?? join(homedir(), ".mnki"), "config.json"); try { return existsSync(p) ? (JSON.parse(readFileSync(p, "utf8")) as { baseUrl?: string; apiKey?: string; telemetry?: boolean }) : {}; } catch { return {}; } })();
  const agent = get("--agent"); const server = get("--server") ?? "mcp"; if (!agent) throw new Error(`--agent is required\n${USAGE}`);
  const mode = (get("--mode") ?? "observe") as GuardMode; if (!MODES.includes(mode)) throw new Error(`--mode must be one of ${MODES.join("|")}`);
  const baseUrl = get("--url") ?? env.MNKI_URL ?? stored.baseUrl ?? ""; const apiKey = get("--key") ?? env.MNKI_API_KEY ?? stored.apiKey ?? "";
  if (!baseUrl || !apiKey) throw new Error(`no console configured — pass --url/--key, set MNKI_URL/MNKI_API_KEY, or run \`mnki init --url … --key …\`\n${USAGE}`);
  let upstream: ProxyConfig["upstream"];
  const url = get("--upstream-url");
  if (url) { const headers: Record<string, string> = {}; argv.forEach((a, i) => { if (a === "--upstream-header" && argv[i + 1]) { const [k, ...v] = argv[i + 1].split("="); headers[k] = v.join("="); } }); upstream = { kind: "http", url, headers }; }
  else { const i = argv.indexOf("--upstream"); if (i < 0) throw new Error(`--upstream -- <command> or --upstream-url <url> is required\n${USAGE}`); const rest = argv.slice(i + 1); const cmd = rest[0] === "--" ? rest.slice(1) : rest; if (!cmd.length) throw new Error("--upstream needs a command"); upstream = { kind: "stdio", command: cmd[0], args: cmd.slice(1) }; }
  return { agent, server, mode, baseUrl, apiKey, upstream, identityFile: get("--identity") ?? env.MNKI_IDENTITY_FILE, amountMap: get("--amount-map"), approvalTimeoutMs: Number(get("--approval-timeout") ?? 300) * 1000, approvalWait: !argv.includes("--no-wait"), telemetry: env.MNKI_TELEMETRY !== "0" && stored.telemetry !== false };
}

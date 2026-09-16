#!/usr/bin/env node
/**
 * mnki-mcp — stdio in front of the MCP client, a stdio command or a Streamable HTTP server behind it.
 * Every tools/call is verified by Agent Trust; see ./config.ts for the flags and `mnki protect` to install it.
 */
import { readFileSync, existsSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { AgentIdentity } from "mnki-sdk";
import { parseArgs, USAGE } from "./config";
import { createProxy, splitFrames } from "./proxy";
import { createVerifier, parseAmountMap } from "./verify";
import { stdioUpstream } from "./upstream/stdio";
import { httpUpstream } from "./upstream/http";
import { appendShadow } from "./shadow";
import { track } from "./telemetry";

export async function main(argv = process.argv.slice(2)): Promise<void> {
  if (argv.includes("--help") || argv.includes("-h") || !argv.length) { console.error(USAGE); process.exitCode = argv.length ? 0 : 2; return; }
  const cfg = parseArgs(argv);
  const log = (m: string) => process.stderr.write(`[mnki-mcp ${cfg.server}] ${m}\n`);
  let identity: AgentIdentity | undefined;
  if (process.env.MNKI_IDENTITY) identity = await AgentIdentity.import(JSON.parse(process.env.MNKI_IDENTITY.trim().startsWith("{") ? process.env.MNKI_IDENTITY : Buffer.from(process.env.MNKI_IDENTITY, "base64").toString("utf8")));
  else if (cfg.identityFile && existsSync(cfg.identityFile)) identity = await AgentIdentity.import(JSON.parse(readFileSync(cfg.identityFile, "utf8")));
  const verifier = createVerifier({ baseUrl: cfg.baseUrl, apiKey: cfg.apiKey, agent: cfg.agent, server: cfg.server, mode: cfg.mode, identity, amountMap: parseAmountMap(cfg.amountMap), approval: { timeoutMs: cfg.approvalTimeoutMs, wait: cfg.approvalWait },
    onDecision: (r) => { if (r.mode === "observe" || r.mode === "warn") appendShadow(cfg.server, r); if (r.decision !== "ALLOW" || r.mode !== "enforce") log(`${r.tool}: ${r.decision}${r.enforced ? "" : " (not enforced)"}${r.reasons.length ? ` — ${r.reasons.filter((x) => !x.endsWith("_verified") && x !== "authority_valid").join(", ")}` : ""}`); track(cfg.telemetry, "proxy_decision", { mode: r.mode, decision: r.decision }); },
    onError: (kind, detail) => { log(`${kind}: ${detail}`); track(cfg.telemetry, "proxy_error", { mode: cfg.mode, error: kind }); } });
  const upstream = cfg.upstream.kind === "stdio" ? stdioUpstream(cfg.upstream.command, cfg.upstream.args, process.env, process.stderr) : httpUpstream(cfg.upstream.url, cfg.upstream.headers, fetch, log);
  const proxy = createProxy({ upstream, verifier, toClient: (f) => { process.stdout.write(f + "\n"); }, log });
  log(`mode ${cfg.mode} · agent ${cfg.agent} · upstream ${cfg.upstream.kind === "stdio" ? `${cfg.upstream.command} ${cfg.upstream.args.join(" ")}` : cfg.upstream.url}`);
  let buf = ""; process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => { buf += chunk; const { frames, rest } = splitFrames(buf); buf = rest; for (const f of frames) void proxy.fromClient(f); });
  process.stdin.on("end", () => { void proxy.close(250).then(() => process.exit(0)); });
  process.on("SIGTERM", () => { void proxy.close().then(() => process.exit(0)); });
}
/**
 * Is this module the process entry point? Bin names differ from the file name (`mnki`, `mnki-cli`,
 * `agenttrust`, `mnki-mcp` all point at dist/main.js), and npx invokes the bin named after the package — so
 * resolve the symlink and compare paths, falling back to the known names when realpath is unavailable.
 */
export function isEntrypoint(argv1: string | undefined, moduleUrl: string): boolean {
  if (!argv1) return false;
  try { return realpathSync(argv1) === fileURLToPath(moduleUrl); } catch { /* not a real path (bundled, virtual fs) */ }
  return /(^|[\\/])(main\.(ts|js)|mnki|mnki-cli|mnki-mcp|agenttrust)$/.test(argv1);
}

if (isEntrypoint(process.argv[1], import.meta.url)) void main().catch((e) => { console.error(e instanceof Error ? e.message : String(e)); process.exit(1); });

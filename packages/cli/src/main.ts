/**
 * agenttrust — the five-minute developer motion.
 *
 *   agenttrust init --url https://staging.mnki.com --key at_…
 *   agenttrust identity create --name procurement-bot [--alg ES256|EdDSA] [--risk low]
 *   agenttrust verify --agent <id> --action purchase.create [--resource r] [--amount 3200 --currency EUR] [--sign]
 *   agenttrust inspect <agent>
 *   agenttrust delegate --issuer principal:<id>|agent:<id> --to <agent> --cap "purchase.create=supplier:*;max_value=5000" [--parent <id>] [--expires 24h]
 *   agenttrust attest <decision_id>
 *   agenttrust scan [--register]
 *   agenttrust protect --mcp <integration_id>
 *   agenttrust conformance --level 1|2|3 [--dir <conformance dir>]
 *
 * Config + identities live in ~/.agenttrust/config.json (private keys included — chmod 600).
 */
import { parseArgs } from "node:util";
import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { AgentTrustClient, AgentIdentity, AgentTrustError, type ExportedIdentity, type CapSet } from "@agent-trust/sdk";
import { scan } from "./scan";
import { findConformanceDir, runConformance, formatReport } from "./conformance";

interface Config { baseUrl: string; apiKey: string; identities: Record<string, ExportedIdentity> }
const CONFIG_DIR = join(process.env.AGENTTRUST_HOME ?? homedir(), ".agenttrust"); const CONFIG = join(CONFIG_DIR, "config.json");
const load = (): Config | null => (existsSync(CONFIG) ? (JSON.parse(readFileSync(CONFIG, "utf8")) as Config) : null);
const save = (c: Config) => { mkdirSync(CONFIG_DIR, { recursive: true }); writeFileSync(CONFIG, JSON.stringify(c, null, 2)); try { chmodSync(CONFIG, 0o600); } catch { /* windows */ } };
const need = (): Config => { const c = load(); if (!c) { console.error("Not initialised. Run: agenttrust init --url <console url> --key <api key>"); process.exit(2); } return c; };
const client = (c: Config) => new AgentTrustClient({ baseUrl: c.baseUrl, apiKey: c.apiKey });
const mark = { pass: "✓", warn: "⚠", fail: "✕", skipped: "·" } as const;
const out = (o: unknown) => console.log(JSON.stringify(o, null, 2));

/** "purchase.create=supplier:*;max_value=5000;currency=EUR;region=EU|NL" → capability */
function parseCap(spec: string): CapSet[number] {
  const [lhs, ...rest] = spec.split(";"); const [action, resource = "*"] = lhs.split("=");
  const constraints: Record<string, unknown> = {};
  for (const kv of rest) { const [k, v] = kv.split("="); if (!k || v === undefined) continue; constraints[k] = /^\d+(\.\d+)?$/.test(v) ? Number(v) : v.includes("|") ? v.split("|") : v; }
  return { action: action.trim(), resource: resource.trim(), ...(rest.length ? { constraints } : {}) };
}
const expiresIso = (s?: string) => { if (!s) return null; const m = /^(\d+)([hdm])$/.exec(s); if (!m) return s; const ms = Number(m[1]) * (m[2] === "h" ? 3600e3 : m[2] === "d" ? 86400e3 : 60e3); return new Date(Date.now() + ms).toISOString(); };

export async function main(argv = process.argv.slice(2)): Promise<void> {
  const [cmd, ...rest] = argv;
  try {
    switch (cmd) {
      case "init": {
        const { values } = parseArgs({ args: rest, options: { url: { type: "string" }, key: { type: "string" } } });
        if (!values.url || !values.key) throw new Error("usage: agenttrust init --url <console url> --key <api key>");
        const c: Config = { ...(load() ?? { identities: {} }), baseUrl: values.url, apiKey: values.key, identities: load()?.identities ?? {} };
        await client(c).agents.list({ limit: 1 }); save(c); console.log(`Connected to ${c.baseUrl}. Config: ${CONFIG}`); return;
      }
      case "identity": {
        const c = need(); const sub = rest[0];
        if (sub === "create") {
          const { values } = parseArgs({ args: rest.slice(1), options: { name: { type: "string" }, alg: { type: "string", default: "ES256" }, risk: { type: "string", default: "medium" }, issuer: { type: "string" }, owner: { type: "string" } } });
          if (!values.name) throw new Error("usage: agenttrust identity create --name <name> [--alg ES256|EdDSA] [--risk low|medium|high|critical] [--owner <principal id>]");
          const r = await client(c).agents.enrol({ name: values.name, riskTier: values.risk as "low", issuer: values.issuer, ownerPrincipalId: values.owner }, values.alg as "ES256");
          c.identities[r.agentId] = await r.identity.export(); save(c);
          console.log(`Agent registered\n  id         ${r.agentId}\n  stable id  ${r.stableId}\n  key        ${r.identity.alg} kid=${r.identity.kid} (private key stored in ${CONFIG})\nNext: delegate authority to it, then \`agenttrust verify --agent ${r.agentId} --action <action> --sign\`.`); return;
        }
        if (sub === "list") { for (const [id, e] of Object.entries(c.identities)) console.log(`${id}\t${e.alg}\tkid=${e.kid}`); return; }
        throw new Error("usage: agenttrust identity create|list");
      }
      case "verify": {
        const c = need();
        const { values } = parseArgs({ args: rest, options: { agent: { type: "string" }, action: { type: "string" }, resource: { type: "string" }, amount: { type: "string" }, currency: { type: "string" }, region: { type: "string" }, attestation: { type: "string" }, sign: { type: "boolean", default: false }, json: { type: "boolean", default: false } } });
        if (!values.agent || !values.action) throw new Error("usage: agenttrust verify --agent <id> --action <action> [--resource r] [--amount n --currency EUR] [--region EU] [--sign] [--json]");
        const identity = values.sign ? (c.identities[values.agent] ? await AgentIdentity.import(c.identities[values.agent]) : (() => { throw new Error(`no local identity for ${values.agent}; create one with \`agenttrust identity create\``); })()) : undefined;
        const d = await client(c).verify({ agent: values.agent, action: values.action, resource: values.resource, amount: values.amount ? Number(values.amount) : undefined, currency: values.currency, context: values.region ? { region: values.region } : undefined, attestation: values.attestation }, { identity });
        if (values.json) return out(d);
        console.log(`Decision: ${d.decision}   (${d.latency_ms} ms · ${d.decision_id})`);
        for (const e of d.evidence) console.log(`  ${mark[e.status]} ${e.title}${e.detail ? `  — ${e.detail}` : ""}`);
        if (d.approval_id) console.log(`Approval pending: ${d.approval_id}`);
        if (d.decision !== "ALLOW") process.exitCode = 1; return;
      }
      case "inspect": {
        const c = need(); const id = rest[0]; if (!id) throw new Error("usage: agenttrust inspect <agent id>");
        const a = await client(c).agents.get(id); const json = rest.includes("--json"); if (json) return out(a);
        const s = a as Record<string, unknown>;
        console.log(`Agent: ${a.name}\n  id          ${a.id}\n  stable id   ${a.stableId}\n  lifecycle   ${a.lifecycle}\n  risk        ${s.riskTier ?? "—"}\n  owner       ${(s.owner as { name?: string } | null)?.name ?? "unassigned"}`);
        const caps = (a.chain?.effective ?? (s.capabilities as CapSet | undefined) ?? []) as CapSet;
        console.log(`  authority   ${a.chain ? `delegated (${a.chain.ids.length} link${a.chain.ids.length === 1 ? "" : "s"}, ${a.chain.valid ? "valid" : "INVALID"})` : "direct capabilities"}`);
        for (const cp of caps) console.log(`    ${cp.action.padEnd(28)} ${cp.resource}${cp.constraints ? "  " + Object.entries(cp.constraints).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("|") : v}`).join(" ") : ""}`);
        return;
      }
      case "delegate": {
        const c = need();
        const { values } = parseArgs({ args: rest, options: { issuer: { type: "string" }, to: { type: "string" }, cap: { type: "string", multiple: true }, parent: { type: "string" }, expires: { type: "string" }, task: { type: "string" } } });
        if (!values.issuer || !values.to || !values.cap?.length) throw new Error('usage: agenttrust delegate --issuer principal:<id>|agent:<id> --to <agent> --cap "action=resource;max_value=5000" [--parent <delegation id>] [--expires 24h] [--task …]');
        const [type, id] = values.issuer.split(":") as ["principal" | "agent", string];
        const r = await client(c).delegations.issue({ issuer: { type, id }, subjectAgentId: values.to, parentId: values.parent ?? null, task: values.task, capabilities: values.cap.map(parseCap), notAfter: expiresIso(values.expires) });
        const cred = await client(c).delegations.credential(r.id).catch(() => null);
        console.log(`Delegation ${r.id} issued (depth ${r.depth}). Effective authority:`); for (const cp of r.effective) console.log(`  ${cp.action}  ${cp.resource}`);
        if (cred) console.log(`Signed credential chain (${cred.credentials.length} link${cred.credentials.length === 1 ? "" : "s"}), verify with ${cred.jwks_url}:\n${cred.credentials[cred.credentials.length - 1]}`); return;
      }
      case "attest": {
        const c = need(); const id = rest[0]; if (!id) throw new Error("usage: agenttrust attest <decision id> [--ttl 600]");
        const r = await client(c).attestations.issue(id, { ttlSeconds: rest.includes("--ttl") ? Number(rest[rest.indexOf("--ttl") + 1]) : undefined });
        console.log(`Attestation ${r.id} (expires ${r.expires_at})\n${r.token}`); return;
      }
      case "scan": {
        const register = rest.includes("--register"); const r = scan();
        console.log(`Scanned ${r.scannedFiles.length} MCP client config${r.scannedFiles.length === 1 ? "" : "s"}${r.scannedFiles.length ? ":\n  " + r.scannedFiles.join("\n  ") : ""}`);
        console.log(`\nFound ${r.mcpServers.length} MCP server${r.mcpServers.length === 1 ? "" : "s"}:`);
        for (const s of r.mcpServers) console.log(`  ${s.name.padEnd(28)} ${s.transport === "http" ? s.url : `stdio: ${s.command} ${(s.args ?? []).join(" ")}`}   [${s.source}]`);
        console.log(`\n${r.credentials.length} credential${r.credentials.length === 1 ? "" : "s"} an agent could use (environment):`);
        for (const k of r.credentials) console.log(`  ${k.provider.padEnd(14)} ${k.name}  ${k.masked}`);
        console.log(`\n${r.workloads.length} workload identit${r.workloads.length === 1 ? "y" : "ies"} via ${r.toolsTried.join(" / ")} (only tools that are installed and signed in answer):`);
        for (const w of r.workloads) console.log(`  ${w.source.padEnd(11)} ${w.kind.padEnd(15)} ${w.name}  ${w.detail}`);
        if (register) {
          const c = need(); let n = 0;
          for (const s of r.mcpServers) if (s.transport === "http" && s.url) { const res = await fetch(`${c.baseUrl}/api/v1/integrations/mcp`, { method: "POST", headers: { authorization: `Bearer ${c.apiKey}`, "content-type": "application/json" }, body: JSON.stringify({ name: s.name, config: { url: s.url, transport: "streamable_http", action_prefix: "mcp:" } }) }); if (res.ok) n++; }
          console.log(`\nRegistered ${n} HTTP MCP server${n === 1 ? "" : "s"} as integrations (stdio servers are reported only — put them behind an HTTP gateway to govern them).`);
        } else if (r.mcpServers.some((s) => s.transport === "http")) console.log("\nRun again with --register to register the HTTP servers as integrations.");
        return;
      }
      case "protect": {
        const c = need(); const { values } = parseArgs({ args: rest, options: { mcp: { type: "string" }, agent: { type: "string" } } });
        if (!values.mcp) throw new Error("usage: agenttrust protect --mcp <integration id> [--agent <agent id>]");
        const url = `${c.baseUrl}/api/gateway/mcp/${values.mcp}`;
        console.log(`Point your MCP client at the gateway instead of the server:\n${JSON.stringify({ mcpServers: { protected: { url, headers: { Authorization: "Bearer <agent trust key, scope verify>", "Agent-Id": values.agent ?? "<agent id>" } } } }, null, 2)}\nEvery tools/call is verified; denials return JSON-RPC -32003, escalations -32001. Decisions land in Audit & Provenance.`); return;
      }
      case "conformance": {
        const { values } = parseArgs({ args: rest, options: { level: { type: "string", default: "3" }, dir: { type: "string" } } });
        const dir = values.dir ?? findConformanceDir(); if (!dir) throw new Error("conformance directory not found — pass --dir <path to conformance/>");
        const level = Math.min(3, Math.max(1, Number(values.level) || 3));
        const { text, ok } = formatReport(await runConformance(dir, level), level); console.log(text); process.exitCode = ok ? 0 : 1; return;
      }
      default:
        console.log("agenttrust <init|identity|verify|inspect|delegate|attest|scan|protect|conformance> — see packages/cli/src/main.ts for usage"); process.exitCode = cmd ? 2 : 0;
    }
  } catch (e) {
    if (e instanceof AgentTrustError) console.error(`API error ${e.status} ${e.code}${e.detail ? ` — ${typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)}` : ""}`);
    else console.error(e instanceof Error ? e.message : String(e));
    process.exitCode = 1;
  }
}

if (process.argv[1] && /main\.ts$|agenttrust$/.test(process.argv[1])) void main();

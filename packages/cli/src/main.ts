#!/usr/bin/env node
/**
 * mnki — the five-minute developer motion (`agenttrust` remains an alias).
 *
 *   mnki demo                                   the 15-second story, no account
 *   mnki init [--name my-agent]                 local mode: identity + world + policy in ~/.mnki, no account
 *   mnki init --url https://mnki.com --key at_…  connected mode
 *   mnki identity create --name procurement-bot [--alg ES256|EdDSA] [--risk low]
 *   mnki verify --agent <id> --action purchase.create [--resource r] [--amount 3200 --currency EUR] [--sign] [--local [--world file]]
 *   mnki policy test <policy.json> --cases <cases.json> · mnki policy explain <decision.json | --last>
 *   mnki inspect <agent>
 *   mnki passport publish|unpublish <agent-id>   (admin key; the organisation's opt-in in Settings → Security decides whether it is served)
 *   mnki delegate --issuer principal:<id>|agent:<id> --to <agent> --cap "purchase.create=supplier:*;max_value=5000" [--parent <id>] [--expires 24h]
 *   mnki attest <decision_id>
 *   mnki access list · mnki access ops <connection> · mnki access run --agent <id> --connection <con_…> --op refund.create --param charge=ch_1 --param amount=42000 [--wait]
 *   mnki access request --agent <id> --connection <con_…> --op customer.get [--for 24h] --reason "…" · mnki access status <request id>
 *   mnki revoke agent|credential|delegation|api_key|policy_version <id> --reason "…"   (admin key; immediate)
 *   mnki scan [--register] [--watch [--interval 300]] [--json]
 *   mnki protect --client claude-desktop|claude-code|cursor|windsurf|vscode|project --server <name> --agent <id> [--mode observe|warn|require_approval|enforce] [--apply]
 *   mnki protect rollback|status|report … · mnki protect --gateway <integration_id>   (hosted gateway instead of the local proxy)
 *   mnki conformance --level 1|2|3 [--dir <conformance dir>] [--badge]
 *   mnki telemetry on|off|status        (anonymous, allow-listed product telemetry; also MNKI_TELEMETRY=0)
 *
 * Config + identities live in ~/.mnki/config.json (private keys included — chmod 600); see ./config.ts.
 */
import { parseArgs } from "node:util";
import { readFileSync, writeFileSync, mkdirSync, existsSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { AgentTrustClient, AgentIdentity, AgentTrustError, type CapSet } from "mnki-sdk";
import { scan } from "./scan";
import { planProtect, applyProtect, planRollback, applyRollback, readManifest, configPathFor, clientRunning, isProxied, type ProtectClient, type ProtectMode } from "./protect";
import { readShadow, summarizeShadow, shadowLogPath } from "mnki-mcp";
import { findConformanceDir, runConformance, formatReport } from "./conformance";
import { configDir, configPath, loadConfig as load, saveConfig as save, type Config } from "./config";
import { track } from "./telemetry";
import { runDemo } from "./demo";
import { policyTest, explainFile, formatExplanation, lastDecisionPath, type PolicyCase } from "./policy";
import { setPassport, formatPassportResult, publishHint } from "./passport";
import { localVerify, demoWorld, explain, type LocalWorld } from "mnki-sdk";

const need = (): Config => { const c = load(); if (!c) { console.error("Not initialised. Run: mnki init --url <console url> --key <api key>"); process.exit(2); } return c; };
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
      case "demo": { const r = await runDemo(console.log, { json: rest.includes("--json") }); track("demo_run", { connected: !!load() }); if (!(r.denied && r.allowed && r.escalated)) process.exitCode = 1; return; }
      case "init": {
        const { values } = parseArgs({ args: rest, options: { url: { type: "string" }, key: { type: "string" }, name: { type: "string" }, cloud: { type: "boolean", default: false } } });
        if (!values.url && !values.key && !values.cloud) {
          // Local mode: a key pair, a world with this agent, and a starter policy — nothing leaves the machine.
          const name = values.name ?? "my-agent"; const id = `agt_${name.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}`;
          const ident = await AgentIdentity.create(id); const e = await ident.export();
          const world: LocalWorld = { ...demoWorld(), agent: { id, stable_id: `spiffe://local/agent/${name}`, lifecycle: "active", risk_tier: "medium", owner_principal_id: "prn_me", labels: {} }, agentAliases: [name], principals: [{ id: "prn_me", display_name: process.env.USER ?? "me", kind: "user" }], delegations: [{ id: "dlg_local", parent_id: null, subject_agent_id: id, status: "active", not_after: null, capabilities: [{ action: "refund.create", resource: "customer:*", constraints: { max_value: 5000, currency: "EUR" } }] }] };
          mkdirSync(configDir(), { recursive: true });
          const idPath = join(configDir(), "identity.json"); if (!existsSync(idPath)) writeFileSync(idPath, JSON.stringify(e, null, 2), { mode: 0o600 });
          const worldPath = join(configDir(), "world.json"); if (!existsSync(worldPath)) writeFileSync(worldPath, JSON.stringify(world, null, 2));
          const policyPath = join(process.cwd(), "mnki.policy.json"); if (!existsSync(policyPath)) writeFileSync(policyPath, JSON.stringify(world.policy?.doc, null, 2));
          save({ ...(load() ?? { baseUrl: "", apiKey: "", identities: {} }), mode: "local" }); track("init", { connected: false });
          console.log(`Local mode ready — nothing left this machine.
  identity  ${idPath}  (${ident.alg}, kid=${ident.kid})
  world     ${worldPath}  (agent "${name}" with a €5,000 refund delegation — edit freely)
  policy    ${policyPath}
Try: mnki verify --local --agent ${name} --action refund.create --amount 420 --currency EUR --resource customer:1
When you want a real console: mnki init --url https://mnki.com --key at_…`); return;
        }
        if (!values.url || !values.key) throw new Error("usage: mnki init --url <console url> --key <api key>   (or `mnki init` for local mode)");
        const c: Config = { ...(load() ?? { baseUrl: "", apiKey: "", identities: {} }), baseUrl: values.url, apiKey: values.key, identities: load()?.identities ?? {} };
        await client(c).agents.list({ limit: 1 }); save(c); track("init", { connected: true }); console.log(`Connected to ${c.baseUrl}. Config: ${configPath()}`); return;
      }
      case "identity": {
        const c = need(); const sub = rest[0];
        if (sub === "create") {
          const { values } = parseArgs({ args: rest.slice(1), options: { name: { type: "string" }, alg: { type: "string", default: "ES256" }, risk: { type: "string", default: "medium" }, issuer: { type: "string" }, owner: { type: "string" } } });
          if (!values.name) throw new Error("usage: mnki identity create --name <name> [--alg ES256|EdDSA] [--risk low|medium|high|critical] [--owner <principal id>]");
          const r = await client(c).agents.enrol({ name: values.name, riskTier: values.risk as "low", issuer: values.issuer, ownerPrincipalId: values.owner }, values.alg as "ES256");
          c.identities[r.agentId] = await r.identity.export(); save(c);
          console.log(`Agent registered\n  id         ${r.agentId}\n  stable id  ${r.stableId}\n  key        ${r.identity.alg} kid=${r.identity.kid} (private key stored in ${configPath()})\nNext: delegate authority to it, then \`mnki verify --agent ${r.agentId} --action <action> --sign\`.\n${publishHint(r.agentId)}`); return;
        }
        if (sub === "list") { for (const [id, e] of Object.entries(c.identities)) console.log(`${id}\t${e.alg}\tkid=${e.kid}`); return; }
        throw new Error("usage: mnki identity create|list");
      }
      case "verify": {
        const { values } = parseArgs({ args: rest, options: { agent: { type: "string" }, action: { type: "string" }, resource: { type: "string" }, amount: { type: "string" }, currency: { type: "string" }, region: { type: "string" }, attestation: { type: "string" }, sign: { type: "boolean", default: false }, json: { type: "boolean", default: false }, local: { type: "boolean", default: false }, "dry-run": { type: "boolean", default: false }, world: { type: "string" }, explain: { type: "boolean", default: false } } });
        if (!values.agent || !values.action) throw new Error("usage: mnki verify --agent <id> --action <action> [--resource r] [--amount n --currency EUR] [--region EU] [--sign] [--json] [--local [--world file]] [--explain]");
        const stored = load();
        if (values.local || values["dry-run"] || (stored?.mode === "local" && !stored.baseUrl)) {
          const worldPath = values.world ?? join(configDir(), "world.json");
          const world: LocalWorld = existsSync(worldPath) ? (JSON.parse(readFileSync(worldPath, "utf8")) as LocalWorld) : demoWorld();
          const r = await localVerify(world, { agent: values.agent, action: values.action, resource: values.resource, amount: values.amount ? Number(values.amount) : undefined, currency: values.currency, context: values.region ? { region: values.region } : undefined, attestation: values.attestation });
          if (!r.ok) throw new Error(`invalid request: ${r.code}`);
          mkdirSync(configDir(), { recursive: true }); writeFileSync(lastDecisionPath(), JSON.stringify(r.result, null, 2));
          if (values.json) return out(r.result);
          console.log(`Decision: ${r.result.decision}   (local, nothing recorded · world: ${existsSync(worldPath) ? worldPath : "demo"})`);
          for (const e of r.result.evidence) console.log(`  ${mark[e.status]} ${e.title}${e.detail ? `  — ${e.detail}` : ""}`);
          if (values.explain || r.result.decision !== "ALLOW") console.log(formatExplanation(explain(r.result)));
          if (r.result.decision !== "ALLOW") process.exitCode = 1; return;
        }
        const c = need();
        const identity = values.sign ? (c.identities[values.agent] ? await AgentIdentity.import(c.identities[values.agent]) : (() => { throw new Error(`no local identity for ${values.agent}; create one with \`mnki identity create\``); })()) : undefined;
        const d = await client(c).verify({ agent: values.agent, action: values.action, resource: values.resource, amount: values.amount ? Number(values.amount) : undefined, currency: values.currency, context: values.region ? { region: values.region } : undefined, attestation: values.attestation }, { identity });
        if (values.json) return out(d);
        console.log(`Decision: ${d.decision}   (${d.latency_ms} ms · ${d.decision_id})`);
        for (const e of d.evidence) console.log(`  ${mark[e.status]} ${e.title}${e.detail ? `  — ${e.detail}` : ""}`);
        if (d.approval_id) console.log(`Approval pending: ${d.approval_id}`);
        if (d.decision !== "ALLOW") process.exitCode = 1; return;
      }
      case "inspect": {
        const c = need(); const id = rest[0]; if (!id) throw new Error("usage: mnki inspect <agent id>");
        const a = await client(c).agents.get(id); const json = rest.includes("--json"); if (json) return out(a);
        const s = a as Record<string, unknown>;
        console.log(`Agent: ${a.name}\n  id          ${a.id}\n  stable id   ${a.stableId}\n  lifecycle   ${a.lifecycle}\n  risk        ${s.riskTier ?? "—"}\n  owner       ${(s.owner as { name?: string } | null)?.name ?? "unassigned"}`);
        const caps = (a.chain?.effective ?? (s.capabilities as CapSet | undefined) ?? []) as CapSet;
        console.log(`  authority   ${a.chain ? `delegated (${a.chain.ids.length} link${a.chain.ids.length === 1 ? "" : "s"}, ${a.chain.valid ? "valid" : "INVALID"})` : "direct capabilities"}`);
        for (const cp of caps) console.log(`    ${cp.action.padEnd(28)} ${cp.resource}${cp.constraints ? "  " + Object.entries(cp.constraints).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("|") : v}`).join(" ") : ""}`);
        return;
      }
      case "passport": {
        const c = need(); const sub = rest[0]; const id = rest[1];
        if ((sub !== "publish" && sub !== "unpublish") || !id) throw new Error("usage: mnki passport publish|unpublish <agent id> [--json]");
        const r = await setPassport(c, id, sub === "publish");
        if (rest.includes("--json")) return out(r);
        console.log(formatPassportResult(id, sub === "publish", r)); return;
      }
      case "delegate": {
        const c = need();
        const { values } = parseArgs({ args: rest, options: { issuer: { type: "string" }, to: { type: "string" }, cap: { type: "string", multiple: true }, parent: { type: "string" }, expires: { type: "string" }, task: { type: "string" } } });
        if (!values.issuer || !values.to || !values.cap?.length) throw new Error('usage: mnki delegate --issuer principal:<id>|agent:<id> --to <agent> --cap "action=resource;max_value=5000" [--parent <delegation id>] [--expires 24h] [--task …]');
        const [type, id] = values.issuer.split(":") as ["principal" | "agent", string];
        const r = await client(c).delegations.issue({ issuer: { type, id }, subjectAgentId: values.to, parentId: values.parent ?? null, task: values.task, capabilities: values.cap.map(parseCap), notAfter: expiresIso(values.expires) });
        const cred = await client(c).delegations.credential(r.id).catch(() => null);
        console.log(`Delegation ${r.id} issued (depth ${r.depth}). Effective authority:`); for (const cp of r.effective) console.log(`  ${cp.action}  ${cp.resource}`);
        if (cred) console.log(`Signed credential chain (${cred.credentials.length} link${cred.credentials.length === 1 ? "" : "s"}), verify with ${cred.jwks_url}:\n${cred.credentials[cred.credentials.length - 1]}`); return;
      }
      case "attest": {
        const c = need(); const id = rest[0]; if (!id) throw new Error("usage: mnki attest <decision id> [--ttl 600]");
        const r = await client(c).attestations.issue(id, { ttlSeconds: rest.includes("--ttl") ? Number(rest[rest.indexOf("--ttl") + 1]) : undefined });
        console.log(`Attestation ${r.id} (expires ${r.expires_at})\n${r.token}`); return;
      }
      case "access": {
        const c = need(); const sub = rest[0]; const cl = client(c);
        if (sub === "list") { const r = await cl.connections.list(); if (rest.includes("--json")) return out(r); if (!r.ready) console.log("Access broker not configured on this deployment (TOOL_ENC_KEY)."); for (const x of r.items) console.log(`  ${x.id}  ${x.provider.padEnd(9)} ${x.status.padEnd(15)} ${x.name}  [${x.allowed_operations.join(", ")}]`); if (!r.items.length) console.log("No connections. Console → Access → Connect a system."); return; }
        if (sub === "ops") { const id = rest[1]; if (!id) throw new Error("usage: mnki access ops <connection id>"); const r = await cl.connections.operations(id); if (rest.includes("--json")) return out(r); for (const o of r.items) console.log(`  ${o.enabled ? "●" : "○"} ${o.id.padEnd(24)} ${o.method.padEnd(6)} ${o.risk.padEnd(8)} ${o.title}`); return; }
        if (sub === "status") { const id = rest[1]; if (!id) throw new Error("usage: mnki access status <request id>"); return out(await cl.accessRequests.status(id)); }
        const { values } = parseArgs({ args: rest.slice(1), options: { agent: { type: "string" }, connection: { type: "string" }, op: { type: "string", multiple: true }, param: { type: "string", multiple: true }, for: { type: "string" }, reason: { type: "string" }, wait: { type: "boolean" }, mint: { type: "boolean" }, sign: { type: "boolean" }, json: { type: "boolean" } } });
        if (!values.agent || !values.connection || !values.op?.length) throw new Error('usage: mnki access run|request --agent <id> --connection <con_…> --op <operation> [--param k=v]… [--wait] [--mint] [--sign] | [--for 24h --reason "…"]');
        if (sub === "request") {
          const seconds = values.for ? Math.round((Date.parse(expiresIso(values.for) ?? "") - Date.now()) / 1000) : 86400;
          const r = await cl.accessRequests.create({ agent: values.agent, connection: values.connection, operations: values.op, duration_seconds: seconds, reason: values.reason ?? "requested from the CLI" });
          if (values.json) return out(r); console.log(`Access request ${r.id} is ${r.status} (expires ${r.expires_at}). A person approves it in the console; poll with \`mnki access status ${r.id}\`.`); return;
        }
        if (sub !== "run") throw new Error("usage: mnki access list|ops|run|request|status …");
        const params: Record<string, string | number | boolean> = {};
        for (const kv of values.param ?? []) { const i = kv.indexOf("="); if (i < 0) throw new Error(`--param expects k=v, got ${kv}`); const k = kv.slice(0, i), v = kv.slice(i + 1); params[k] = v === "true" ? true : v === "false" ? false : /^-?\d+(\.\d+)?$/.test(v) ? Number(v) : v; }
        const identity = values.sign ? (c.identities[values.agent] ? await AgentIdentity.import(c.identities[values.agent]) : (() => { throw new Error(`no local identity for ${values.agent}`); })()) : undefined;
        const input = { agent: values.agent, connection: values.connection, operation: values.op[0], params };
        if (values.mint) { const r = await cl.grants.mint(input); if (values.json) return out(r); console.log(`Grant ${r.grant.id} (${r.grant.kind}, ${r.grant.status})`); if (r.permit) console.log(`Permit for ${r.permit.audience}, expires ${r.permit.expires_at}:\n${r.permit.token}`); if (r.result) console.log(JSON.stringify(r.result.body, null, 2)); return; }
        try {
          const r = values.wait ? await cl.grants.run(input, { identity }) : await cl.grants.execute(input, { identity });
          if (values.json) return out(r);
          if (r.status === "approval_required") { console.log(`Approval pending: ${r.approval_id} (decision ${r.decision.decision_id}). Resend with --wait, or later: mnki access run … --param approval_id=${r.approval_id}`); process.exitCode = 1; return; }
          console.log(`Grant ${r.grant.id}: ${r.grant.status}  (upstream ${r.result.status}${r.result.request_id ? ` · ${r.result.request_id}` : ""} · decision ${r.decision.decision_id})`);
          for (const e of r.decision.evidence as { status: string; title: string; detail?: string }[]) console.log(`  ${mark[e.status as keyof typeof mark] ?? "•"} ${e.title}${e.detail ? `  — ${e.detail}` : ""}`);
          console.log(JSON.stringify(r.result.body, null, 2)); if (!r.result.ok) process.exitCode = 1; return;
        } catch (e) {
          if (e instanceof AgentTrustError && e.status === 403 && e.detail && typeof e.detail === "object") { const d = e.detail as { decision?: { reasons?: string[]; evidence?: { status: string; title: string; detail?: string }[] }; access_request_hint?: unknown }; console.log(`Denied: ${(d.decision?.reasons ?? []).join(", ")}`); for (const ev of d.decision?.evidence ?? []) console.log(`  ${mark[ev.status as keyof typeof mark] ?? "•"} ${ev.title}${ev.detail ? `  — ${ev.detail}` : ""}`); if (d.access_request_hint) console.log(`Ask for access: mnki access request --agent ${values.agent} --connection ${values.connection} --op ${values.op[0]} --reason "…"`); process.exitCode = 1; return; }
          throw e;
        }
      }
      case "scan": {
        const register = rest.includes("--register");
        if (rest.includes("--watch")) {
          // Continuous local discovery: re-scan on an interval, report and (with --register) register what is new.
          const iv = rest.includes("--interval") ? Number(rest[rest.indexOf("--interval") + 1]) || 300 : 300;
          const statePath = join(configDir(), "scan-state.json"); mkdirSync(configDir(), { recursive: true });
          const known = new Set<string>(existsSync(statePath) ? (JSON.parse(readFileSync(statePath, "utf8")) as string[]) : []);
          console.log(`Watching every ${iv}s (${known.size} known items). Ctrl-C to stop.`);
          for (;;) {
            const r = scan(); const items = [...r.mcpServers.map((s) => `mcp:${s.name}:${s.transport}:${s.url ?? s.command}`), ...r.workloads.map((w) => `${w.source}:${w.kind}:${w.name}`), ...r.credentials.map((k) => `env:${k.name}`)];
            const fresh = items.filter((i) => !known.has(i));
            if (fresh.length) {
              console.log(`${new Date().toISOString()} — ${fresh.length} new: ${fresh.join(", ")}`);
              if (register) { const c = load(); if (c) for (const s of r.mcpServers) if (s.transport === "http" && s.url && fresh.includes(`mcp:${s.name}:http:${s.url}`)) { const res = await fetch(`${c.baseUrl}/api/v1/integrations/mcp`, { method: "POST", headers: { authorization: `Bearer ${c.apiKey}`, "content-type": "application/json" }, body: JSON.stringify({ name: s.name, config: { url: s.url, transport: "streamable_http", action_prefix: "mcp:" } }) }); console.log(`  registered ${s.name}: ${res.status}`); } }
              for (const i of fresh) known.add(i); writeFileSync(statePath, JSON.stringify([...known]));
            }
            await new Promise((r) => setTimeout(r, iv * 1000));
          }
        }
        const r = scan(); track("scan", { connected: !!load() });
        if (rest.includes("--json")) return out({ ...r, mcpServers: r.mcpServers.map((s) => ({ ...s, protected: isProxied(s.args) })) });
        if (!load()) console.log("Tip: `mnki init` (local, no account) or `mnki init --url … --key …` to connect a console; `mnki protect` puts a server behind the proxy.\n");
        console.log(`Scanned ${r.scannedFiles.length} MCP client config${r.scannedFiles.length === 1 ? "" : "s"}${r.scannedFiles.length ? ":\n  " + r.scannedFiles.join("\n  ") : ""}`);
        console.log(`\nFound ${r.mcpServers.length} MCP server${r.mcpServers.length === 1 ? "" : "s"}:`);
        for (const s of r.mcpServers) console.log(`  ${(isProxied(s.args) ? "🛡 " : "   ")}${s.name.padEnd(26)} ${s.transport === "http" ? s.url : `stdio: ${s.command} ${(s.args ?? []).join(" ")}`}   [${s.source}]`);
        if (r.mcpServers.length) console.log(`  (🛡 = behind the mnki proxy; ${r.mcpServers.filter((s) => isProxied(s.args)).length}/${r.mcpServers.length} protected)`);
        console.log(`\n${r.credentials.length} credential${r.credentials.length === 1 ? "" : "s"} an agent could use (environment):`);
        for (const k of r.credentials) console.log(`  ${k.provider.padEnd(14)} ${k.name}  ${k.masked}`);
        console.log(`\n${r.workloads.length} workload identit${r.workloads.length === 1 ? "y" : "ies"} via ${r.toolsTried.join(" / ")} (only tools that are installed and signed in answer):`);
        for (const w of r.workloads) console.log(`  ${w.source.padEnd(11)} ${w.kind.padEnd(15)} ${w.name}  ${w.detail}`);
        if (register) {
          const c = need(); let n = 0;
          for (const s of r.mcpServers) if (s.transport === "http" && s.url) { const res = await fetch(`${c.baseUrl}/api/v1/integrations/mcp`, { method: "POST", headers: { authorization: `Bearer ${c.apiKey}`, "content-type": "application/json" }, body: JSON.stringify({ name: s.name, config: { url: s.url, transport: "streamable_http", action_prefix: "mcp:" } }) }); if (res.ok) n++; }
          console.log(`\nRegistered ${n} HTTP MCP server${n === 1 ? "" : "s"} as integrations (stdio servers: use \`mnki protect --client … --server …\` to put them behind the local proxy).`);
        } else if (r.mcpServers.some((s) => s.transport === "http")) console.log("\nRun again with --register to register the HTTP servers as integrations.");
        return;
      }
      case "protect": {
        const sub = rest[0] === "rollback" || rest[0] === "status" || rest[0] === "report" ? rest[0] : null;
        const { values } = parseArgs({ args: sub ? rest.slice(1) : rest, options: { client: { type: "string" }, server: { type: "string" }, agent: { type: "string" }, mode: { type: "string", default: "observe" }, apply: { type: "boolean", default: false }, project: { type: "string" }, "amount-map": { type: "string" }, gateway: { type: "string" }, mcp: { type: "string" }, json: { type: "boolean", default: false }, yes: { type: "boolean", default: false } } });
        const CLIENTS: ProtectClient[] = ["claude-desktop", "claude-code", "cursor", "windsurf", "vscode", "project"];
        const gw = values.gateway ?? values.mcp;
        if (gw) { const c = need(); const url = `${c.baseUrl}/api/gateway/mcp/${gw}`; console.log(`Hosted gateway — point your MCP client at it instead of the server:\n${JSON.stringify({ mcpServers: { protected: { url, headers: { Authorization: "Bearer <agent trust key, scope verify>", "Agent-Id": values.agent ?? "<agent id>" } } } }, null, 2)}\nEvery tools/call is verified; denials return JSON-RPC -32003, escalations -32001.`); return; }
        if (sub === "status") { const m = readManifest(); if (values.json) return out(m); if (!m.entries.length) { console.log("No servers protected on this machine. Try: mnki protect --client cursor --server <name> --agent <id>"); return; } for (const e of m.entries) console.log(`  ${e.client.padEnd(15)} ${e.server.padEnd(24)} ${e.mode.padEnd(17)} agent ${e.agent}  since ${e.appliedAt.slice(0, 16)}  ${e.path}`); return; }
        if (sub === "report") {
          if (!values.server) throw new Error("usage: mnki protect report --server <name> [--json]");
          const sum = summarizeShadow(values.server, readShadow(values.server)); if (values.json) return out(sum);
          if (!sum.calls) { console.log(`No shadow log yet at ${shadowLogPath(values.server)} — run the client in observe or warn mode first.`); return; }
          console.log(`Shadow report for ${sum.server}: ${sum.calls} tools/call observed\n  would allow ${sum.wouldAllow}   would deny ${sum.wouldDeny}   approval required ${sum.approvalRequired}\n  missing identity ${sum.missingIdentity}   missing delegation ${sum.missingDelegation}   excess capability ${sum.excessCapability}   policy mismatch ${sum.policyMismatch}`);
          console.log("  by tool:"); for (const [t, v] of Object.entries(sum.byTool)) console.log(`    ${t.padEnd(32)} ${String(v.calls).padStart(5)} calls  ${String(v.deny).padStart(4)} deny  ${String(v.approval).padStart(4)} approval`);
          if (sum.suggestions.length) { console.log("  before --mode enforce:"); for (const x of sum.suggestions) console.log(`    • ${x}`); }
          return;
        }
        const client = values.client as ProtectClient | undefined; if (!client || !CLIENTS.includes(client) || !values.server) throw new Error(`usage: mnki protect [rollback] --client ${CLIENTS.join("|")} --server <name> --agent <id> [--mode observe|warn|require_approval|enforce] [--apply]`);
        const path = configPathFor(client); if (!existsSync(path)) throw new Error(`${path} does not exist — is ${client} installed / configured?`);
        const text = readFileSync(path, "utf8");
        if (sub === "rollback") {
          const entry = readManifest().entries.find((e) => e.client === client && e.server === values.server && e.path === path);
          const plan = planRollback(text, values.server, path, entry?.original, values.project, { appliedSha256: entry?.appliedSha256, backupText: entry && existsSync(entry.backup) ? readFileSync(entry.backup, "utf8") : undefined });
          if (!values.apply) { console.log(plan.diff); console.log(`\nDry run. Re-run with --apply to restore "${values.server}" in ${path}.`); return; }
          applyRollback(plan, client, values.server); console.log(`Restored "${values.server}" in ${path}. Restart ${client} to pick it up.`); track("protect_rollback", { client }); return;
        }
        const mode = values.mode as ProtectMode; if (!["observe", "warn", "require_approval", "enforce"].includes(mode)) throw new Error("--mode must be observe|warn|require_approval|enforce");
        if (!values.agent) throw new Error("--agent <id> is required (mnki identity create --name … prints one)");
        const spec = { client, server: values.server, agent: values.agent, mode, amountMap: values["amount-map"], project: values.project };
        const plan = planProtect(text, spec, path);
        if (!values.apply) { console.log(plan.diff); console.log(`\nDry run — nothing written. ${plan.alreadyProtected ? "Already protected; this changes the proxy flags." : `"${values.server}" would be routed through the mnki proxy in ${mode} mode.`}\nRe-run with --apply to write ${path} (a backup and a manifest make \`mnki protect rollback\` exact).`); return; }
        if (clientRunning(client)) console.error(`Note: ${client} appears to be running — it reads its config on restart.`);
        if (!load()) console.error("Note: no console configured; the proxy will refuse to start until MNKI_URL/MNKI_API_KEY are set or `mnki init --url … --key …` has run.");
        const { backup } = applyProtect(plan, spec); track("protect_applied", { client, mode });
        console.log(`Protected "${values.server}" for ${client} in ${mode} mode.\n  file    ${path}\n  backup  ${backup}\n  next    restart ${client}; then \`mnki protect report --server ${values.server}\` shows what would have been denied; \`mnki protect --client ${client} --server ${values.server} --agent ${values.agent} --mode enforce --apply\` when ready; \`mnki protect rollback --client ${client} --server ${values.server} --apply\` undoes it.`);
        return;
      }
      case "revoke": {
        const c = need(); const { values, positionals } = parseArgs({ args: rest, options: { reason: { type: "string" }, "effective-at": { type: "string" } }, allowPositionals: true });
        const [subjectType, subjectId] = positionals; if (!subjectType || !subjectId || !values.reason) throw new Error('usage: mnki revoke <agent|credential|delegation|api_key|policy_version> <id> --reason "why" [--effective-at <iso>]');
        const res = await fetch(`${c.baseUrl}/api/v1/revocations`, { method: "POST", headers: { authorization: `Bearer ${c.apiKey}`, "content-type": "application/json" }, body: JSON.stringify({ subject_type: subjectType, subject_id: subjectId, reason: values.reason, effective_at: values["effective-at"] }) });
        const j = (await res.json().catch(() => ({}))) as { id?: string; error?: string };
        if (!res.ok) throw new Error(`revocation refused: ${j.error ?? res.status}${res.status === 403 ? " (needs an admin-scope key)" : ""}`);
        console.log(`Revoked ${subjectType} ${subjectId} (${j.id}). Every verification touching it now answers DENY; edge snapshots follow within 60 s.`); return;
      }
      case "policy": {
        const sub = rest[0];
        if (sub === "test") {
          const { values, positionals } = parseArgs({ args: rest.slice(1), options: { cases: { type: "string" }, json: { type: "boolean", default: false } }, allowPositionals: true });
          const docPath = positionals[0]; if (!docPath || !values.cases) throw new Error("usage: mnki policy test <policy.json> --cases <cases.json> [--json]");
          const r = policyTest(JSON.parse(readFileSync(docPath, "utf8")), JSON.parse(readFileSync(values.cases, "utf8")) as PolicyCase[]);
          if (!r.ok && "error" in r) throw new Error(`invalid policy: ${r.error}`);
          if (values.json) return out(r);
          for (const t of r.results) console.log(`  ${t.ok ? "✓" : "✕"} ${t.name.padEnd(40)} ${t.effect}${t.fired.length ? `  (${t.fired.join(", ")})` : "  (default)"}${t.expected && !t.ok ? `  expected ${t.expected}` : ""}`);
          console.log(`${r.results.filter((t) => t.ok).length}/${r.results.length} cases as expected`); process.exitCode = r.ok ? 0 : 1; return;
        }
        if (sub === "explain") { const target = rest[1] ?? "--last"; const x = explainFile(target); if (rest.includes("--json")) return out(x); console.log(formatExplanation(x)); return; }
        throw new Error("usage: mnki policy test <policy.json> --cases <cases.json> | mnki policy explain <decision.json|--last>");
      }
      case "telemetry": {
        const sub = rest[0]; const c = load() ?? { baseUrl: "", apiKey: "", identities: {} };
        if (sub === "on" || sub === "off") { save({ ...c, telemetry: sub === "on" }); console.log(`Telemetry ${sub}.`); return; }
        console.log(`Telemetry is ${process.env.MNKI_TELEMETRY === "0" ? "off (MNKI_TELEMETRY=0)" : c.telemetry === false ? "off" : "on"} — anonymous install id, allow-listed events, never arguments or names. \`mnki telemetry off\` to disable.`); return;
      }
      case "conformance": {
        const { values } = parseArgs({ args: rest, options: { level: { type: "string", default: "3" }, dir: { type: "string" }, badge: { type: "boolean", default: false } } });
        const dir = values.dir ?? findConformanceDir(); if (!dir) throw new Error("conformance directory not found — pass --dir <path to conformance/>");
        const level = Math.min(3, Math.max(1, Number(values.level) || 3));
        const { text, ok } = formatReport(await runConformance(dir, level), level); console.log(text); process.exitCode = ok ? 0 : 1;
        if (values.badge && ok) console.log(`\nREADME badge:\n[![Agent Trust conformance level ${level}](https://mnki.com/badge/conformance-L${level}.svg)](https://mnki.com/docs/conformance)`);
        return;
      }
      default:
        console.log("mnki <demo|init|identity|verify|policy|inspect|passport|delegate|attest|revoke|scan|protect|conformance|telemetry> — see packages/cli/src/main.ts for usage"); process.exitCode = cmd ? 2 : 0;
    }
  } catch (e) {
    if (e instanceof AgentTrustError) console.error(`API error ${e.status} ${e.code}${e.detail ? ` — ${typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)}` : ""}`);
    else console.error(e instanceof Error ? e.message : String(e));
    process.exitCode = 1;
  }
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

if (isEntrypoint(process.argv[1], import.meta.url)) void main();

/**
 * `agenttrust scan` — discover agents and the credentials they could use on
 * this machine, from the places they actually live: MCP client configs
 * (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf), and API keys in the
 * environment. Pure functions over file contents so it is testable.
 */
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir, platform } from "node:os";
import { execFileSync } from "node:child_process";

export interface McpServerFinding { source: string; name: string; transport: "http" | "stdio"; url?: string; command?: string; args?: string[] }
export interface CredentialFinding { source: "env"; name: string; provider: string; masked: string }
export interface WorkloadFinding { source: "kubernetes" | "aws" | "github"; name: string; kind: string; detail: string }
export interface ScanResult { mcpServers: McpServerFinding[]; credentials: CredentialFinding[]; workloads: WorkloadFinding[]; scannedFiles: string[]; toolsTried: string[] }
/** Run a local CLI and return stdout, or null when the tool is missing / not authenticated. Injectable for tests. */
export type Runner = (cmd: string, args: string[]) => string | null;
export const defaultRunner: Runner = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 15000 }); } catch { return null; } };

/** Kubernetes: service accounts and deployments that look like agents (name/label heuristics) — the identities workloads actually run as. */
export function discoverKubernetes(run: Runner): WorkloadFinding[] {
  const out: WorkloadFinding[] = [];
  const sa = run("kubectl", ["get", "serviceaccounts", "-A", "-o", "json"]);
  if (sa) { try { for (const it of (JSON.parse(sa).items ?? []) as { metadata: { name: string; namespace: string; labels?: Record<string, string> } }[]) { if (it.metadata.name === "default" || it.metadata.namespace.startsWith("kube-")) continue; out.push({ source: "kubernetes", name: `${it.metadata.namespace}/${it.metadata.name}`, kind: "serviceaccount", detail: Object.entries(it.metadata.labels ?? {}).map(([k, v]) => `${k}=${v}`).join(" ") || "no labels" }); } } catch { /* ignore */ } }
  const dep = run("kubectl", ["get", "deployments", "-A", "-o", "json"]);
  if (dep) { try { for (const it of (JSON.parse(dep).items ?? []) as { metadata: { name: string; namespace: string }; spec?: { template?: { spec?: { serviceAccountName?: string; containers?: { image?: string }[] } } } }[]) { const n = `${it.metadata.namespace}/${it.metadata.name}`; if (!/agent|bot|assistant|copilot|llm|mcp|orchestrat|worker/i.test(n)) continue; const t = it.spec?.template?.spec; out.push({ source: "kubernetes", name: n, kind: "deployment", detail: `sa=${t?.serviceAccountName ?? "default"} image=${t?.containers?.[0]?.image ?? "?"}` }); } } catch { /* ignore */ } }
  return out;
}
/** AWS: IAM roles and Bedrock agents whose names suggest autonomous workloads. */
export function discoverAws(run: Runner): WorkloadFinding[] {
  const out: WorkloadFinding[] = [];
  const roles = run("aws", ["iam", "list-roles", "--output", "json"]);
  if (roles) { try { for (const r of (JSON.parse(roles).Roles ?? []) as { RoleName: string; Arn: string; Description?: string }[]) { if (!/agent|bot|bedrock|lambda|assistant|llm|mcp|orchestrat/i.test(r.RoleName)) continue; out.push({ source: "aws", name: r.RoleName, kind: "iam-role", detail: r.Arn }); } } catch { /* ignore */ } }
  const agents = run("aws", ["bedrock-agent", "list-agents", "--output", "json"]);
  if (agents) { try { for (const a of (JSON.parse(agents).agentSummaries ?? []) as { agentId: string; agentName: string; agentStatus?: string }[]) out.push({ source: "aws", name: a.agentName, kind: "bedrock-agent", detail: `${a.agentId} ${a.agentStatus ?? ""}`.trim() }); } catch { /* ignore */ } }
  return out;
}
/** GitHub: Apps installed for the authenticated user (each is a machine identity with repository authority). */
export function discoverGitHub(run: Runner): WorkloadFinding[] {
  const out: WorkloadFinding[] = [];
  const inst = run("gh", ["api", "/user/installations", "--paginate"]);
  if (inst) { try { for (const i of (JSON.parse(inst).installations ?? []) as { id: number; app_slug?: string; account?: { login?: string }; permissions?: Record<string, string>; repository_selection?: string }[]) out.push({ source: "github", name: i.app_slug ?? String(i.id), kind: "github-app", detail: `on ${i.account?.login ?? "?"} · ${i.repository_selection ?? "?"} repos · ${Object.entries(i.permissions ?? {}).map(([k, v]) => `${k}:${v}`).join(" ")}` }); } catch { /* ignore */ } }
  return out;
}

const KEY_PROVIDERS: [RegExp, string][] = [[/^OPENAI_API_KEY$/, "OpenAI"], [/^ANTHROPIC_API_KEY$/, "Anthropic"], [/^GOOGLE_API_KEY$|^GEMINI_API_KEY$/, "Google AI"], [/^GITHUB_TOKEN$|^GH_TOKEN$/, "GitHub"], [/^AWS_ACCESS_KEY_ID$/, "AWS"], [/^AZURE_OPENAI_API_KEY$/, "Azure OpenAI"], [/^SLACK_BOT_TOKEN$/, "Slack"], [/^STRIPE_SECRET_KEY$/, "Stripe"], [/^HF_TOKEN$|^HUGGINGFACE_TOKEN$/, "Hugging Face"], [/^MISTRAL_API_KEY$/, "Mistral"], [/^OPENROUTER_API_KEY$/, "OpenRouter"]];

/** Known MCP client config locations for this OS. */
export function mcpConfigCandidates(home = homedir(), cwd = process.cwd(), os = platform()): { source: string; path: string }[] {
  const appSupport = os === "darwin" ? join(home, "Library", "Application Support") : os === "win32" ? (process.env.APPDATA ?? join(home, "AppData", "Roaming")) : join(home, ".config");
  return [
    { source: "Claude Desktop", path: join(appSupport, "Claude", "claude_desktop_config.json") },
    { source: "Claude Code", path: join(home, ".claude.json") },
    { source: "Cursor", path: join(home, ".cursor", "mcp.json") },
    { source: "Cursor (project)", path: join(cwd, ".cursor", "mcp.json") },
    { source: "VS Code (project)", path: join(cwd, ".vscode", "mcp.json") },
    { source: "Windsurf", path: join(home, ".codeium", "windsurf", "mcp_config.json") },
    { source: "Project", path: join(cwd, ".mcp.json") },
  ];
}

/** Parse the `mcpServers` / `servers` maps found in MCP client configs (Claude Code nests them per project too). */
export function parseMcpConfig(source: string, text: string): McpServerFinding[] {
  let j: unknown; try { j = JSON.parse(text); } catch { return []; }
  const out: McpServerFinding[] = [];
  const take = (map: unknown, where: string) => {
    if (!map || typeof map !== "object") return;
    for (const [name, v] of Object.entries(map as Record<string, unknown>)) {
      if (!v || typeof v !== "object") continue; const s = v as Record<string, unknown>;
      if (typeof s.url === "string") out.push({ source: where, name, transport: "http", url: s.url });
      else if (typeof s.command === "string") out.push({ source: where, name, transport: "stdio", command: s.command, args: Array.isArray(s.args) ? s.args.map(String) : [] });
    }
  };
  const root = j as Record<string, unknown>;
  take(root.mcpServers, source); take(root.servers, source);
  if (root.projects && typeof root.projects === "object") for (const [dir, p] of Object.entries(root.projects as Record<string, Record<string, unknown>>)) take(p?.mcpServers, `${source} · ${dir}`);
  return out;
}

export function scanEnvironment(env: NodeJS.ProcessEnv = process.env): CredentialFinding[] {
  const out: CredentialFinding[] = [];
  for (const [k, v] of Object.entries(env)) { if (!v) continue; const hit = KEY_PROVIDERS.find(([re]) => re.test(k)); if (hit) out.push({ source: "env", name: k, provider: hit[1], masked: `${v.slice(0, 4)}…${v.slice(-3)}` }); }
  return out.sort((a, b) => a.provider.localeCompare(b.provider));
}

export function scan(opts: { home?: string; cwd?: string; env?: NodeJS.ProcessEnv; run?: Runner; tools?: boolean } = {}): ScanResult {
  const files = mcpConfigCandidates(opts.home, opts.cwd); const scannedFiles: string[] = []; const mcpServers: McpServerFinding[] = [];
  for (const f of files) { if (!existsSync(f.path)) continue; scannedFiles.push(f.path); try { mcpServers.push(...parseMcpConfig(f.source, readFileSync(f.path, "utf8"))); } catch { /* unreadable */ } }
  const run = opts.run ?? defaultRunner; const workloads: WorkloadFinding[] = []; const toolsTried: string[] = [];
  if (opts.tools !== false) { toolsTried.push("kubectl", "aws", "gh"); workloads.push(...discoverKubernetes(run), ...discoverAws(run), ...discoverGitHub(run)); }
  return { mcpServers, credentials: scanEnvironment(opts.env), workloads, scannedFiles, toolsTried };
}

/**
 * `agenttrust scan` — discover agents and the credentials they could use on
 * this machine, from the places they actually live: MCP client configs
 * (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf), and API keys in the
 * environment. Pure functions over file contents so it is testable.
 */
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir, platform } from "node:os";

export interface McpServerFinding { source: string; name: string; transport: "http" | "stdio"; url?: string; command?: string; args?: string[] }
export interface CredentialFinding { source: "env"; name: string; provider: string; masked: string }
export interface ScanResult { mcpServers: McpServerFinding[]; credentials: CredentialFinding[]; scannedFiles: string[] }

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

export function scan(opts: { home?: string; cwd?: string; env?: NodeJS.ProcessEnv } = {}): ScanResult {
  const files = mcpConfigCandidates(opts.home, opts.cwd); const scannedFiles: string[] = []; const mcpServers: McpServerFinding[] = [];
  for (const f of files) { if (!existsSync(f.path)) continue; scannedFiles.push(f.path); try { mcpServers.push(...parseMcpConfig(f.source, readFileSync(f.path, "utf8"))); } catch { /* unreadable */ } }
  return { mcpServers, credentials: scanEnvironment(opts.env), scannedFiles };
}

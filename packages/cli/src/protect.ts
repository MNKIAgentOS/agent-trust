/**
 * `mnki protect` — put an MCP server behind the local proxy by rewriting the client's own config. Dry run by
 * default (unified diff), `--apply` writes atomically with a verified backup and a manifest so `rollback` is
 * exact; refuses symlinks and unknown formats; warns when the client is running. Pure planning functions over
 * file text so every client format is tested with fixtures.
 */
import { readFileSync, writeFileSync, renameSync, existsSync, lstatSync, mkdirSync, copyFileSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { homedir, platform } from "node:os";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mcpConfigCandidates } from "./scan";
import { configDir } from "./config";

export type ProtectClient = "claude-desktop" | "claude-code" | "cursor" | "windsurf" | "vscode" | "project";
export type ProtectMode = "observe" | "warn" | "require_approval" | "enforce";
export interface ProtectSpec { client: ProtectClient; server: string; agent: string; mode: ProtectMode; proxyPackage?: string; amountMap?: string; project?: string }
export interface ProtectPlan { path: string; before: string; after: string; diff: string; entryBefore: unknown; entryAfter: unknown; alreadyProtected: boolean }
export interface ProtectManifest { entries: { client: ProtectClient; server: string; path: string; backup: string; agent: string; mode: ProtectMode; appliedAt: string; original: unknown; /** sha256 of the file as written — rollback restores the backup byte-for-byte while the file is still untouched. */ appliedSha256?: string }[] }
const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");

const CLIENTS: Record<ProtectClient, string> = { "claude-desktop": "Claude Desktop", "claude-code": "Claude Code", cursor: "Cursor", windsurf: "Windsurf", vscode: "VS Code (project)", project: "Project" };
export const PROXY_PACKAGE = "mnki-mcp";
export const isProxied = (args: string[] | undefined, pkg = PROXY_PACKAGE): boolean => (args ?? []).some((a) => a === pkg || a.startsWith(`${pkg}@`) || /packages\/mcp\/(src|dist)\/main\.(ts|js)$/.test(a));

export function configPathFor(client: ProtectClient, home = homedir(), cwd = process.cwd(), os = platform()): string {
  const want = CLIENTS[client]; const c = mcpConfigCandidates(home, cwd, os).find((x) => x.source === want);
  if (!c) throw new Error(`no config location known for ${client}`); return c.path;
}
/** Locate the map holding the server (`mcpServers`, `servers`, or Claude Code's per-project map) inside a parsed config. */
function locate(root: Record<string, unknown>, server: string, project?: string): { map: Record<string, unknown>; key: string } | null {
  if (project && root.projects && typeof root.projects === "object") { const p = (root.projects as Record<string, Record<string, unknown>>)[project]; const m = p?.mcpServers as Record<string, unknown> | undefined; if (m && server in m) return { map: m, key: "mcpServers" }; }
  for (const key of ["mcpServers", "servers"]) { const m = root[key] as Record<string, unknown> | undefined; if (m && typeof m === "object" && server in m) return { map: m, key }; }
  if (root.projects && typeof root.projects === "object") for (const p of Object.values(root.projects as Record<string, Record<string, unknown>>)) { const m = p?.mcpServers as Record<string, unknown> | undefined; if (m && server in m) return { map: m, key: "mcpServers" }; }
  return null;
}
/** The proxied entry for a server: stdio entries keep env; HTTP entries carry url + headers as proxy flags; VS Code keeps `type`. */
export function proxiedEntry(entry: Record<string, unknown>, spec: ProtectSpec, vscode: boolean): Record<string, unknown> {
  const pkg = spec.proxyPackage ?? PROXY_PACKAGE;
  const base = ["-y", pkg, "--agent", spec.agent, "--server", spec.server, "--mode", spec.mode, ...(spec.amountMap ? ["--amount-map", spec.amountMap] : [])];
  let args: string[];
  if (typeof entry.url === "string") { const headers = (entry.headers && typeof entry.headers === "object" ? entry.headers : {}) as Record<string, string>; args = [...base, "--upstream-url", entry.url, ...Object.entries(headers).flatMap(([k, v]) => ["--upstream-header", `${k}=${v}`])]; }
  else if (typeof entry.command === "string") args = [...base, "--upstream", "--", entry.command, ...(Array.isArray(entry.args) ? entry.args.map(String) : [])];
  else throw new Error(`server "${spec.server}" has neither url nor command — unknown format`);
  const out: Record<string, unknown> = { ...(vscode ? { type: "stdio" } : {}), command: "npx", args };
  if (entry.env && typeof entry.env === "object") out.env = entry.env;
  if (entry.cwd) out.cwd = entry.cwd;
  return out;
}
/** Restore the original entry from a proxied one (used when re-protecting with a different mode, and by rollback without a manifest). */
export function unproxiedEntry(entry: Record<string, unknown>): Record<string, unknown> | null {
  const args = Array.isArray(entry.args) ? entry.args.map(String) : []; if (entry.command !== "npx" || !isProxied(args)) return null;
  const rest = { ...(entry.env ? { env: entry.env } : {}), ...(entry.cwd ? { cwd: entry.cwd } : {}) };
  const u = args.indexOf("--upstream-url");
  if (u >= 0) { const headers: Record<string, string> = {}; args.forEach((a, i) => { if (a === "--upstream-header") { const [k, ...v] = args[i + 1].split("="); headers[k] = v.join("="); } }); return { ...(entry.type ? { type: "http" } : {}), url: args[u + 1], ...(Object.keys(headers).length ? { headers } : {}), ...rest }; }
  const s = args.indexOf("--upstream"); if (s < 0) return null; const cmd = args.slice(s + 1); if (cmd[0] === "--") cmd.shift();
  return { ...(entry.type ? { type: "stdio" } : {}), command: cmd[0], args: cmd.slice(1), ...rest };
}
/** Minimal unified diff (whole-line) for the dry run. */
export function unifiedDiff(a: string, b: string, name: string): string {
  const A = a.split("\n"), B = b.split("\n"); const n = A.length, m = B.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out: string[] = [`--- ${name}`, `+++ ${name}`]; let i = 0, j = 0;
  while (i < n || j < m) { if (i < n && j < m && A[i] === B[j]) { out.push(` ${A[i]}`); i++; j++; } else if (i < n && (j >= m || dp[i + 1][j] >= dp[i][j + 1])) { out.push(`-${A[i]}`); i++; } else { out.push(`+${B[j]}`); j++; } }
  return out.join("\n");
}
/** Plan the rewrite: parse, locate the server, build the proxied entry, serialise with the file's own indentation. */
export function planProtect(text: string, spec: ProtectSpec, path: string): ProtectPlan {
  let root: Record<string, unknown>; try { root = JSON.parse(text) as Record<string, unknown>; } catch { throw new Error(`${path} is not valid JSON — refusing to rewrite`); }
  if (!root || typeof root !== "object" || Array.isArray(root)) throw new Error(`${path}: unknown config format`);
  const loc = locate(root, spec.server, spec.project); if (!loc) throw new Error(`server "${spec.server}" not found in ${path} (run \`mnki scan\` to list servers)`);
  const current = loc.map[spec.server] as Record<string, unknown>; const original = unproxiedEntry(current) ?? current;
  const next = proxiedEntry(original, spec, loc.key === "servers");
  loc.map[spec.server] = next;
  const indent = /^\s+/m.exec(text)?.[0].replace(/\n/g, "") || "  ";
  const after = JSON.stringify(root, null, indent.includes("\t") ? "\t" : indent.length) + (text.endsWith("\n") ? "\n" : "");
  return { path, before: text, after, diff: unifiedDiff(text, after, path), entryBefore: current, entryAfter: next, alreadyProtected: unproxiedEntry(current) !== null };
}
export const manifestPath = (): string => join(configDir(), "protect.json");
export function readManifest(): ProtectManifest { const p = manifestPath(); if (!existsSync(p)) return { entries: [] }; try { return JSON.parse(readFileSync(p, "utf8")) as ProtectManifest; } catch { return { entries: [] }; } }
function writeManifest(m: ProtectManifest): void { mkdirSync(configDir(), { recursive: true }); writeFileSync(manifestPath(), JSON.stringify(m, null, 2)); }
/** Write `after` to `path` atomically: refuse symlinks, back up (re-read to verify), temp file + rename. */
export function writeAtomic(path: string, before: string, after: string): string {
  if (existsSync(path) && lstatSync(path).isSymbolicLink()) throw new Error(`${path} is a symlink — refusing to rewrite; protect the target file instead`);
  const backup = `${path}.mnki-bak-${new Date().toISOString().replace(/[:.]/g, "-")}`;
  copyFileSync(path, backup); if (readFileSync(backup, "utf8") !== before) throw new Error(`backup verification failed for ${backup}`);
  const tmp = join(dirname(path), `.${basename(path)}.mnki-tmp-${process.pid}`); writeFileSync(tmp, after); renameSync(tmp, path);
  return backup;
}
export function applyProtect(plan: ProtectPlan, spec: ProtectSpec): { backup: string } {
  const backup = writeAtomic(plan.path, plan.before, plan.after);
  const m = readManifest(); m.entries = m.entries.filter((e) => !(e.client === spec.client && e.server === spec.server && e.path === plan.path));
  const prior = readManifest().entries.find((e) => e.client === spec.client && e.server === spec.server && e.path === plan.path);
  // Re-protecting keeps the first backup (the truly original file) so rollback lands on what the user had before mnki touched it.
  const keepBackup = prior && existsSync(prior.backup) && prior.appliedSha256 === sha256(plan.before) ? prior.backup : backup;
  m.entries.push({ client: spec.client, server: spec.server, path: plan.path, backup: keepBackup, agent: spec.agent, mode: spec.mode, appliedAt: new Date().toISOString(), original: prior?.original ?? unproxiedEntry(plan.entryBefore as Record<string, unknown>) ?? plan.entryBefore, appliedSha256: sha256(plan.after) });
  writeManifest(m); return { backup };
}
/** Put the original entry back (from the manifest, or by unwrapping the proxied entry when there is no manifest row). */
export function planRollback(text: string, server: string, path: string, original?: unknown, project?: string, exact?: { appliedSha256?: string; backupText?: string }): ProtectPlan {
  const root = JSON.parse(text) as Record<string, unknown>; const loc = locate(root, server, project); if (!loc) throw new Error(`server "${server}" not found in ${path}`);
  const current = loc.map[server] as Record<string, unknown>; const restored = original ?? unproxiedEntry(current); if (!restored) throw new Error(`server "${server}" in ${path} is not proxied and no manifest entry exists`);
  // Untouched since we wrote it → put the backup back byte for byte (formatting, comments-as-keys, ordering all survive).
  if (exact?.backupText !== undefined && exact.appliedSha256 && sha256(text) === exact.appliedSha256) return { path, before: text, after: exact.backupText, diff: unifiedDiff(text, exact.backupText, path), entryBefore: current, entryAfter: restored, alreadyProtected: true };
  loc.map[server] = restored;
  const indent = /^\s+/m.exec(text)?.[0].replace(/\n/g, "") || "  ";
  const after = JSON.stringify(root, null, indent.includes("\t") ? "\t" : indent.length) + (text.endsWith("\n") ? "\n" : "");
  return { path, before: text, after, diff: unifiedDiff(text, after, path), entryBefore: current, entryAfter: restored, alreadyProtected: true };
}
export function applyRollback(plan: ProtectPlan, client: ProtectClient, server: string): void {
  writeAtomic(plan.path, plan.before, plan.after);
  const m = readManifest(); m.entries = m.entries.filter((e) => !(e.client === client && e.server === server && e.path === plan.path)); writeManifest(m);
}
/** Is the client app running? (best effort, `ps` on unix; the config is re-read on restart only). */
export function clientRunning(client: ProtectClient, ps: () => string = () => { try { return execFileSync("ps", ["-axo", "comm="], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }); } catch { return ""; } }): boolean {
  const pat: Record<ProtectClient, RegExp> = { "claude-desktop": /\/Claude(\.app\/Contents\/MacOS\/Claude)?$|^claude$/im, "claude-code": /\bclaude$/m, cursor: /Cursor/, windsurf: /Windsurf/i, vscode: /Code(\.app|$)|Code Helper/i, project: /$^/ };
  return pat[client].test(ps());
}

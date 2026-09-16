import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, symlinkSync, existsSync, rmSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { planProtect, applyProtect, planRollback, applyRollback, readManifest, unproxiedEntry, isProxied, configPathFor, clientRunning, unifiedDiff, type ProtectSpec } from "../src/protect";

const spec = (over: Partial<ProtectSpec> = {}): ProtectSpec => ({ client: "cursor", server: "github", agent: "agt_1", mode: "observe", ...over });
let home: string;
beforeEach(() => { home = mkdtempSync(join(tmpdir(), "mnki-protect-")); process.env.MNKI_HOME = home; });
afterEach(() => { delete process.env.MNKI_HOME; rmSync(home, { recursive: true, force: true }); });

describe("mnki protect — planning", () => {
  it("wraps a stdio server (mcpServers format) in the proxy, keeps env, and re-protecting swaps the mode without double-wrapping", () => {
    const text = JSON.stringify({ mcpServers: { github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"], env: { GITHUB_TOKEN: "x" } }, other: { url: "https://a/mcp" } } }, null, 2) + "\n";
    const p = planProtect(text, spec(), "/c/mcp.json");
    const e = p.entryAfter as { command: string; args: string[]; env: unknown };
    expect(e.command).toBe("npx"); expect(e.args).toEqual(["-y", "mnki-mcp", "--agent", "agt_1", "--server", "github", "--mode", "observe", "--upstream", "--", "npx", "-y", "@modelcontextprotocol/server-github"]); expect(e.env).toEqual({ GITHUB_TOKEN: "x" });
    expect(p.alreadyProtected).toBe(false); expect(p.diff).toMatch(/^--- \/c\/mcp\.json/); expect(p.diff).toMatch(/\+\s+"mnki-mcp"/); expect(p.after.endsWith("\n")).toBe(true);
    expect((JSON.parse(p.after) as { mcpServers: { other: unknown } }).mcpServers.other).toEqual({ url: "https://a/mcp" });
    const p2 = planProtect(p.after, spec({ mode: "enforce" }), "/c/mcp.json");
    expect(p2.alreadyProtected).toBe(true); expect((p2.entryAfter as { args: string[] }).args.filter((a) => a === "--upstream")).toHaveLength(1); expect((p2.entryAfter as { args: string[] }).args).toContain("enforce");
  });
  it("wraps an HTTP server with url + headers as proxy flags, and VS Code's `servers` format keeps `type`", () => {
    const http = planProtect(JSON.stringify({ mcpServers: { billing: { url: "https://mcp.example/mcp", headers: { Authorization: "Bearer t=1" } } } }), spec({ server: "billing", amountMap: "pay=amount:currency" }), "/c/x.json");
    expect((http.entryAfter as { args: string[] }).args).toEqual(["-y", "mnki-mcp", "--agent", "agt_1", "--server", "billing", "--mode", "observe", "--amount-map", "pay=amount:currency", "--upstream-url", "https://mcp.example/mcp", "--upstream-header", "Authorization=Bearer t=1"]);
    expect(unproxiedEntry(http.entryAfter as Record<string, unknown>)).toEqual({ url: "https://mcp.example/mcp", headers: { Authorization: "Bearer t=1" } });
    const vs = planProtect(JSON.stringify({ servers: { pw: { type: "stdio", command: "npx", args: ["@playwright/mcp"] } } }), spec({ client: "vscode", server: "pw" }), "/p/.vscode/mcp.json");
    expect((vs.entryAfter as { type: string }).type).toBe("stdio"); expect(unproxiedEntry(vs.entryAfter as Record<string, unknown>)).toEqual({ type: "stdio", command: "npx", args: ["@playwright/mcp"] });
  });
  it("finds Claude Code's per-project servers and refuses unknown servers, invalid JSON and entries without url/command", () => {
    const cc = JSON.stringify({ mcpServers: {}, projects: { "/work/app": { mcpServers: { pg: { command: "docker", args: ["run", "pg-mcp"] } } } } });
    expect((planProtect(cc, spec({ client: "claude-code", server: "pg", project: "/work/app" }), "/h/.claude.json").entryAfter as { args: string[] }).args).toContain("pg-mcp");
    expect(() => planProtect(cc, spec({ server: "nope" }), "/x")).toThrow(/not found/);
    expect(() => planProtect("{ nope", spec(), "/x")).toThrow(/not valid JSON/);
    expect(() => planProtect(JSON.stringify({ mcpServers: { github: { weird: true } } }), spec(), "/x")).toThrow(/neither url nor command/);
  });
  it("knows every client's config path and detects proxied entries", () => {
    expect(configPathFor("claude-desktop", "/h", "/c", "darwin")).toBe("/h/Library/Application Support/Claude/claude_desktop_config.json");
    expect(configPathFor("claude-code", "/h", "/c", "linux")).toBe("/h/.claude.json"); expect(configPathFor("cursor", "/h", "/c", "linux")).toBe("/h/.cursor/mcp.json");
    expect(configPathFor("windsurf", "/h", "/c", "linux")).toBe("/h/.codeium/windsurf/mcp_config.json"); expect(configPathFor("vscode", "/h", "/c", "linux")).toBe("/c/.vscode/mcp.json"); expect(configPathFor("project", "/h", "/c", "linux")).toBe("/c/.mcp.json");
    expect(isProxied(["-y", "mnki-mcp@0.1.0"])).toBe(true); expect(isProxied(["-y", "@modelcontextprotocol/server-github"])).toBe(false); expect(isProxied(["packages/mcp/src/main.ts"])).toBe(true);
    expect(clientRunning("cursor", () => "Cursor Helper\nzsh")).toBe(true); expect(clientRunning("claude-desktop", () => "/Applications/Claude.app/Contents/MacOS/Claude\n")).toBe(true); expect(clientRunning("project", () => "anything")).toBe(false);
    expect(unifiedDiff("a\nb\n", "a\nc\n", "f")).toBe("--- f\n+++ f\n a\n-b\n+c\n ");
  });
});

describe("mnki protect — apply and rollback", () => {
  it("writes atomically with a verified backup and a manifest; rollback restores the exact original and clears the manifest", () => {
    const path = join(home, "mcp.json"); const text = JSON.stringify({ mcpServers: { github: { command: "npx", args: ["-y", "srv"] } } }, null, 4) + "\n"; writeFileSync(path, text);
    const s = spec(); const { backup } = applyProtect(planProtect(text, s, path), s);
    expect(readFileSync(backup, "utf8")).toBe(text); expect(readFileSync(path, "utf8")).toMatch(/"mnki-mcp"/); expect(readFileSync(path, "utf8")).toMatch(/^    "mcpServers"/m);
    expect(readdirSync(home).filter((f) => f.includes("mnki-tmp"))).toEqual([]);
    const m = readManifest(); expect(m.entries).toHaveLength(1); expect(m.entries[0]).toMatchObject({ client: "cursor", server: "github", path, backup, mode: "observe", original: { command: "npx", args: ["-y", "srv"] } });
    expect(m.entries[0].appliedSha256).toHaveLength(64);
    // Re-protect in enforce mode: the manifest keeps the original backup and the original entry.
    const s2 = spec({ mode: "enforce" }); applyProtect(planProtect(readFileSync(path, "utf8"), s2, path), s2);
    const m2 = readManifest(); expect(m2.entries).toHaveLength(1); expect(m2.entries[0]).toMatchObject({ mode: "enforce", backup, original: { command: "npx", args: ["-y", "srv"] } });
    // Untouched since apply → rollback restores the backup byte for byte (a JSON edit would reformat it).
    const compact = '{"mcpServers":{"github":{"command":"npx","args":["-y","srv"]}}}'; writeFileSync(path, compact); const s3 = spec(); applyProtect(planProtect(compact, s3, path), s3);
    const e3 = readManifest().entries[0]; const rb = planRollback(readFileSync(path, "utf8"), "github", path, e3.original, undefined, { appliedSha256: e3.appliedSha256, backupText: readFileSync(e3.backup, "utf8") }); applyRollback(rb, "cursor", "github");
    expect(readFileSync(path, "utf8")).toBe(compact); expect(readManifest().entries).toEqual([]);
    // Edited by hand after apply → structural rollback keeps the user's other changes.
    const s4 = spec(); applyProtect(planProtect(compact, s4, path), s4); const edited = readFileSync(path, "utf8").replace('"github"', '"other": {"url":"https://o"}, "github"'); writeFileSync(path, edited);
    const e4 = readManifest().entries[0]; const rb2 = planRollback(edited, "github", path, e4.original, undefined, { appliedSha256: e4.appliedSha256, backupText: readFileSync(e4.backup, "utf8") }); applyRollback(rb2, "cursor", "github");
    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual({ mcpServers: { other: { url: "https://o" }, github: { command: "npx", args: ["-y", "srv"] } } });
    expect(() => planRollback(text, "github", path)).toThrow(/not proxied/);
  });
  it("refuses to rewrite through a symlink", () => {
    const real = join(home, "real.json"); writeFileSync(real, JSON.stringify({ mcpServers: { github: { command: "x" } } })); const link = join(home, "link.json"); symlinkSync(real, link);
    const s = spec(); expect(() => applyProtect(planProtect(readFileSync(link, "utf8"), s, link), s)).toThrow(/symlink/); expect(existsSync(join(home, "protect.json"))).toBe(false);
  });
});

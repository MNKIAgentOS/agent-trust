import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { parseMcpConfig, scan, scanEnvironment, mcpConfigCandidates } from "../src/scan";

describe("agenttrust scan", () => {
  it("finds MCP servers across client configs (including Claude Code's per-project nesting) and API keys in the environment", () => {
    const home = mkdtempSync(join(tmpdir(), "at-home-")); const cwd = mkdtempSync(join(tmpdir(), "at-cwd-"));
    mkdirSync(join(home, ".cursor"), { recursive: true }); mkdirSync(join(cwd, ".vscode"), { recursive: true });
    writeFileSync(join(home, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { github: { url: "https://api.githubcopilot.com/mcp/" }, fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"] } } }));
    writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: { linear: { url: "https://mcp.linear.app/mcp" } }, projects: { "/work/app": { mcpServers: { postgres: { command: "docker", args: ["run", "pg-mcp"] } } } } }));
    writeFileSync(join(cwd, ".vscode", "mcp.json"), JSON.stringify({ servers: { playwright: { command: "npx", args: ["@playwright/mcp"] } } }));
    const r = scan({ home, cwd, env: { OPENAI_API_KEY: "sk-proj-abcdefghijklmnop", GITHUB_TOKEN: "ghp_1234567890", PATH: "/usr/bin" } });
    expect(r.scannedFiles).toHaveLength(3);
    expect(r.mcpServers.map((s) => `${s.name}:${s.transport}`).sort()).toEqual(["fs:stdio", "github:http", "linear:http", "playwright:stdio", "postgres:stdio"]);
    expect(r.mcpServers.find((s) => s.name === "postgres")?.source).toBe("Claude Code · /work/app");
    expect(r.credentials).toEqual([{ source: "env", name: "GITHUB_TOKEN", provider: "GitHub", masked: "ghp_…890" }, { source: "env", name: "OPENAI_API_KEY", provider: "OpenAI", masked: "sk-p…nop" }]);
    expect(parseMcpConfig("x", "not json")).toEqual([]); expect(scanEnvironment({})).toEqual([]);
    expect(mcpConfigCandidates("/h", "/c", "darwin")[0].path).toBe("/h/Library/Application Support/Claude/claude_desktop_config.json");
  });
});

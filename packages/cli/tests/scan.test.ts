import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { parseMcpConfig, scan, scanEnvironment, mcpConfigCandidates, discoverKubernetes, discoverAws, discoverGitHub } from "../src/scan";

describe("agenttrust scan", () => {
  it("finds MCP servers across client configs (including Claude Code's per-project nesting) and API keys in the environment", () => {
    const home = mkdtempSync(join(tmpdir(), "at-home-")); const cwd = mkdtempSync(join(tmpdir(), "at-cwd-"));
    mkdirSync(join(home, ".cursor"), { recursive: true }); mkdirSync(join(cwd, ".vscode"), { recursive: true });
    writeFileSync(join(home, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { github: { url: "https://api.githubcopilot.com/mcp/" }, fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"] } } }));
    writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: { linear: { url: "https://mcp.linear.app/mcp" } }, projects: { "/work/app": { mcpServers: { postgres: { command: "docker", args: ["run", "pg-mcp"] } } } } }));
    writeFileSync(join(cwd, ".vscode", "mcp.json"), JSON.stringify({ servers: { playwright: { command: "npx", args: ["@playwright/mcp"] } } }));
    const r = scan({ home, cwd, env: { OPENAI_API_KEY: "sk-proj-abcdefghijklmnop", GITHUB_TOKEN: "ghp_1234567890", PATH: "/usr/bin" }, tools: false });
    expect(r.scannedFiles).toHaveLength(3);
    expect(r.mcpServers.map((s) => `${s.name}:${s.transport}`).sort()).toEqual(["fs:stdio", "github:http", "linear:http", "playwright:stdio", "postgres:stdio"]);
    expect(r.mcpServers.find((s) => s.name === "postgres")?.source).toBe("Claude Code · /work/app");
    expect(r.credentials).toEqual([{ source: "env", name: "GITHUB_TOKEN", provider: "GitHub", masked: "ghp_…890" }, { source: "env", name: "OPENAI_API_KEY", provider: "OpenAI", masked: "sk-p…nop" }]);
    expect(parseMcpConfig("x", "not json")).toEqual([]); expect(scanEnvironment({})).toEqual([]);
    expect(mcpConfigCandidates("/h", "/c", "darwin")[0].path).toBe("/h/Library/Application Support/Claude/claude_desktop_config.json");
  });
});

describe("agenttrust scan — workload identities via local CLIs (stubbed)", () => {
  it("lists Kubernetes service accounts / agent-like deployments, AWS agent roles + Bedrock agents, and GitHub Apps; missing tools yield nothing", () => {
    const run = (cmd: string, args: string[]): string | null => {
      const key = `${cmd} ${args.join(" ")}`;
      if (key.startsWith("kubectl get serviceaccounts")) return JSON.stringify({ items: [{ metadata: { name: "default", namespace: "prod" } }, { metadata: { name: "procurement-agent", namespace: "prod", labels: { team: "finance" } } }, { metadata: { name: "x", namespace: "kube-system" } }] });
      if (key.startsWith("kubectl get deployments")) return JSON.stringify({ items: [{ metadata: { name: "procurement-agent", namespace: "prod" }, spec: { template: { spec: { serviceAccountName: "procurement-agent", containers: [{ image: "acme/procurement:1.8.2" }] } } } }, { metadata: { name: "web", namespace: "prod" } }] });
      if (key.startsWith("aws iam list-roles")) return JSON.stringify({ Roles: [{ RoleName: "bedrock-agent-exec", Arn: "arn:aws:iam::1:role/bedrock-agent-exec" }, { RoleName: "OrganizationAccountAccessRole", Arn: "arn:x" }] });
      if (key.startsWith("aws bedrock-agent list-agents")) return JSON.stringify({ agentSummaries: [{ agentId: "AG1", agentName: "support-agent", agentStatus: "PREPARED" }] });
      if (key.startsWith("gh api /user/installations")) return JSON.stringify({ installations: [{ id: 7, app_slug: "deploy-bot", account: { login: "MNKIAgentOS" }, repository_selection: "selected", permissions: { contents: "write" } }] });
      return null;
    };
    expect(discoverKubernetes(run).map((w) => `${w.kind}:${w.name}`)).toEqual(["serviceaccount:prod/procurement-agent", "deployment:prod/procurement-agent"]);
    expect(discoverAws(run).map((w) => `${w.kind}:${w.name}`)).toEqual(["iam-role:bedrock-agent-exec", "bedrock-agent:support-agent"]);
    expect(discoverGitHub(run)[0]).toMatchObject({ kind: "github-app", name: "deploy-bot", detail: "on MNKIAgentOS · selected repos · contents:write" });
    expect(discoverKubernetes(() => null)).toEqual([]);
    const r = scan({ home: "/nonexistent-home", cwd: "/nonexistent-cwd", env: {}, run });
    expect(r.workloads).toHaveLength(5); expect(r.toolsTried).toEqual(["kubectl", "aws", "gh"]);
  });
});

# Integrations

Every path into Agent Trust in three lines or fewer. Pick the row that matches what you already run; each
section is complete on its own. `mnki` is the developer brand: npm `mnki-cli`, `mnki-sdk`, `mnki-mcp`,
`mnki-verifier`; PyPI `mnki`; container `ghcr.io/mnkiagentos/mnki-mcp`.

| You have… | Start here | What you get |
| --- | --- | --- |
| Nothing yet | `npx mnki-cli demo` | The €47,000 refund story: DENY with evidence, ALLOW, REQUIRE_APPROVAL. No account. |
| MCP servers in Claude Desktop, Claude Code, Cursor, Windsurf or VS Code | `npx mnki-cli scan` then `mnki protect` | Every `tools/call` verified; observe first, enforce when ready. |
| An agent written in TypeScript or Python | `npm i mnki-sdk` / `pip install mnki` | `guard.wrap(tool)` in local mode, then a console for approvals and the ledger. |
| OpenAI Agents, LangChain, Claude Agent SDK, Vercel AI, CrewAI, Pydantic AI | the adapter subpath | One line per framework, framework never imported by mnki. |
| A remote MCP server (HTTP) | Console → Integrations → MCP gateway | Hosted proxy URL, nothing installed. |
| Anything else that speaks HTTP | `POST /v1/verify` | The same decision, evidence and ledger from any language. |
| A "must not depend on a vendor" requirement | `mnki-verifier` / `at-verify` (Go) | Offline verification of chains and attestations against the public vectors. |

## MCP clients

`mnki-mcp` is a local proxy: it speaks stdio to the client, launches or connects to the real server behind
it, and verifies each `tools/call` with the evidence list. `mnki protect` edits the client's config for you
(diff first, `--apply` to write, backup kept, `mnki protect rollback` to undo). The blocks below are what
it writes, if you prefer to paste them yourself. Every example needs a console API key with the `verify`
scope (Settings → API keys), placed in `MNKI_API_KEY`; the agent id is the identity the calls run under.

### Claude Desktop

One-click: download `mnki-mcp.mcpb` from the [latest release](https://github.com/MNKIAgentOS/agent-trust/releases/latest),
double-click it, and fill in the upstream server command, the agent id and the API key in the dialog.
Claude Desktop keeps the key in its keychain.

Or edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) / `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "mnki-mcp", "--agent", "desktop-assistant", "--server", "github", "--mode", "observe",
               "--upstream", "--", "npx", "-y", "@modelcontextprotocol/server-github"],
      "env": { "MNKI_API_KEY": "at_verify_…", "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_…" }
    }
  }
}
```

```bash
npx mnki-cli protect --client claude-desktop --server github --agent desktop-assistant --apply
```

### Claude Code

```bash
claude mcp add github -e MNKI_API_KEY=at_verify_… -- npx -y mnki-mcp --agent claude-code --server github --upstream -- npx -y @modelcontextprotocol/server-github
```

or `npx mnki-cli protect --client claude-code --server github --agent claude-code --apply`, which rewrites
the entry in `~/.claude.json` or the project's `.mcp.json`. The Claude Agent SDK (programmatic Claude Code)
uses the hook adapter instead, see below.

### Cursor

`~/.cursor/mcp.json` (global) or `<project>/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "mnki-mcp", "--agent", "cursor", "--server", "github", "--upstream", "--", "npx", "-y", "@modelcontextprotocol/server-github"],
      "env": { "MNKI_API_KEY": "at_verify_…" }
    }
  }
}
```

`npx mnki-cli protect --client cursor --server github --agent cursor --apply` does the same. Cursor's
"Add to Cursor" deep links (`cursor://anysphere.cursor-deeplink/mcp/install?name=…&config=<base64 JSON>`)
carry exactly this JSON, so a team can hand out one link.

### Windsurf

`~/.codeium/windsurf/mcp_config.json`, same `mcpServers` shape as Cursor; `--client windsurf` in `mnki protect`.

### VS Code (Copilot agent mode)

`<project>/.vscode/mcp.json`:

```json
{
  "servers": {
    "github": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "mnki-mcp", "--agent", "vscode", "--server", "github", "--upstream", "--", "npx", "-y", "@modelcontextprotocol/server-github"],
      "env": { "MNKI_API_KEY": "${input:mnki-key}" }
    }
  },
  "inputs": [{ "id": "mnki-key", "type": "promptString", "password": true, "description": "Agent Trust API key" }]
}
```

`npx mnki-cli protect --client vscode --server github --agent vscode --apply`.

### Any other MCP client, or a remote server

Stdio upstream: `npx -y mnki-mcp --agent <id> --server <name> --upstream -- <command> [args…]`.
HTTP upstream (Streamable HTTP): `npx -y mnki-mcp --agent <id> --server <name> --upstream-url https://… --upstream-header "Authorization=Bearer …"`.
Container: `docker run -i ghcr.io/mnkiagentos/mnki-mcp --agent <id> --upstream-url https://…` with `MNKI_API_KEY` in the environment.

Modes: `observe` (default: everything runs, would-deny is logged to `~/.mnki/shadow/<server>.ndjson`), `warn`,
`require_approval` (only what policy escalates waits for a human), `enforce`. `mnki protect report` reads the
shadow log and lists the delegations and capabilities to grant before switching a server to `enforce`.
Denials reach the client as JSON-RPC error `-32003` with the evidence; an approval that timed out is `-32001`;
`-32005` is the plan's verification quota.

### Hosted MCP gateway (no local proxy)

Console → Integrations → **MCP gateway** → the upstream URL and its auth header. The console answers with a
gateway URL; the client calls it with an Agent Trust API key in the `Authorization` header. Same verification,
same ledger, nothing installed. Any client that can send a header works today, for example the OpenAI
Responses API's hosted `mcp` tool:

```python
from openai import OpenAI
client = OpenAI()
resp = client.responses.create(
    model="gpt-5",
    tools=[{ "type": "mcp", "server_label": "github-via-agent-trust",
             "server_url": "https://mnki.com/api/gateway/mcp/<integration id>",
             "headers": { "Authorization": f"Bearer {os.environ['MNKI_API_KEY']}" },
             "require_approval": "never" }],
    input="Open a pull request that bumps the dependency.",
)
```

The ChatGPT connector directory, Claude connectors and Smithery require OAuth sign-in on the server instead of
a header; that is planned for the gateway and will be announced here.

## Frameworks

Adapters are subpaths of `mnki-sdk` and modules of `mnki`; the framework itself is never imported by the
adapter, so its upgrades cannot break the guard. A refused call returns
`{ "error": "denied", "reasons": [...], "evidence": [...] }` to the model unless you pass `onRefused: "throw"`.
Pinned versions and support levels: [compatibility](/docs/compatibility).

```ts
import { createGuard } from "mnki-sdk";
const guard = createGuard({ client: { baseUrl: "https://mnki.com", apiKey: process.env.MNKI_API_KEY! }, agent: "invoice-agent" });

import { guardTools } from "mnki-sdk/openai-agents";      // new Agent({ tools: guardTools(guard, [refund]) })
import { guardTools } from "mnki-sdk/langchain";           // new ToolNode(guardTools(guard, [refund]))
import { preToolUse } from "mnki-sdk/claude-agent-sdk";    // query({ hooks: { PreToolUse: [{ hooks: [preToolUse(guard)] }] } })
import { guardTools } from "mnki-sdk/ai";                  // generateText({ tools: guardTools(guard, { refund }) })
import { signTaskRequest, verifyBeforeAccept } from "mnki-sdk/a2a";   // agent-to-agent: sign outgoing tasks, verify incoming ones
```

```python
from mnki import AgentTrustClient, Guard
g = Guard(AgentTrustClient("https://mnki.com", api_key=os.environ["MNKI_API_KEY"]), agent="invoice-agent")

from mnki.adapters.openai_agents import guard_tools   # Agent(tools=guard_tools(g, [refund]))
from mnki.adapters.langchain import guard_tools       # create_react_agent(model, guard_tools(g, [refund]))
from langchain_mnki import guard_tools                # the same, as the `pip install langchain-mnki` partner package
from mnki.adapters.crewai import guard_tools          # Agent(tools=guard_tools(g, [refund_tool]))
from mnki.adapters.pydantic_ai import guard_tool      # @agent.tool_plain  @guard_tool(g)  def refund(...): ...
```

Local mode (no account) is the same call with a world instead of a client:
`createGuard({ world: demoWorld(), agent: "invoice-agent" })` / `Guard(world=demo_world(), agent="invoice-agent")`.

## API

```bash
curl https://mnki.com/api/v1/verify -H "Authorization: Bearer at_verify_…" -H "content-type: application/json" \
  -d '{"agent":"invoice-agent","action":"refund.create","resource":"customer:4711","amount":47000,"currency":"EUR"}'
```

The response carries `decision` (`ALLOW` / `DENY` / `REQUIRE_APPROVAL`), `reasons`, the evidence list and
the ledger event id; a `REQUIRE_APPROVAL` includes an `approval_id` to poll at `/v1/approvals/{id}/status`.
Policy engines that speak [AuthZEN](/docs/standards) call `/api/access/v1/evaluation` with the same key.
Full reference: [API](/docs/api) and the OpenAPI document at `/api/v1/openapi`.

## Offline verification

`mnki-verifier` (TypeScript) and `at-verify` (Go, `go/cmd/at-verify`) validate delegation chains, signed
decisions and attestations without contacting the console, against the organisation's published keys. They
pass the same [conformance vectors](/docs/conformance) as the hosted verifier, so a partner can check a
signed attestation from your agents in their own process.

## Where the packages live

| Channel | Name |
| --- | --- |
| npm | [`mnki-cli`](https://www.npmjs.com/package/mnki-cli) · [`mnki-sdk`](https://www.npmjs.com/package/mnki-sdk) · [`mnki-mcp`](https://www.npmjs.com/package/mnki-mcp) · [`mnki-verifier`](https://www.npmjs.com/package/mnki-verifier) |
| PyPI | [`mnki`](https://pypi.org/project/mnki/) |
| Container | `ghcr.io/mnkiagentos/mnki-mcp` (cosign-signed) |
| MCP Registry | `io.github.MNKIAgentOS/mnki-mcp` (also what the GitHub and VS Code galleries and PulseMCP index) |
| Claude Desktop extension | `mnki-mcp.mcpb` on every [GitHub release](https://github.com/MNKIAgentOS/agent-trust/releases) |
| Cursor, Smithery, Glama, mcp.so | listed from the repository (`.mcp.json`, `smithery.yaml`, `glama.json` at its root) |
| Source | [github.com/MNKIAgentOS/agent-trust](https://github.com/MNKIAgentOS/agent-trust) (Apache-2.0) |

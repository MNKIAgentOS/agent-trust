# Compatibility matrix

What mnki has been run against, at which version, and how much that claim is worth. Levels are deliberately
strict: **Verified** means a design partner runs it against real agents on staging and it is in CI;
**Compatible** means the integration is exercised by an automated test against the pinned version;
**Experimental** means the adapter exists, follows the framework's public tool contract, and is tested against
a stand-in of that contract only; **Unsupported** is documented so nobody wonders.

Every adapter is a thin wrapper over `guard.check(tool, args)`; the framework is never imported by the
package (type-only in TypeScript, lazy in Python), so an adapter loads without the framework installed.
Refusals are returned to the model as a structured result by default (`{ error, reasons, evidence }`) or
thrown (`onRefused: "throw"` / `on_refused="throw"`). Modes `observe → warn → require_approval → enforce`
apply everywhere.

## Frameworks

| Framework | Language | Pinned version | Entry point | Integration | Approval wait | Level |
| --- | --- | --- | --- | --- | --- | --- |
| OpenAI Agents SDK | TypeScript | `@openai/agents` 0.1.x | `mnki-sdk/openai-agents` → `guardTools(guard, tools)` | wraps `FunctionTool.invoke` | yes (guard waits, or `ask` result) | Experimental |
| OpenAI Agents SDK | Python | `openai-agents` 0.22.x | `mnki.adapters.openai_agents.guard_tools` | wraps `FunctionTool.on_invoke_tool` | yes | Compatible |
| LangChain / LangGraph | TypeScript | `@langchain/core` 0.3.x | `mnki-sdk/langchain` → `guardTools` | wraps `invoke` (args or ToolCall), prototype kept for `ToolNode` | yes | Experimental |
| LangChain / LangGraph | Python | `langchain-core` 1.6.x | `mnki.adapters.langchain.guard_tools` | `GuardedTool(BaseTool)` subclass, `_run`/`_arun` → `invoke` | yes | Compatible |
| Claude Agent SDK | TypeScript | `@anthropic-ai/claude-agent-sdk` 0.1.x | `mnki-sdk/claude-agent-sdk` → `preToolUse(guard)` | `PreToolUse` hook → `allow` / `deny` (evidence as reason) / `ask` | `ask` (human decides in the client) or guard waits | Experimental |
| Vercel AI SDK | TypeScript | `ai` 5.x | `mnki-sdk/ai` → `guardTools(guard, { … })` | wraps `execute`; client-side tools untouched | yes | Experimental |
| CrewAI | Python | `crewai` 0.80+ | `mnki.adapters.crewai.guard_tools` | `GuardedTool(BaseTool)` subclass, `_run` | yes | Experimental |
| Pydantic AI | Python | `pydantic-ai` 0.1+ | `mnki.adapters.pydantic_ai.guard_tool` | decorator on tool functions (sync/async, `RunContext` aware) | yes | Experimental |
| Plain functions | both | — | `guard.wrap(tool, fn)` / `@g.wrap("tool")` | — | yes | Verified |

## MCP clients (`mnki protect`)

| Client | Config | Formats | Level |
| --- | --- | --- | --- |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `%APPDATA%\Claude\…` (Windows) | `mcpServers` | Compatible |
| Claude Code | `~/.claude.json` (global and per-project `projects[dir].mcpServers`), `<project>/.mcp.json` | `mcpServers` | Compatible |
| Cursor | `~/.cursor/mcp.json`, `<project>/.cursor/mcp.json` | `mcpServers` | Compatible |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` | Compatible |
| VS Code | `<project>/.vscode/mcp.json` | `servers` (`type` kept) | Compatible |

## MCP servers (`mnki-mcp` proxy)

| Transport | Level | Notes |
| --- | --- | --- |
| stdio (spawned command) | Verified | staging run 16 Sep 2026: observe logs would-deny, enforce answers `-32003` with evidence, delegation flips a tool to ALLOW |
| Streamable HTTP (JSON and SSE answers, `mcp-session-id`) | Compatible | tested against a stand-in server; `DELETE` on close |
| Hosted gateway (`/api/gateway/mcp/<integration>`) | Verified | Streamable HTTP servers only |

## Brokered systems (access broker)

Providers the broker can hold a credential for and execute against on an agent's behalf. "Verified" means the
operation catalogue runs against a fake of the provider's documented API in the integration tests; live runs against
each provider are recorded here as they are done.

| Provider | Auth | Operations | Level |
| --- | --- | --- | --- |
| Stripe | restricted or secret key | refunds, charges, payment intents, customers, invoices, balance (probe) | Verified (fake API) |
| GitHub | OAuth app or token | issues, issue comments, pull list, repo, user (probe); owner allow-list | Verified (fake API) |
| Slack | OAuth app | `chat.postMessage`, `conversations.list`, `auth.test` (probe); `ok:false` envelopes fail the grant | Verified (fake API) |
| Google | OAuth app | Gmail send, Calendar event create, userinfo (probe) | Verified (fake API) |
| Microsoft 365 | OAuth app | Mail send, Calendar event create, `me` (probe) | Verified (fake API) |
| AWS | IAM access key pair | STS AssumeRole (native short-lived credential), SigV4-signed request to allow-listed services | Verified live, 20 Sep 2026 |
| Kubernetes | ServiceAccount bearer token | read pods and namespaces, logs, restart and scale deployments, delete a pod or namespace; namespace allow-list | Verified (fake API server) |
| Cloudflare | scoped API token | zones, DNS records, cache purge by URL or everything; zone-id allow-list; success read from the response envelope | Verified live, 20 Sep 2026 |
| Any HTTP API | API key in a header | operations declared per connection; public https only | Verified |

## Identity and standards

| Standard | Where | Level |
| --- | --- | --- |
| SPIFFE JWT-SVID as agent credential | `Agent-Credential` header, trust anchors per organisation | Verified |
| OIDC issuer tokens (Okta, Entra) | trust anchors, SSO | Verified |
| AuthZEN 1.0 evaluation | `/api/access/v1/evaluation` | Verified |
| MCP 2025-06 (tools/call) | proxy and gateway | Verified |
| A2A (agent card, `mnki-sdk/a2a` signTaskRequest / verifyBeforeAccept) | `/v1/agents/{id}/agent-card`, `/.well-known/agent-card.json` | Compatible (attestation verified offline against the caller organisation's JWKS; tested with two local organisations) |
| OpenID Federation entity configuration | `/.well-known/openid-federation` | Compatible |
| Attestation status, profile §12.1 | `/v1/orgs/{id}/status/attestation/{jti}` (public, no auth) | Verified |
| Single-use permits, profile §9.2 | `atp.use` on an attestation; consumed on the first `ALLOW` | Verified |
| Effect path declaration, profile §15 | `context.effect_path` on `/v1/verify`; gateway `custody`, A2A receiver `attested`, local proxy `none` | Verified |

## Runtimes

| Runtime | Level |
| --- | --- |
| Node 20, 22 (ESM) | Verified |
| Python 3.10 – 3.14 | Compatible (3.14 in CI) |
| Go 1.22+ (`at-verify`) | Verified |
| Bun / Deno | Unsupported (untested) |

Levels move up only when a real deployment is behind them. To get a framework to **Verified**, run it against
staging with real agents and tell us: [github.com/MNKIAgentOS/agent-trust/issues](https://github.com/MNKIAgentOS/agent-trust/issues).

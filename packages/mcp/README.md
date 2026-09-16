# mnki-mcp

`mnki-mcp` is a local MCP proxy: it sits between an MCP client (Claude Desktop, Claude Code, Cursor, Windsurf, VS Code) and
an MCP server — a stdio command or a Streamable HTTP endpoint — and verifies every `tools/call` against Agent Trust
before it reaches the server. Everything else is forwarded untouched.

Modes (`--mode`): `observe` (log only, always forward — the default), `warn` (forward, surface evidence), `require_approval`
(escalate only where policy says so, never hard-deny), `enforce` (deny with evidence, wait for human approval).

JSON-RPC errors the client sees in enforce mode: `-32003` denied (with the ✓/⚠/✕ evidence), `-32001` approval required /
rejected / expired, `-32005` verification quota exceeded, `-32006` Agent Trust unreachable (observe and warn forward instead).

Install it with `mnki protect` (dry run by default) or by hand — see `examples/`.

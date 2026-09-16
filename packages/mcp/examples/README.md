# Installing the proxy

Ready-made snippets: `claude-desktop.json`, `cursor.json`, `windsurf.json`, `vscode.json` (the `servers` format) and `docker-compose.yml` (sidecar in front of an HTTP server).

`mnki protect` rewrites the client's own config (dry run by default, `--apply` to write, `mnki protect rollback` to undo):

```bash
npx mnki-cli protect --client cursor --server github --agent my-agent            # shows the diff
npx mnki-cli protect --client cursor --server github --agent my-agent --apply    # observe mode
npx mnki-cli protect report --server github                                     # what would have been denied
npx mnki-cli protect --client cursor --server github --agent my-agent --mode enforce --apply
```

By hand, a stdio server entry becomes:

```json
{ "mcpServers": { "github": { "command": "npx", "args": ["-y", "mnki-mcp", "--agent", "my-agent", "--server", "github", "--mode", "observe", "--upstream", "--", "npx", "-y", "@modelcontextprotocol/server-github"], "env": { "GITHUB_TOKEN": "…" } } } }
```

and an HTTP server entry:

```json
{ "mcpServers": { "billing": { "command": "npx", "args": ["-y", "mnki-mcp", "--agent", "my-agent", "--server", "billing", "--upstream-url", "https://mcp.example/mcp", "--upstream-header", "Authorization=Bearer …"] } } }
```

`MNKI_URL` / `MNKI_API_KEY` (or `mnki init`) tell the proxy which console verifies; `MNKI_IDENTITY_FILE` points at the agent key for signed requests.
Docker: `docker run -i ghcr.io/mnkiagentos/mnki-mcp --agent my-agent --server billing --upstream-url https://mcp.example/mcp`.

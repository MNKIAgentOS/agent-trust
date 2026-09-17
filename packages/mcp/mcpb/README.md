# Claude Desktop extension (`mnki-mcp.mcpb`)

`manifest.json` describes the extension; the bundle itself is built by the release workflow (`mcpb` job in the
public repository): it installs the published `mnki-mcp` package into a scratch directory next to this
manifest and packs it with `@anthropic-ai/mcpb`. The result is attached to every GitHub release.

Build one by hand for a local check:

```bash
mkdir bundle && cp packages/mcp/mcpb/manifest.json packages/mcp/mcpb/icon.png bundle/ && cd bundle
printf '{ "name": "mnki-mcp-extension", "version": "0.0.0", "private": true }\n' > package.json
npm install --omit=dev mnki-mcp@latest && npx @anthropic-ai/mcpb pack . ../mnki-mcp.mcpb
```

Double-clicking the file opens Claude Desktop's install dialog: the upstream server command, agent id,
mode, console URL and API key are asked once and the key goes to the OS keychain.

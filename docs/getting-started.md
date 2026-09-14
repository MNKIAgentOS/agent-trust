# Agent Trust in five minutes

```bash
# 1. Point the CLI at your console and key (Settings → API keys, scope: verify or write)
npm run agenttrust -- init --url https://staging.mnki.com --key at_write_…

# 2. See what already exists on this machine
npm run agenttrust -- scan            # MCP servers, API keys, Kubernetes / AWS / GitHub identities

# 3. Give an agent an identity (key pair stays local; public half is registered)
npm run agenttrust -- identity create --name procurement-bot --risk low

# 4. Delegate authority to it from a human principal, with limits
npm run agenttrust -- delegate --issuer principal:<prn_id> --to <agent id> \
  --cap "purchase.create=supplier:*;max_value=5000;currency=EUR;region=EU" --expires 24h

# 5. Ask for a decision, signed with the agent's key
npm run agenttrust -- verify --agent <agent id> --action purchase.create --resource supplier:4711 \
  --amount 3200 --currency EUR --region EU --sign
#   Decision: REQUIRE_APPROVAL … followed by the ✓/⚠/✕ evidence list

# 6. Put an MCP server behind the gateway
npm run agenttrust -- protect --mcp <integration id> --agent <agent id>
```

Every step lands in **Audit & Provenance** as a hash-chained, signed envelope. From here: obtain an
authorization attestation (`agenttrust attest <decision id>`), present it to other services, or federate
with another organization (Settings → Trust domains).

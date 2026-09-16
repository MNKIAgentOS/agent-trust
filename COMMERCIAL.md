# Open source and commercial: where the line is

Agent Trust is built as an open protocol with an open reference implementation, and a commercial control
plane that operates it for organisations. The line is drawn by *what runs where*, not by feature flags.

## Open source (Apache-2.0, this repository)

Everything a developer needs to give an agent an identity, verify its authority and prove what it did,
usable without an account and without the control plane:

- the **Agent Trust Profile** and Internet-Draft (`spec/`), and the **conformance vectors** that certify
  any implementation (`conformance/`, levels 1–3);
- the **reference verifier** in TypeScript (`packages/verifier`) and Go (`go/verifier`), and `at-verify`,
  a self-hosted verifier that serves decisions from an exported snapshot;
- the **SDKs** — `mnki-sdk` (TypeScript) and `mnki` (Python) — including `guard()` / `wrap()`, local
  mode, identity handling, offline verification of credentials and attestations, and the framework adapters;
- the **CLI** `mnki-cli`, installed as the `mnki` command (`demo`, `init`, `scan`, `protect`, `verify`, `policy`, `conformance`, …);
- the **local MCP proxy** `mnki-mcp`, which verifies every `tools/call` on the developer's machine.

These are not "source available" and not a trial: the licence is Apache-2.0 for any use, including in
competing products, and the packages work in local mode with no service behind them.

## Commercial (hosted by MNKI, or self-hosted under licence)

The control plane is where an organisation governs many agents, many people and many environments:

| Capability | Free (Cloud) | Cloud (Individual / Team) | Enterprise / Self-hosted |
| --- | --- | --- | --- |
| Agent identities and public passports | unlimited | unlimited | unlimited |
| Hosted verification with evidence | 10,000 / month | plan volume + overage | unmetered |
| Tamper-evident ledger and export | 90 days | 180–365 days | 10 years, archive to your bucket |
| Human approvals (web + phone, device-signed) | ✓ | ✓ | ✓ |
| Central policies, simulation, rollback | basic | ✓ | ✓ |
| Delegation chains, revocation, trust graph | ✓ | ✓ | ✓ |
| Notifications, SIEM/webhook forwarding | — | ✓ | ✓ |
| Identity-provider sync, trust domains | — | ✓ | ✓ |
| SSO + SCIM | — | add-on | ✓ |
| Federation between organisations, runtime attestation | — | — | ✓ |
| Self-hosted image (Postgres/Redis/S3), licence, support SLA | — | — | ✓ |

The hosted MCP gateway, the console, the admin portal, billing, SSO/SCIM, federation, runtime attestation
analytics and the self-hosted control-plane image are proprietary and are not in this repository.

## What will not change

- The wire contract between the open packages and the control plane is the public `/v1` API and the
  profile; both are versioned and documented, so a self-hosted verifier or a third-party control plane can
  speak the same objects.
- Conformance is open: anyone can run the vectors and claim a level (see `TRADEMARK.md` for the badge rules).
- We will not move a capability from the open packages into the control plane in a later release.
  New capabilities are placed by the rule above: on the agent's side it is open; fleet-wide governance
  is commercial.

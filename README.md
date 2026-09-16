# Agent Trust

**Prove what an autonomous AI agent is authorized to do.** An open profile plus a reference
implementation for agent identity, principal binding, delegation with attenuation,
capability-based authorization, request proof-of-possession, authorization attestations,
tamper-evident provenance and revocation — carried on JWS, OAuth/OIDC, SPIFFE/WIMSE, AuthZEN,
OpenID Federation, MCP and A2A. No new cryptography, no new protocol.

> No consequential agent action should be accepted because a process is running or a token is
> valid. It should be accepted because the action is attributable, authorized, constrained,
> current and verifiable.

| Package | What it is |
|---|---|
| [`packages/verifier`](packages/verifier) | The pure core: parsing, delegation chain + attenuation, policy engine, request proof, delegation credentials, attestations, the 12-step evidence pipeline. Deterministic, dependency-free, WebCrypto only. |
| [`packages/sdk-ts`](packages/sdk-ts) | `mnki-sdk` — TypeScript SDK: agent identity (keys, signed requests), `guard()` for any tool call, verify, delegate, attest, offline verification against an organization's JWKS; framework adapters as subpaths. |
| [`packages/cli`](packages/cli) | `mnki-cli` — `mnki demo · init · identity · verify · inspect · delegate · attest · scan · protect · conformance` (`agenttrust` is an alias). |
| [`packages/mcp`](packages/mcp) | `mnki-mcp` — a local MCP proxy that verifies every `tools/call` before it reaches the server (`mnki protect` installs it). |
| [`python/`](python) | `pip install mnki` — Python SDK (zero dependencies; `mnki[signing]` for Agent-Proof). |
| [`go/`](go) | Go verifier (same vectors, no dependencies) and **`at-verify`**, the self-hosted verifier that serves `/v1/verify` from an exported organization snapshot. |
| [`spec/`](spec) | **Agent Trust Profile v0.1**, the interoperability positioning, the Internet-Draft (`draft-mnki-agent-trust-profile-00`) and the standards plan. |
| [`conformance/`](conformance) | Executable vectors for **certification levels 1–3** (`LEVELS.md`) — the cross-language contract; TypeScript and Go runners pass them all. |

```bash
npx mnki-cli demo      # the 15-second story, no account: a €47,000 refund denied, €420 allowed
npx mnki-cli scan      # find the MCP servers and API keys agents can use on this machine
npm install mnki-sdk   # guard() any tool call
pip install mnki               # same in Python
```

Develop against the open verifier and SDKs for free; govern fleets with the hosted control plane at
[mnki.com](https://mnki.com) — see [COMMERCIAL.md](COMMERCIAL.md) for the boundary and
[TRADEMARK.md](TRADEMARK.md) for name and badge use. Releases carry npm/PyPI provenance, SBOMs and
cosign-signed checksums ([SECURITY.md](SECURITY.md)).

Apache-2.0.

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
| [`packages/sdk-ts`](packages/sdk-ts) | TypeScript SDK: agent identity (keys, signed requests), verify, delegate, attest, offline verification against an organization's JWKS. |
| [`packages/cli`](packages/cli) | `agenttrust init · identity · verify · inspect · delegate · attest · scan · protect`. |
| [`python/`](python) | Python SDK (zero dependencies; `cryptography` for Agent-Proof signing). |
| [`spec/`](spec) | **Agent Trust Profile v0.1** and the interoperability positioning. |
| [`conformance/`](conformance) | Executable vectors — the cross-language contract (a Go core follows). |

```bash
npm install
npm test                       # verifier + sdk + cli suites, property tests, conformance vectors
npm run agenttrust -- scan     # find the MCP servers and API keys agents can use on this machine
```

Managed console, gateway hosting, trust graph and federation: [mnki.com](https://mnki.com).

Apache-2.0.

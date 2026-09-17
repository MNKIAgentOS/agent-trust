# Agent Trust Profile

An interoperability **profile** — not a new protocol — for proving what an autonomous
AI agent is authorized to do. It defines *semantics* (identity, principal binding,
delegation, attenuation, capabilities, constraints, authorization, attestation,
provenance, revocation, trust domains) and carries them on existing standards:
JWS/JWT, OAuth/OIDC, SPIFFE/WIMSE, OpenID AuthZEN, OpenID Federation, MCP and A2A.

| Document | What it fixes |
|---|---|
| [agent-trust-profile-v0.1.md](./agent-trust-profile-v0.1.md) | The normative profile: objects, claims, reason codes, verification algorithm |
| [interoperability.md](./interoperability.md) | How the profile maps onto AuthZEN, WIMSE/SPIFFE, OpenID Federation, MCP, A2A, NVIDIA AIP, Microsoft Entra Agent ID |
| [../conformance/](../conformance/) | Executable vectors every implementation must pass |

North-star invariant (from the mnki whitepaper): *no consequential agent action is accepted
because a process is running or a token is valid — it is accepted because the action is
attributable, authorized, constrained, current and verifiable.*

Status: **v0.1, experimental.** The reference implementation is `packages/verifier`
(TypeScript, Apache-2.0). Breaking changes are expected until v0.5; the conformance
vectors are the compatibility contract.

**Internet-Draft:** `draft-mnki-agent-trust-profile-00` is posted and active (individual submission,
Informational, 16 Sep 2026): <https://datatracker.ietf.org/doc/draft-mnki-agent-trust-profile/>. `-00` is
frozen; changes go to `-01` (see STANDARDS.md).

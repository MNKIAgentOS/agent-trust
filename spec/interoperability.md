# Interoperability positioning

The profile adds the **semantic layer** — who the agent is, whom it represents, what authority was delegated, what it may do right now, and proof of all of that — on top of infrastructure that already exists. It deliberately replaces nothing.

| Layer / project | Relationship | Concretely |
|---|---|---|
| **OAuth 2.x / OIDC** | Build on | Access tokens keep authenticating the client; the profile answers the questions a bearer token cannot (principal, delegation, constraints). OIDC issuers are trust anchors for principals. |
| **DPoP (RFC 9449)** | Same pattern | `Agent-Proof` is a DPoP-style detached JWS bound to method, URL and body hash, signed with the agent's registered key. |
| **SPIFFE / SPIRE / WIMSE** | Build on | Agent identifiers may be SPIFFE IDs; JWT-SVID / X.509-SVID are credential kinds; SPIFFE trust domains are trust anchors; workload attestation feeds the `attestation` evidence row. |
| **OpenID AuthZEN** | Build on | The policy engine is PDP-shaped: `subject` (agent + principal), `action`, `resource`, `context` (amount, currency, region, risk tier, attestations, delegation depth). An AuthZEN evaluation endpoint maps 1:1 onto `verify()` — planned as `/access/v1/evaluation`. |
| **OpenID Federation 1.0** | Build on (planned) | Organization keys are already published as JWKS; entity statements and trust-chain resolution to anchors are the federation layer for cross-organization verification. |
| **MCP** | Integrate | MCP's OAuth answers "may this client reach this server"; the Agent Trust gateway adds "which agent, for whom, under what delegated authority" per `tools/call`, with JSON-RPC `-32001` (approval) and `-32003` (denied) as the enforcement surface. |
| **A2A** | Integrate | Agent Cards describe capabilities and auth requirements; the profile supplies identity, principal, delegation credential and attestation endpoints an Agent Card can advertise. |
| **NVIDIA AIP** | Interoperate | AIP covers agent identity, keys, registry and signed outbound actions. The profile's identity and proof objects are compatible in shape; delegation, attenuation, attestation, provenance and federation extend it rather than compete. |
| **Microsoft Entra Agent ID, Okta, cloud IAM** | Federate, never compete | Identity providers issue the agent's credential; the profile is provider-neutral and consumes them as trust anchors. |
| **CloudEvents 1.0 + JCS (RFC 8785)** | Reuse | The provenance envelope shape and its canonical hashing. |

What is deliberately **not** standardized here: new cryptography, new transports, agent messaging, discovery, marketplaces, payments, reputation scores.

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
| **OAuth 2.0 Token Exchange (RFC 8693), AWS STS** | Build on (§17) | Where a provider can mint a short-lived, down-scoped credential, a grant is exchanged for one whose lifetime is bounded by the grant; where it cannot, the broker executes the operation itself (custody, §15). |

What is deliberately **not** standardized here: new cryptography, new transports, agent messaging, discovery, marketplaces, payments, reputation scores.

## Cross-organisation verification over A2A

MCP connects agents to tools; A2A connects agents to agents. The profile does not define agent messaging — it
supplies what an A2A exchange between two organisations needs to be trustworthy: who the caller is, whom it
represents, what it was authorised to do right now, and a proof of that which the receiver can check without
calling the caller's control plane.

**Caller (organisation A).** Before sending a task the caller's agent verifies the action with its own control
plane (`POST /v1/verify`, action `a2a:<skill>`). An `ALLOW` — or an approval, once granted — can be turned into an
**authorization attestation** (`POST /v1/attestations { decision_id }`): a short-lived JWS signed by A's
organisation key (`typ: agent-trust-attestation+jwt`, claims: subject agent, action, resource, principal,
effective capabilities, delegation chain ids, human approval). The A2A request carries:

| Header | Content |
| --- | --- |
| `Agent-Proof` | DPoP-style detached JWS by the agent's own key over method, URL and body hash |
| `Agent-Attestation` | the attestation above |
| `Agent-Id`, `Agent-Card` | the agent id and the URL of its Agent Card (`/.well-known/agent-card.json?agent=<public id>` or the organisation-scoped `/v1/agents/{id}/agent-card`) |

`mnki-sdk/a2a` → `signTaskRequest(identity, { url, body, attestation, cardUrl })` produces exactly these.

**Receiver (organisation B).** `verifyBeforeAccept(guard, task)`:

1. resolves the caller's Agent Card and reads the `https://mnki.com/agent-trust/profile/v0.1` extension
   (`agent_id`, `stable_id`, `public_id`, `organization`, `jwks_url`, `passport_url`, `delegation_credential_url`);
2. verifies `Agent-Attestation` **offline** against `jwks_url` (A's published organisation keys): signature,
   `typ`, expiry, issuer = the card's organisation, subject = the card's agent, `atp.action` = `a2a:<skill>`;
3. when the card advertises a public passport, checks the caller's **standing** (`registered | verified |
   attested | revoked`) — a revoked or suspended caller is refused;
4. runs B's **own guard** for the receiving agent (`a2a:<skill>`, the task parameters, and the caller's identity
   in `context.a2a`) — B's delegations and policy decide whether B's agent may perform the skill for this caller;
5. returns the **trust metadata** (caller identity, attestation claims, standing, B's decision) without any of
   A's private evidence, and `refusalToJsonRpc()` maps a refusal onto the same JSON-RPC codes the MCP surface
   uses (`-32003` denied, `-32001` approval, `-32006` unreachable).

Both organisations record their side: A's ledger holds the decision and the issued attestation; B's ledger holds
the decision to accept, with the attestation `jti` in its context. Nothing crosses the boundary except signed,
short-lived objects and public keys. Federation trust levels (peer organisations whose attested agents may act
*as if local*, level 2) build on the same attestation; the receiver above treats the caller as foreign and
decides with its own authority model, which is the safe default between organisations that have not federated.
From profile v0.2 (§12.1) both receivers ask A's public attestation status endpoint about the `jti` before the
first acceptance, so a revocation at A lands at B within a minute instead of at expiry.

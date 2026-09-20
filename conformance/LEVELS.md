# Agent Trust conformance levels

Certification is earned by reproducing fixtures, not by a review. Each level is a directory of vectors
and a runner (`packages/verifier` for TypeScript, `go/verifier` for Go); `agenttrust conformance --level N`
runs them and prints the report.

| Level | Name | What it proves | Vectors |
|---|---|---|---|
| **1** | Verifier | The decision pipeline: identity, credential, principal, delegation + attenuation, capability + constraints, revocation, attestation evidence, effect path (v0.2 `enforcement` step from `context.effect_path`), policy precedence — same decision, reasons and per-step evidence for every vector. | `conformance/vectors/V*.json` |
| **2** | Credentials | Signed objects: delegation credential chains (signature, `typ`, expiry, `parent_hash` commitment, depth, issuer = parent subject, child ⊆ parent), request proofs (ES256/EdDSA, `htm`/`htu`/`rh`/`exp`), authorization attestations (signature, `typ`, expiry, claims). | `conformance/crypto/L2-*.json` |
| **3** | Federation and permits | Federated agents: an attestation from a peer organization (trust level 2) stands in for identity, credential, principal and delegation; local policy and constraints still apply; level-1 peers and unknown peers are refused. Profile v0.2: single-use attestations (`use: single`) are consumed on the first ALLOW, refused on replay, bound to the request hash, refused without a consumption store, and an approved permit satisfies the policy's approval requirement once (vectors marked v0.2). | `conformance/crypto/L3-*.json` |

Vector format (levels 2–3): `{ id, level, title, now, keys: { <issuer>: { <kid>: JWK } }, case | world+request, expect }`.
`case.kind` is `delegation_chain` (`tokens[]`), `request_proof` (`proof`, `agent_keys`, `htm`, `htu`, `body_hash`)
or `attestation` (`token`, optional `expect.use`); level-3 vectors reuse the level-1 world shape plus `peers[]` and `request.attestation`. v0.2 vectors may add `world.consumed[]` (jtis already spent; its presence means the runner offers a consumption store) and a top-level `request_hash` passed to the verifier as the hash of the request being executed. v0.3 vectors may add a top-level `audience` (the relying party's own identifier, §17) and level-1 worlds may hold several delegations for one agent, which a runner resolves with a covering-delegation lookup (V18, V19).

An implementation may claim a level only when every vector of that level and all lower levels pass.
Vectors never change semantics without a version bump; a new behaviour always ships with a vector.

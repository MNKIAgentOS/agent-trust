# Agent Trust conformance levels

Certification is earned by reproducing fixtures, not by a review. Each level is a directory of vectors
and a runner (`packages/verifier` for TypeScript, `go/verifier` for Go); `agenttrust conformance --level N`
runs them and prints the report.

| Level | Name | What it proves | Vectors |
|---|---|---|---|
| **1** | Verifier | The decision pipeline: identity, credential, principal, delegation + attenuation, capability + constraints, revocation, attestation evidence, policy precedence — same decision, reasons and per-step evidence for every vector. | `conformance/vectors/V*.json` |
| **2** | Credentials | Signed objects: delegation credential chains (signature, `typ`, expiry, `parent_hash` commitment, depth, issuer = parent subject, child ⊆ parent), request proofs (ES256/EdDSA, `htm`/`htu`/`rh`/`exp`), authorization attestations (signature, `typ`, expiry, claims). | `conformance/crypto/L2-*.json` |
| **3** | Federation | Federated agents: an attestation from a peer organization (trust level 2) stands in for identity, credential, principal and delegation; local policy and constraints still apply; level-1 peers and unknown peers are refused. | `conformance/crypto/L3-*.json` |

Vector format (levels 2–3): `{ id, level, title, now, keys: { <issuer>: { <kid>: JWK } }, case | world+request, expect }`.
`case.kind` is `delegation_chain` (`tokens[]`), `request_proof` (`proof`, `agent_keys`, `htm`, `htu`, `body_hash`)
or `attestation` (`token`); level-3 vectors reuse the level-1 world shape plus `peers[]` and `request.attestation`.

An implementation may claim a level only when every vector of that level and all lower levels pass.
Vectors never change semantics without a version bump; a new behaviour always ships with a vector.

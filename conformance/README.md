# Agent Trust conformance vectors

Language-neutral fixtures for the verification pipeline. Every implementation
(the TypeScript reference in `packages/verifier`, the Go core that follows)
must produce the expected decision, reasons and evidence statuses for each
vector. The vectors *are* the protocol profile's executable specification.

## Format (`vectors/*.json`)

```json
{
  "id": "V01", "title": "…",
  "now": "2026-09-14T12:00:00Z",
  "world": {
    "agent":       { "id", "stable_id", "lifecycle", "risk_tier", "owner_principal_id", "labels" } | null,
    "credential":  { "id", "kind", "status", "not_after" } | null,
    "principals":  [ { "id", "display_name", "kind" } ],
    "delegations": [ Delegation ],            // leaf = the delegation whose subject is the agent (parent_id !== null preferred)
    "capabilities": [ Capability ],           // direct capabilities, used only when no delegation exists
    "revoked":     [ "id", … ],
    "attestations": [ { "id", "kind", "verified", "expires_at" } ],
    "policy":      { "version_id", "hash", "doc": PolicyDoc } | null
  },
  "request": VerifyRequest,
  "expect": {
    "decision": "ALLOW" | "DENY" | "REQUIRE_APPROVAL",
    "reasons_include": [ "…" ],
    "reasons_exact":   [ "…" ],               // optional
    "evidence":        { "<step>": "pass|warn|fail|skipped" }   // subset
  }
}
```

Invariants every implementation must also satisfy (property-tested in the
reference): `attenuate(parent, child) ⊆ parent`; a chain never widens the root's
authority; an expired or revoked link anywhere yields no authority; `verify()`
is deterministic for a fixed `now`.

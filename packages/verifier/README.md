# mnki-verifier

The pure core of Agent Trust, Apache-2.0. Everything here is a deterministic
function of its inputs — no Cloudflare bindings, no framework, no network,
no clock other than the one you pass in.

```ts
import { verify, parseVerifyRequest } from "mnki-verifier";

const parsed = parseVerifyRequest(untrustedJson);          // never throws
if (parsed.ok) {
  const result = await verify(parsed.request, deps, { now: new Date() });
  // result.decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL"
  // result.reasons:  machine-readable codes, e.g. "constraint_violated"
  // result.evidence: one row per check — identity, credential, principal,
  //                  delegation, capability, constraints, revocation,
  //                  attestation, policy — each pass | warn | fail | skipped
}
```

`deps` is a `VerifierDeps` — nine async getters you implement over your own
storage (the console uses D1; the tests use maps built from JSON vectors).

## What is guaranteed

- **Delegation only narrows.** `attenuate(parent, child) ⊆ parent`, a chain never
  widens the root's authority, an expired or revoked link anywhere ⇒ no authority.
  Property-tested with fast-check.
- **Policy is deterministic.** Same document + input + clock ⇒ same outcome.
  Precedence: deny › require_approval › allow.
- **Evidence over scores.** The decision is derived from the evidence rows;
  there is no numeric trust score anywhere in this package.
- **Conformance.** `conformance/vectors/*.json` (repo root) are the executable
  specification; `tests/conformance.test.ts` runs every vector. A second
  implementation is conformant when it passes the same files.

## Layout

```
src/types.ts                 Capability · Delegation · VerifyRequest · Decision
src/parse.ts                 parseVerifyRequest — validate untrusted input
src/delegation/attenuate.ts  resourceContains · constraintsTighter · isSubset · attenuate
src/delegation/chain.ts      resolveChain · linkValidAt · computeEffectiveAuthority
src/policy/schema.ts         PolicyDoc · parsePolicyDoc
src/policy/evaluate.ts       evaluate · simulate
src/pipeline.ts              verify(req, deps, { now }) · VerifierDeps
```

Boundary: this package must never import `next`, `@opennextjs/*`, `@/*` or
`@cloudflare/*` (enforced by ESLint). It is extracted to the public
`MNKIAgentOS/agent-trust` repository once the protocol profile freezes.

# Proposal: effect paths, single-use attestations, peer revocation (profile v0.2)

Status: **implemented 19 Sep 2026** (commits `f2afbe1` single-use, `ff4ab1b` peer revocation, `89e70ee` effect paths); the normative text now lives in `spec/agent-trust-profile-v0.2.md` §9.2, §12.1, §13.1 and §15, the vectors in `conformance/`. Kept as the design record. Originally: proposal, 19 Sep 2026. Three gaps in Agent Trust Profile v0.1 raised against a competing profile. Each
section states what v0.1 says today (with the code that implements it), the normative text proposed, and the
implementation it needs across the TypeScript verifier, the Go core, the conformance vectors and the product.
Nothing here changes semantics until a vector ships with it (§14).

## Gap 1: direct-effect paths

**Today.** The profile never says that an effect requires a decision. Enforcement is a deployment fact:
the hosted MCP gateway holds the upstream credential (`getAccessToken(env, orgId, "int:<id>")` in
`src/lib/gateway/mcp.ts`), so a server reached only through the gateway cannot be called with authority the
gateway did not grant. The local proxy (`mnki protect`) rewrites the client's config, but the agent process
and the server share a machine and nothing stops a direct call. The A2A receiver (`verifyBeforeAccept`,
`spec/interoperability.md`) is the one place where the *effector itself* demands an attestation. None of this
is stated, and none of it appears in the evidence list.

**Proposed §15, Enforcement points and effect paths.**

> An *effect* is a state change outside the agent (a tool call executed, a message sent, money moved). An
> *enforcement point* (EP) is the component that obtains a decision for a request before its effect. An
> implementation conforms to `NO_DIRECT_EFFECT_PATH` when every effect an agent can cause is produced by an
> *effector* that can establish, for that request, an `ALLOW` decision or a `REQUIRE_APPROVAL` decision whose
> approval was granted. Two ways to establish it are defined:
>
> - **Custody.** The effector accepts requests only from the EP, because the credential that produces the
>   effect is held by the EP and never by the agent. Provenance MUST record the `decision_id` on every effect.
> - **Attested.** The effector is a relying party (§9) and executes a request only with an Authorization
>   Attestation whose `aud` names the effector, whose `atp.request_hash` equals the hash of the request being
>   executed, and (for single-use attestations, §9.2) whose `jti` it has not consumed before.
>
> A verification request MAY declare its effect path in `context.effect_path ∈ { "custody", "attested", "none" }`.
> Verifiers MUST emit evidence step `enforcement`: `pass` for `custody` or `attested`, `warn` for `none` or
> absent ("a direct path to the effector may exist; this decision relies on deployment isolation").

**Why this shape.** It keeps the profile free of transport assumptions, makes the deployment fact visible on
every decision (evidence over scores), and gives buyers a testable claim: "our effectors are custody or attested,
and the ledger shows it". The A2A receiver is already `attested`; the hosted gateway is `custody`; the local
proxy is honestly `none` until the server credential moves into the proxy's own store.

**Implementation.** Verifier: read `context.effect_path`, add evidence codes `enforcement.custody`,
`enforcement.attested`, `enforcement.none` (TS `packages/verifier/src/pipeline.ts`, Go `go/verifier/pipeline.go`,
`evidence-codes.ts` + Spanish strings). Gateway and A2A receiver set the context themselves; the local proxy sets
`none` and `mnki protect` gains `--credential-custody` (moves the server's env/token into the proxy wrapper and
removes it from the client entry) which flips it to `custody`. Attestation issuance: `aud` becomes required
when `opts.audience` is an effector (`src/lib/data/attestations.ts`). Vectors: two L1 vectors (custody pass,
none warn). Effort: about a day.

## Gap 2: one-shot permits

**Today.** An approval request is resolved once (`approval_requests.status`), but the attestation issued from
it (`issueAuthorizationAttestation`, 600 s default, 3600 s max) is a bearer object that every relying party
accepts until `exp`. §9 says relying parties "SHOULD check revocation by `jti`"; nothing marks a `jti` as
used. The verifier already has the right primitive for request proofs (`seenJti(jti, exp)` in `VerifierDeps`)
but not for attestations. Federated agents make it worse: their request proof is skipped
(`pipeline.ts`, "Request proof not checked for federated agents"), so a captured attestation is enough to act
as that agent at the receiver until it expires. The €47,000 refund can be replayed as a second €47,000 refund
with the same body.

**Proposed §9.2, Single-use attestations.**

> `atp.use ∈ { "single", "multi" }`, default `multi` (v0.1 compatibility). Issuers MUST set `single` on any
> attestation derived from a `REQUIRE_APPROVAL` decision, and SHOULD set it whenever `atp.request_hash` is
> present. A relying party that accepts a `single` attestation MUST atomically record its `jti` as consumed
> before producing the effect and MUST refuse any later presentation with `attestation_invalid:consumed`. The
> consumed set is kept until `exp`. For `single` attestations `atp.request_hash` MUST equal the hash of the
> request being executed (`attestation_invalid:request_hash` otherwise).

**Implementation.** Verifier deps: `consumeAttestation?(jti, exp): Promise<"first" | "seen">` (TS and Go),
called after signature/subject/action/resource checks and before `attestation_valid`; evidence codes
`attestation_token.consumed` (fail) and `attestation_token.single_use` (pass, with the `jti`). Storage:
`authorization_attestations.consumed_at, consumed_by_type, consumed_by_id` for attestations we issued;
for peer attestations a `consumed_attestations (org_id, jti, exp)` table (or KV with TTL) at the receiver.
Issuance: `use: "single"` whenever `human_approval` is set or `request_hash` is present. Product: the
attestation row shows *Used* and the ledger gets `attestation.consumed`; the A2A receiver and the gateway
(when a client presents `Agent-Attestation`) consume. Vectors: L2 (claims: `use`), L1 (second presentation
denied), L3 (federated replay denied). Effort: one to two days, mostly the atomic claim on D1 and Postgres.

## Gap 3: cross-organisation revocation

**Today.** For a federated agent the pipeline emits a warning it names itself: `revocation.peer_unchecked`,
"Peer revocation not consulted", and §13 declares cross-organisation trust out of scope. The federation record
(`federated_orgs`) holds a `jwks_url` only. Our own status endpoint (`/api/v1/status/{subject}`) answers for
agents, credentials, delegations, API keys and policy versions but not for attestation `jti`s, so a peer could
not ask us either. Revoking an attestation at the issuer (`revokeAttestation`) therefore has no effect at any
receiver.

**Proposed §12.1 and §13.1, Peer status.**

> An organisation that issues attestations for federated use MUST publish a status endpoint
> `GET {status_url}/attestation/{jti}` answering `{ status: "active" | "revoked" | "unknown", ttl_hint }` from
> one indexed lookup, and MUST advertise it as `status_url` in its entity configuration and Agent Card
> extension. A receiver that accepts a peer attestation at trust level 2 MUST consult the peer's status for the
> `jti` before the first acceptance, MAY cache the answer for `min(ttl_hint, 60 s)`, and on `revoked` MUST
> refuse with `revoked`. When the peer is unreachable the receiver MUST refuse unless the federation record
> allows a stale window (`stale_ok_seconds`) and the attestation was issued within it; the evidence row says
> which. Signed revocation lists (`.../revocations?since=`) are a compatible optimisation, not a substitute.

**Implementation.** Verifier deps: `peerAttestationStatus?(iss, jti): Promise<"active" | "revoked" | "unreachable">`;
evidence codes `revocation.peer_none` (pass), `revocation.peer_revoked` (fail), `revocation.peer_unreachable`
(fail, or warn inside the stale window), replacing `revocation.peer_unchecked`. Federation: migration adds
`federated_orgs.status_url` and `stale_ok_seconds`; the entity-configuration fetch reads `status_url`; the
Agent Card extension already carries `status_url`. Our status route learns `aat_*` subjects. Vectors: three L3
(active, revoked, unreachable with and without stale window). Effort: about two days including the Go core.

## Order and compatibility

Gap 2 first (it is the exploitable one, and its `use` claim defaults to `multi` so v0.1 tokens keep verifying),
then gap 3 (needs the status route on both sides before receivers can require it), then gap 1 (text plus
evidence, no wire change). Profile version becomes v0.2 with the vectors; v0.1 vectors keep passing.

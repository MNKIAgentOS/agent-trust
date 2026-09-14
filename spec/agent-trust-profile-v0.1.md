# Agent Trust Profile v0.1

Status: experimental · Licence: Apache-2.0 · Reference: `packages/verifier` · Vectors: `conformance/vectors`

The key words MUST, SHOULD and MAY are to be interpreted as in RFC 2119.

## 1. Scope

This profile standardizes the **semantics of agent authority** and how they are carried on
standard cryptography. It does not define new encryption, transport, token formats or
authentication protocols. Every wire object is a compact JWS (RFC 7515) with a `typ`
header naming the profile object; signatures are ES256 (ECDSA P-256 / SHA-256) or
EdDSA (Ed25519). Implementations MUST reject any other `alg`.

## 2. Model

```
Organization ─ operates ─▶ Agent ─ represents ─▶ Principal
                            │
                            ├─ holds ─▶ Credential (key, kid, validity)
                            ├─ receives ─▶ Delegation chain (root issued by a principal) ─ grants ─▶ effective Capabilities
                            ├─ presents ─▶ Request proof · Authorization attestation
                            └─ produces ─▶ Actions ─ recorded as ─▶ Provenance envelopes (hash-chained)
```

| Term | Definition |
|---|---|
| **Agent** | A cryptographically identifiable software actor with a stable identifier, a lifecycle and a set of credentials. |
| **Principal** | The human, service or organization the agent acts *for*. Always represented separately from the agent. |
| **Organization** | The trust domain that operates the agent and signs its delegations and attestations. |
| **Capability** | `{ action, resource, constraints? }` — a machine-evaluable unit of authority. |
| **Delegation** | A grant of capabilities from an issuer (a principal at the root, otherwise the parent's subject agent) to a subject agent, with validity and status. |
| **Effective authority** | What survives the whole chain: the intersection, never the union. |
| **Decision** | `ALLOW`, `DENY` or `REQUIRE_APPROVAL`, derived from evidence rows, never from a score. |
| **Evidence** | `{ step, status: pass|warn|fail|skipped, title, detail?, refs? }`, one row per check. |

## 3. Identity

3.1 An agent identifier MUST be a URI-safe string that is stable, non-secret and unique within its organization. SPIFFE IDs (`spiffe://trust-domain/path`), `agent-trust://<org>/agent/<name>-<suffix>`, DIDs and OIDC subjects are all acceptable; the profile does not mandate a scheme.

3.2 Lifecycle states: `pending → active → suspended → revoked → retired`. Only `active` agents may be authorized; every other state yields reason `agent_<state>`.

3.3 Credentials bind a public key to the agent: `kind ∈ {jwt, jwt_svid, x509_svid, api_key, oidc}`, `kid`, `public_key_jwk` (JWK), `not_before`, `not_after`, `issuer`, `status ∈ {active, rotated, revoked}`. Rotation MAY overlap validity windows. An expired credential yields `credential_expired`; a missing one `credential_missing`.

3.4 **Trusted issuers.** An organization MAY restrict credential issuers to configured trust anchors (OIDC issuer URLs and SPIFFE trust domains). Matching is exact for issuer URLs and host-suffix for trust domains (`internal-ca.acme.corp` ⊂ `spiffe://acme.corp`). A credential outside every anchor yields `credential_issuer_untrusted`. Ownership of a trust domain SHOULD be proven with a DNS TXT record at `_agent-trust.<host>` containing an organization challenge.

## 4. Principal binding

An agent SHOULD have an `owner_principal_id`. Verification reports it as a distinct evidence row (`principal`); an agent without one is still verifiable but carries the warning `principal_unbound`. Relying parties MUST NOT conflate the agent with its principal.

## 5. Capabilities and constraints

5.1 `action` is an exact string (`purchase.create`, `mcp:tools/call:query_db`). `resource` is exact or a trailing-`*` prefix (`supplier:*`, `mcp://host/tools/*`).

5.2 `constraints` is an object. Keys defined in v0.1: `max_value` (number), `currency` (ISO-4217 string), `region` (string array). Unknown keys MUST be carried through and compared for equality when attenuating.

5.3 **Attenuation rule.** A child capability is covered by a parent when `action` is equal, the parent resource contains the child resource, and the child constraints are *tighter*: `max_value` ≤ parent, `region` ⊆ parent, every other parent key equal in the child. A child capability set is a subset of the parent set when every child capability is covered by some parent capability. Delegation MUST refuse anything wider (`exceeds_parent`).

5.4 **Request coverage.** A request `{ action, resource?, amount?, currency?, context.region? }` is authorized when some effective capability has the same action, contains the resource, and its constraints are satisfied by the request (`amount ≤ max_value`, currency equal, region in set). Otherwise `capability_missing` or `constraint_violated`.

## 6. Delegation

6.1 A delegation is `{ id, parent_id, subject_agent_id, issuer: {type: principal|agent, id}, capabilities, constraints?, not_before?, not_after?, status: active|expired|revoked, depth }`. The root MUST be issued by a principal (`root_requires_principal`); a child MUST be issued by the parent's subject agent (`issuer_must_be_parent_subject`). Depth is 0 at the root; chains MUST NOT exceed depth 8 (`depth_exceeded`); organizations MAY lower the limit.

6.2 **Delegation credential** — JWS `typ: "agent-trust-delegation+jwt"`, signed by the issuing organization's key:

```json
{ "iss": "<org id>", "sub": "<subject agent id>", "jti": "<delegation id>", "iat": 1789400000, "nbf": …, "exp": …,
  "atp": { "v": 1, "issuer": {"type":"principal","id":"prn_…"}, "capabilities": [...], "constraints": {...},
           "effective": [...], "parent": "<parent delegation id>|null", "parent_hash": "<b64url sha256(parent JWS)>|null",
           "depth": 0, "task": "supplier research|null" } }
```

`parent_hash` commits each link to the exact parent token, so a chain of credentials verifies offline: signature and `typ` per link; `exp`/`nbf`; `parent` = previous `jti`; `parent_hash` = hash of the previous token; `depth` = previous + 1; issuer = previous subject; `capabilities ⊆` previous effective; `effective` = attenuate(previous effective, capabilities). Reason codes: `parent_link`, `parent_hash`, `depth`, `issuer_must_be_parent_subject`, `exceeds_parent`, `effective_mismatch`, `root_expected`, `too_long`, `unknown_key`, `signature`, `expired`.

## 7. Request proof-of-possession

An agent SHOULD sign each request with a detached JWS carried in the `Agent-Proof` header (modelled on DPoP, RFC 9449):

```
header  { "alg": "ES256|EdDSA", "typ": "agent-trust-proof+jwt", "kid": "<credential kid>" }
payload { "iss": "<agent id>", "htm": "POST", "htu": "https://host/v1/verify", "iat": …, "exp": …, "jti": "<unique>", "rh": "<b64url sha256(exact request body bytes)>" }
```

`htu` is compared after normalising scheme and host to lower case and dropping query and fragment. Verifiers MUST check signature against the credential identified by `kid`, `htm`, `htu`, `rh`, `exp`, an `iat` skew window (default 300 s) and SHOULD reject replayed `jti`s until `exp`. Outcomes: `request_signed` (evidence `proof: pass`), `proof_invalid:<reason>` (fail, hard), or `request_unsigned` (warn — or fail when the organization requires signed requests).

## 8. Authorization

8.1 Authority (capabilities via delegation or direct assignment) is **default-deny** and checked before policy. Policy then *narrows*: it may deny or require approval, and MAY allow explicitly.

8.2 A policy document is `{ version: 1, default?: allow|deny|require_approval, rules: Rule[] }` with `Rule = { id, description?, match?: { action?, resource?, risk_tier?, agent_labels? }, conditions?: Condition[], effect }` and conditions `amount_lte`, `amount_gt`, `currency_in`, `region_in`, `requires_attestation`, `missing_attestation`, `delegation_depth_lte`, `delegation_depth_gt`, `time_window` (UTC, may wrap midnight). All rules whose match and conditions hold fire; precedence is `deny > require_approval > allow`; when nothing fires the document default applies (default `allow`). Evaluation MUST be deterministic given the document, the input and the clock. Reason codes: `policy:<rule id>:<effect>`, `policy:default:<effect>`.

8.3 Organization defaults (max depth, escalate-by-risk-tier, attestation-by-risk-tier) are expressed as synthetic rules with ids `org-default:*` evaluated ahead of policy, so they appear in evidence like any rule.

8.4 Human approval is a first-class object: `{ id, decision_id, status: pending|approved|rejected|expired, reviewer_id, review_reason, requested_at, expires_at }`; resolving it is audited.

## 9. Authorization attestation

JWS `typ: "agent-trust-attestation+jwt"`, issued by the organization from an `ALLOW` decision or a `REQUIRE_APPROVAL` decision whose approval was granted; short-lived (default 600 s, max 3600 s):

```json
{ "iss": "<org id>", "sub": "<agent id>", "jti": "<attestation id>", "iat": …, "exp": …, "aud": "<optional>",
  "atp": { "v": 1, "principal": "prn_…|null", "organization": "<org id>", "action": "purchase.create", "resource": "supplier:123|null",
           "decision": "ALLOW|REQUIRE_APPROVAL", "capabilities": [...effective...], "delegation_chain": ["dlg_…"],
           "human_approval": { "required": true, "approved": true, "approver": "usr_…", "approval_id": "apr_…" } | null,
           "decision_id": "dec_…", "request_hash": "<sha256>", "policy_version": "pv_…|null" } }
```

A relying party MUST verify signature (org JWKS), `typ`, `exp`, that `sub` is the calling agent, that `atp.action` equals the requested action and `atp.resource` (when present) contains the requested resource, and SHOULD check revocation by `jti`. Outcomes: `attestation_valid` / `attestation_invalid:<reason>`.

## 10. Verification algorithm

Input `VerifyRequest = { agent, action, resource?, principal?, delegation_id?, amount?, currency?, context?, attestation? }` plus optional request binding `{ proof, htm, htu, bodyHash }`. Steps, each producing exactly one evidence row:

1. `request` — parse; 2. `identity` — resolve agent, lifecycle active; 3. `credential` — active, unexpired, issuer trusted; 4. `proof` — §7; 5. `attestation_token` — §9 (only when presented); 6. `principal`; 7. `delegation` — resolve chain (cycle guard, depth ≤ 8), every link active and inside its window, compute effective authority (or direct capabilities with warning `no_delegation`); 8. `capability` + `constraints` — §5.4; 9. `revocation` — agent, credential, leaf delegation; 10. `attestation` — runtime attestations present (evidence only in v0.1); 11. `policy` — §8; 12. decide.

Decision: any `fail` row ⇒ `DENY`; else policy `require_approval` ⇒ `REQUIRE_APPROVAL`; else `ALLOW`. Reasons are the union of the codes above (`identity_verified`, `authority_valid`, `agent_unknown`, `agent_<state>`, `credential_missing|expired|issuer_untrusted`, `principal_unbound`, `no_delegation`, `delegation_chain_<reason>`, `delegation_expired|revoked`, `capability_missing`, `constraint_violated`, `revoked`, `request_signed|request_unsigned|proof_invalid:*`, `attestation_valid|attestation_invalid:*`, `policy:*`).

## 11. Provenance

Every consequential event is a CloudEvents-shaped envelope `{ id, source: "agent-trust/<org>", type, time, subject?, correlation_id?, org_id, schema_version: 1, data, prev_hash, hash, signature }`. `hash = sha256(JCS(envelope without hash/signature))` (RFC 8785 canonicalization); `prev_hash` links to the previous envelope of the organization (per-org sequence); `signature` is HMAC-SHA256 in v0.1 (asymmetric signing planned). Stores MUST be append-only; verifiers re-derive hashes and links over a window. Decision events carry reasons, evidence, request hash and the delegation chain.

## 12. Revocation

Subjects: `agent`, `credential`, `delegation`, `api_key`, `policy_version`, plus attestations by `jti`. A revoked subject yields `revoked` at verification; `GET /v1/status/{subject}` MUST answer from one indexed lookup. Short-lived credentials + explicit status + cached verification is the recommended combination; chain status is honoured on every link.

## 13. Trust domains and organization keys

Each organization publishes a JWKS (`/v1/orgs/{id}/jwks`) containing active and retired signing keys with `kid`, `alg`, `use: "sig"`. Retired keys stay published so historic credentials still verify. Cross-organization trust (OpenID Federation entity statements, trust-chain resolution to anchors) is out of scope for v0.1.

## 14. Conformance

An implementation conforms when it reproduces the decision, the listed reasons and the per-step evidence statuses of every vector in `conformance/vectors`. Vectors are the executable specification; a change of semantics MUST come with a vector.

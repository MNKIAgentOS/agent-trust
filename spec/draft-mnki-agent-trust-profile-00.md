---
title: "The Agent Trust Profile: Verifiable Authority for Autonomous Agents"
abbrev: agent-trust-profile
docname: draft-mnki-agent-trust-profile-00
category: info
submissiontype: independent
ipr: trust200902
area: Security
keyword: [agent, delegation, authorization, attestation, provenance, WIMSE, AuthZEN]
author:
 - name: Javvad Azam
 role: editor
 organization: MNKI AgentOS
 email: javvad@mnki.com
 uri: https://mnki.com
 country: NL
normative:
 RFC2119:
 RFC7515:
 RFC7517:
 RFC7519:
 RFC8785:
 RFC9449:
informative:
 AUTHZEN:
 title: "OpenID AuthZEN Authorization API 1.0"
 target: https://openid.net/specs/authorization-api-1_0.html
 OIDFED:
 title: "OpenID Federation 1.0"
 target: https://openid.net/specs/openid-federation-1_0.html
 SPIFFE:
 title: "SPIFFE: Secure Production Identity Framework for Everyone"
 target: https://spiffe.io/docs/latest/spiffe-about/overview/
 CLOUDEVENTS:
 title: "CloudEvents 1.0"
 target: https://cloudevents.io/
---

--- abstract

Autonomous AI agents act on behalf of people and organizations across system and organizational
boundaries. Existing credentials establish that a token is valid; they do not express which agent is
acting, for whom, under what delegated authority, within which constraints, and whether that authority is
still current. This document profiles existing standards -- JWS, OAuth/OIDC, SPIFFE/WIMSE workload
identity, DPoP-style proof of possession, OpenID AuthZEN and OpenID Federation -- to carry those semantics:
agent identity and principal binding, delegation with authority attenuation, capability-based
authorization with constraints, request proof of possession, authorization attestations, tamper-evident
provenance, revocation, and cross-organization trust. It defines no new cryptography, transport or
token format.

--- middle

# Introduction

An agent request today typically carries a bearer token. A relying party can conclude "this credential is
valid" but not "this specific agent, acting for this principal, holds delegated authority for this action
under these limits, and that authority has not been revoked". The profile fills that gap with verifiable
objects layered on existing standards. Conformance is defined by executable vectors (Section 12).

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHOULD", "MAY" are to be interpreted as
described in {{RFC2119}}. All signed objects are compact JWS {{RFC7515}} with JOSE headers `alg`, `typ`
and `kid`; `alg` MUST be `ES256` or `EdDSA`. Public keys are JWKs {{RFC7517}}. Timestamps are ISO 8601
in UTC. Canonicalization for hashing is JCS {{RFC8785}}.

# Model

| Term | Meaning |
|---|---|
| Agent | Cryptographically identifiable software actor with a stable identifier, lifecycle and credentials |
| Principal | The human, service or organization the agent acts for; always distinct from the agent |
| Organization | The trust domain that operates the agent and signs its delegations and attestations |
| Capability | `{action, resource, constraints?}` -- a machine-evaluable unit of authority |
| Delegation | A grant of capabilities from an issuer to a subject agent with validity and status |
| Effective authority | The intersection of every grant in the chain, never the union |
| Decision | `ALLOW`, `DENY` or `REQUIRE_APPROVAL`, derived from evidence rows |

# Agent Identity

An agent identifier MUST be URI-safe, stable, non-secret and unique within its organization. SPIFFE IDs
{{SPIFFE}}, DIDs, OIDC subjects and organization-specific URIs are acceptable. Lifecycle states are
`pending`, `active`, `suspended`, `revoked`, `retired`; only `active` agents may be authorized.
Credentials bind a public JWK to the agent (`kid`, `not_before`, `not_after`, `issuer`, `status`).
Issuer-signed identity tokens ({{RFC7519}} JWT-SVIDs, IdP JWTs) MAY be presented in the `Agent-Credential` header
and validated against configured trust anchors (OIDC issuers via discovery JWKS; SPIFFE trust domains via
their bundle endpoint); a valid presented token MAY stand in for a registered key.

# Principal Binding

Every agent SHOULD carry an owner principal. Verifiers MUST report the principal as separate evidence and
MUST NOT conflate agent and principal.

# Capabilities, Constraints and Attenuation

`action` is exact; `resource` is exact or a trailing-`*` prefix. Constraint keys defined here: `max_value`
and `max_total` (numbers), `currency` (ISO 4217), `region` (list). A child capability is covered by a
parent when actions are equal, the parent resource contains the child resource, and the child constraints
are tighter (`max_value`/`max_total` not greater; `region` a subset; other keys equal). Delegation MUST
refuse anything wider (`exceeds_parent`). `max_total` denotes a lifetime budget across allowed requests.

# Delegation Credential

Type `agent-trust-delegation+jwt`. Claims: `iss` (organization), `sub` (subject agent), `jti`
(delegation id), `iat`, optional `nbf`/`exp`, and `atp` with `v` (1), `issuer` (`{type, id}`),
`capabilities`, `constraints`, `effective`, `parent`, `parent_hash` (base64url SHA-256 of the parent JWS),
`depth`, `task`. A chain root MUST be issued by a principal at depth 0; each child MUST be issued by the
parent's subject, reference its parent by `jti` and `parent_hash`, increment `depth`, and satisfy
`capabilities is a subset of parent effective` with `effective = attenuate(parent effective, capabilities)`. Chains MUST
NOT exceed depth 8.

# Request Proof of Possession

A detached JWS of type `agent-trust-proof+jwt` in the `Agent-Proof` header, modelled on DPoP {{RFC9449}}:
`iss` (agent), `htm`, `htu` (scheme and host lower-cased, no query or fragment), `iat`, `exp`, `jti`,
`rh` (base64url SHA-256 of the exact request body). Verifiers MUST check the signature against the
credential named by `kid`, `htm`, `htu`, `rh`, expiry and skew, and SHOULD reject replayed `jti` values.

# Authorization

Authority is checked first and is default-deny; policy narrows. A policy document
`{version: 1, default?, rules[]}` with rules `{id, match?, conditions?, effect}` fires every rule whose
match and conditions hold; precedence is `deny > require_approval > allow`; the document default applies
when nothing fires. Conditions: `amount_lte`, `amount_gt`, `currency_in`, `region_in`,
`requires_attestation`, `missing_attestation`, `delegation_depth_lte`, `delegation_depth_gt`,
`time_window`. Evaluation MUST be deterministic. A policy decision point exposing this evaluation SHOULD
implement the AuthZEN evaluation request {{AUTHZEN}}. Human approval is a first-class signed object
(`agent-trust-approval+jwt`) bound to the decision's request hash: `iss` (organization), `sub` (agent),
`jti` (approval id), `iat`, `exp`, and `atp` with `decision_id`, `action`, `resource`, `maximum`,
`currency`, `request_hash`, `approver`, `status` and `reason`. It MAY be signed by the approver's registered
device key (`kid` = device id, lifetime <= 600 s) and is then countersigned by the organization key with
`atp.device` and `atp.device_proof_hash` (SHA-256 of the device-signed object), so the record commits to the
device that approved.

# Authorization Attestation

Type `agent-trust-attestation+jwt`, short-lived, issued by the organization from an `ALLOW` decision or an
approved `REQUIRE_APPROVAL` decision: `iss`, `sub` (agent), `jti`, `iat`, `exp`, optional `aud`, and
`atp` with `principal`, `organization`, `action`, `resource`, `decision`, `capabilities` (effective),
`delegation_chain`, `human_approval`, `decision_id`, `request_hash`, `policy_version`. A relying party
MUST verify signature, type, expiry, subject, action and resource coverage, and SHOULD check revocation by
`jti`.

# Provenance

Each consequential event is a CloudEvents-shaped {{CLOUDEVENTS}} envelope hash-chained per organization
(`prev_hash`, `hash = SHA-256(JCS(envelope))`), signed with the organization key (`es256:<kid>:<sig>`) or
an HMAC. Stores MUST be append-only. A signed ledger-head checkpoint (`agent-trust-ledger-head+jwt`)
enables external anchoring.

# Revocation

Subjects: agent, credential, delegation, attestation, policy version. Revoking any link of a delegation
chain invalidates every descendant at verification time. Short-lived credentials plus an indexed status
lookup are RECOMMENDED.

# Federation

Organizations publish an entity configuration (keys, endpoints, `authority_hints`) and MAY act as anchors
publishing signed subordinate statements (`entity-statement+jwt`), following the shape of OpenID
Federation {{OIDFED}}. Trust level 1 recognises an organization; level 2 permits its attested agents to
act under the relying organization's policy. Peer revocation lists are not consulted in this version;
attestation lifetimes bound the exposure.

# Conformance

Three levels: Level 1 Verifier (decision vectors), Level 2 Credentials (signed-object vectors), Level 3
Federation. An implementation claims a level only when every vector of that level and all lower levels is
reproduced.

# Security Considerations

The model is not trusted: an agent's proposal never carries authority by itself. Replay of request proofs
is bounded by `jti` tracking and short lifetimes. Attestations are short-lived because peer revocation is
not consulted across organizations. Budget enforcement requires the ledger; snapshot-based verifiers MUST
flag decisions taken without it. Debuggable enclaves MUST NOT yield verified TEE attestations.

# IANA Considerations

This document requests registration of the media types `application/agent-trust-proof+jwt`,
`application/agent-trust-delegation+jwt`, `application/agent-trust-attestation+jwt`,
`application/agent-trust-approval+jwt` and `application/agent-trust-ledger-head+jwt` in the "Media Types"
registry, and of the HTTP header fields `Agent-Proof`, `Agent-Credential` and `Agent-Attestation` in the
"Hypertext Transfer Protocol (HTTP) Field Name Registry".

--- back

# Acknowledgements

The profile builds on the work of the IETF WIMSE and OAuth working groups, the OpenID Foundation AuthZEN
and Federation working groups, the SPIFFE project, and the Model Context Protocol and Agent-to-Agent
communities.

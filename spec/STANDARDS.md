# Standards engagement plan

Position: *an early implementer and contributor, not a competing protocol.* The profile is a semantic
layer on OAuth/OIDC, WIMSE/SPIFFE, DPoP, AuthZEN, OpenID Federation, MCP and A2A.

| Venue | What we bring | Action (human) |
|---|---|---|
| IETF WIMSE WG | Agent identity on workload identity; delegation chains and attenuation as WIMSE-compatible objects | Post `draft-mnki-agent-trust-profile-00` to the WIMSE list; ask for agenda time; align delegation credential with the WIMSE token-exchange/delegation drafts |
| IETF OAuth WG | Agent-Proof as a DPoP application; presented issuer credentials | Cross-post; offer interop at the next hackathon |
| OpenID Foundation — AuthZEN WG | `/access/v1/evaluation` mapping; agent-specific context claims | Join the WG; submit the agent context profile as an implementer's draft |
| OpenID Foundation — Federation WG | Entity configurations, subordinate statements, trust levels for agents | Join; contribute the "agent trust" metadata type |
| NIST AI Agent Standards Initiative | Verifiable authority, provenance and revocation as measurable controls | Respond to the RFI with the profile, the conformance suite and the whitepaper |
| MCP / A2A communities | Gateway enforcement semantics (JSON-RPC -32001/-32003), Agent Card extension | Open discussion threads; publish the extension URI and JSON schema |
| NVIDIA AIP | Identity/proof compatibility | Interop note in `spec/interoperability.md`; offer a mapping PR |

Submission mechanics: the draft is authored in kramdown-rfc markdown; render with `kdrfc
spec/draft-mnki-agent-trust-profile-00.md` and submit via the IETF datatracker. Keep `-00` frozen once
posted; changes go to `-01`. Every semantic change ships with a conformance vector first.

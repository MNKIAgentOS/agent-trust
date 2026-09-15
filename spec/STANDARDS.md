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

## Submission-ready rendering

`spec/rendered/` holds the Internet-Draft as XML (RFC 7991 v3), plain text and HTML, produced from the
kramdown source with the IETF toolchain and free of xml2rfc warnings:

```bash
gem install kramdown-rfc && pip install xml2rfc
cd spec/rendered && kramdown-rfc2629 ../draft-mnki-agent-trust-profile-00.md > draft-mnki-agent-trust-profile-00.xml && xml2rfc --text --html draft-mnki-agent-trust-profile-00.xml
```

Submission checklist (human steps):
1. Replace the placeholder author (`Editor (MNKI)`) in the kramdown front matter with the named editor — the Datatracker requires a person — and re-render.
2. Upload `spec/rendered/draft-mnki-agent-trust-profile-00.xml` at https://datatracker.ietf.org/submit/ (independent submission, Informational). The confirmation email goes to the author address.
3. Announce on the WIMSE and OAuth lists (see the venue plan above) and open the OpenID AuthZEN / Federation issues listed there.
4. On feedback, bump `docname` to `-01`, re-render, resubmit; keep the profile text in `spec/agent-trust-profile-v0.1.md` in sync.

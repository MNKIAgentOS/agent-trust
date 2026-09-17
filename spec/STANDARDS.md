# Standards engagement plan

**Posted 16 September 2026:** `draft-mnki-agent-trust-profile-00` is an active IETF Internet-Draft
(individual submission, Informational) —
[datatracker](https://datatracker.ietf.org/doc/draft-mnki-agent-trust-profile/) ·
[text](https://www.ietf.org/archive/id/draft-mnki-agent-trust-profile-00.txt). It expires 19 March 2027;
a `-01` before then keeps it active. `-00` is frozen as posted.

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

Submission checklist:
1. ~~Named editor in the front matter~~ — done: Javvad Azam, MNKI AgentOS, NL.
2. ~~Upload the XML at https://datatracker.ietf.org/submit/~~ — done, posted 16 Sep 2026 (idnits: 0 errors,
   0 flaws, 1 warning about non-ASCII characters, since fixed in the source for `-01`).
3. **Next:** announce on the WIMSE and OAuth lists and open the OpenID AuthZEN / Federation issues — drafts in
   [../docs/gtm/announcements.md](../docs/gtm/announcements.md).
4. On feedback, bump `docname` to `-01`, re-render, resubmit; keep the profile text in
   `spec/agent-trust-profile-v0.1.md` in sync. Re-render with the venv used for `-00`:
   `xml2rfc --text --html spec/rendered/draft-mnki-agent-trust-profile-00.xml`.

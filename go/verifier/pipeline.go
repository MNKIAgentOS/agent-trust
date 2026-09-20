package verifier

import (
	"fmt"
	"strings"
	"time"
)

// Evidence is one row per check. Title/Detail are the normative English text (asserted by the conformance
// vectors); Code/Params are the same row in machine-readable form (`<step>.<meaning>` plus the interpolated
// values) so a client can render it in any language. See packages/verifier/src/evidence-codes.ts.
type Evidence struct {
	Step   string         `json:"step"`
	Status string         `json:"status"` // pass | warn | fail | skipped
	Title  string         `json:"title"`
	Detail string         `json:"detail,omitempty"`
	Refs   []string       `json:"refs,omitempty"`
	Code   string         `json:"code,omitempty"`
	Params map[string]any `json:"params,omitempty"`
}

// P is the parameter bag of an evidence row.
type P = map[string]any

func strOrNil(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// PresentedCredential is the outcome of Deps.VerifyPresentedCredential.
type PresentedCredential struct {
	OK     bool
	Reason string
	Kind   string
	Issuer string
	Sub    string
	Kid    string
	Exp    *int64
}

// FederatedIssuer is a trusted peer organization.
type FederatedIssuer struct {
	Name       string
	TrustLevel int
	// StaleOkSeconds (§12.1): accept (with a warning) an attestation issued at most this long ago when the peer's status endpoint is unreachable; 0 = refuse.
	StaleOkSeconds int
}

// Deps is everything the pipeline needs from storage. Nil funcs are optional capabilities.
type Deps struct {
	GetAgent                  func(ref string) *AgentInfo
	GetActiveCredential       func(agentID string) *CredentialInfo
	GetPrincipal              func(id string) *PrincipalInfo
	GetLeafDelegation         func(agentID string, delegationID *string) *Delegation
	// GetCoveringDelegation (optional, §17): the newest active delegation whose authority covers action on resource; nil → GetLeafDelegation fallback.
	GetCoveringDelegation     func(agentID, action string, resource *string) *Delegation
	GetDelegationAncestry     func(leafID string) []Delegation
	GetAgentCapabilities      func(agentID string) CapSet
	IsRevoked                 func(subjectType, subjectID string) bool
	GetAttestations           func(agentID string) []AttestationInfo
	GetPolicy                 func() *ActivePolicy
	IsTrustedIssuer           func(issuer *string) bool
	GetCredentialKey          func(agentID, kid string) *JWK
	SeenJti                   func(jti string, exp int64) bool
	GetOrgKey                 func(kid, iss string) *JWK
	IsAttestationRevoked      func(jti string) bool
	// ConsumeAttestation (optional, §9.2) atomically claims a single-use jti: "first" when this call claimed it, "seen" when already consumed. Nil = single-use attestations are refused.
	ConsumeAttestation        func(jti string, exp int64) string
	// PeerAttestationStatus (optional, §12.1) asks the issuing peer about a jti: "active", "revoked" or "unreachable". Nil = not consulted (v0.1 warning).
	PeerAttestationStatus     func(iss, jti string) string
	VerifyPresentedCredential func(token string) PresentedCredential
	GetFederatedIssuer        func(iss string) *FederatedIssuer
	SpentSoFar                func(delegationID *string, agentID, action string, currency *string) float64
}

// RequestBinding: transport facts the proof is bound to.
type RequestBinding struct {
	Proof      *string
	Htm, Htu   string
	BodyHash   string
	Credential *string
}

// Options for Verify.
type Options struct {
	Now          time.Time
	Request      *RequestBinding
	RequireProof bool
	// RequestHash (§9.2): canonical hash of the request being executed; a single-use attestation must be bound to it.
	RequestHash string
	// Audience (§17): the relying party's own identifier; when set, a presented attestation must carry it in aud.
	Audience string
}

// Result mirrors the TypeScript VerifyResult (same JSON shape).
type Result struct {
	Decision string     `json:"decision"`
	Reasons  []string   `json:"reasons"`
	Evidence []Evidence `json:"evidence"`
	Agent    *struct {
		ID       string `json:"id"`
		Verified bool   `json:"verified"`
	} `json:"agent"`
	Principal *struct {
		ID       string `json:"id"`
		Verified bool   `json:"verified"`
	} `json:"principal"`
	Delegation struct {
		Valid       bool     `json:"valid"`
		ChainLength int      `json:"chain_length"`
		Chain       []string `json:"chain"`
	} `json:"delegation"`
	Authorization struct {
		Capability     string   `json:"capability"`
		Valid          bool     `json:"valid"`
		RemainingLimit *float64 `json:"remaining_limit"`
	} `json:"authorization"`
	Revocation struct {
		Checked bool `json:"checked"`
		Valid   bool `json:"valid"`
	} `json:"revocation"`
	PolicyVersion *string `json:"policy_version"`
	PolicyHash    *string `json:"policy_hash"`
	Proof         struct {
		Present  bool    `json:"present"`
		Verified bool    `json:"verified"`
		Kid      *string `json:"kid"`
		Alg      *string `json:"alg"`
	} `json:"proof"`
	Attestation struct {
		Present   bool    `json:"present"`
		Valid     bool    `json:"valid"`
		Jti       *string `json:"jti"`
		ExpiresIn *int64  `json:"expires_in"`
		Use       *string `json:"use"`
		Consumed  bool    `json:"consumed"`
	} `json:"attestation"`
	Federation *struct {
		Issuer     string `json:"issuer"`
		Name       string `json:"name"`
		TrustLevel int    `json:"trust_level"`
	} `json:"federation"`
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func fmtConstraints(c Constraints) string {
	if c == nil {
		return ""
	}
	parts := []string{}
	for k, v := range c {
		if ss, ok := asStrings(v); ok {
			parts = append(parts, k+"="+strings.Join(ss, "|"))
		} else {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	return strings.Join(parts, ", ")
}

// Verify runs the profile's verification algorithm. Pure: no I/O beyond deps, no clock beyond opts.Now.
func Verify(req VerifyRequest, deps Deps, opts Options) Result {
	now := opts.Now
	res := Result{Reasons: []string{}, Evidence: []Evidence{}}
	res.Delegation.Chain = []string{}
	res.Authorization.Capability = req.Action
	res.Revocation.Checked = true
	hardFail := false
	push := func(e Evidence) { res.Evidence = append(res.Evidence, e) }
	fail := func(step, code, title, reason, detail string, params P, refs ...string) {
		push(Evidence{Step: step, Status: "fail", Title: title, Detail: detail, Refs: refs, Code: code, Params: params})
		res.Reasons = append(res.Reasons, reason)
		hardFail = true
	}
	var cred *CredentialInfo
	var principal *PrincipalInfo
	var leaf *Delegation
	var effective CapSet = CapSet{}
	chainIDs := []string{}
	delegationValid, authorized, revoked := false, false, false
	var pol *ActivePolicy
	var remaining *float64
	var attExp, attIat int64
	var attApprovalID *string
	attApproved, attBound := false, false
	approvalOf := func(a AttestationClaims) {
		if a.HumanApproval != nil && a.HumanApproval.Approved {
			attApproved, attApprovalID = true, a.HumanApproval.ApprovalID
			attBound = opts.RequestHash == "" || a.RequestHash == nil || *a.RequestHash == opts.RequestHash
		}
	}
	boundElsewhere := func(a AttestationClaims) bool {
		return a.Use == "single" && opts.RequestHash != "" && a.RequestHash != nil && *a.RequestHash != opts.RequestHash
	}
	audOk := func(aud Audience) bool { return opts.Audience == "" || aud.Contains(opts.Audience) }
	audText := func(aud Audience) string {
		if len(aud) == 0 {
			return "(none)"
		}
		return strings.Join(aud, ",")
	}
	useOf := func(a AttestationClaims) *string {
		u := a.Use
		if u == "" {
			u = "multi"
		}
		return &u
	}
	res.Proof.Present = opts.Request != nil && opts.Request.Proof != nil
	res.Attestation.Present = req.Attestation != nil
	var federation *FederatedIssuer
	federationIss := ""
	var fedCaps CapSet
	fedChain := []string{}
	var fedPrincipal *string
	fedApproved := false

	finish := func(decision string, agent *AgentInfo) Result {
		res.Decision = decision
		res.Reasons = uniq(res.Reasons)
		if agent != nil {
			res.Agent = &struct {
				ID       string `json:"id"`
				Verified bool   `json:"verified"`
			}{agent.ID, agent.Lifecycle == "active"}
		}
		if principal != nil {
			res.Principal = &struct {
				ID       string `json:"id"`
				Verified bool   `json:"verified"`
			}{principal.ID, true}
		}
		res.Delegation.Valid = delegationValid
		res.Delegation.ChainLength = len(chainIDs)
		res.Delegation.Chain = chainIDs
		res.Authorization.Valid = authorized
		if authorized {
			res.Authorization.RemainingLimit = remaining
		}
		res.Revocation.Valid = !revoked
		if pol != nil {
			res.PolicyVersion = pol.VersionID
			res.PolicyHash = pol.Hash
		}
		if federation != nil {
			res.Federation = &struct {
				Issuer     string `json:"issuer"`
				Name       string `json:"name"`
				TrustLevel int    `json:"trust_level"`
			}{federationIss, federation.Name, federation.TrustLevel}
		}
		return res
	}

	detail := req.Action
	if req.Resource != nil {
		detail += " on " + *req.Resource
	}
	if req.Amount != nil {
		detail += fmt.Sprintf(" · %v", *req.Amount)
		if req.Currency != nil {
			detail += " " + *req.Currency
		}
	}
	var amount any
	if req.Amount != nil {
		amount = *req.Amount
	}
	push(Evidence{Step: "request", Status: "pass", Title: "Request parsed", Detail: detail, Code: "request.parsed", Params: P{"action": req.Action, "resource": strOrNil(req.Resource), "amount": amount, "currency": strOrNil(req.Currency)}})

	// 3. identity — local registry, or a federated agent attested by a level-2 peer
	agent := deps.GetAgent(req.Agent)
	if agent == nil && req.Attestation != nil && deps.GetFederatedIssuer != nil && deps.GetOrgKey != nil {
		var hdr struct {
			Iss string `json:"iss"`
		}
		if _, ok := DecodeJWT(*req.Attestation, &hdr); ok && hdr.Iss != "" {
			if peer := deps.GetFederatedIssuer(hdr.Iss); peer != nil {
				if peer.TrustLevel < 2 {
					fail("identity", "identity.federation_level_insufficient", "Peer organization is trusted at level 1 only", "federation_level_insufficient", peer.Name+" may not act here; raise it to trust level 2", P{"peer": peer.Name, "issuer": hdr.Iss})
					return finish(Deny, nil)
				}
				a, expIn, r := VerifyAttestation(*req.Attestation, KeyResolver(deps.GetOrgKey), now)
				if r != "" {
					fail("identity", "identity.federated_attestation_invalid", "Federated attestation invalid", "attestation_invalid:"+r, "issuer "+hdr.Iss+": "+r, P{"issuer": hdr.Iss, "reason": r})
					return finish(Deny, nil)
				}
				if a.Sub != req.Agent {
					fail("identity", "identity.federated_attestation_subject", "Federated attestation names a different agent", "attestation_invalid:subject", "sub "+a.Sub, P{"sub": a.Sub})
					return finish(Deny, nil)
				}
				if !audOk(a.Aud) {
					fail("identity", "identity.federated_attestation_audience", "Federated attestation is for a different audience", "attestation_invalid:audience", "aud "+audText(a.Aud)+"; expected "+opts.Audience, P{"aud": audText(a.Aud), "expected": opts.Audience})
					return finish(Deny, nil)
				}
				if a.Atp.Action != req.Action || (a.Atp.Resource != nil && req.Resource != nil && !ResourceContains(*a.Atp.Resource, *req.Resource)) {
					fail("identity", "identity.federated_attestation_action", "Federated attestation does not cover this action", "attestation_invalid:action", "attested "+a.Atp.Action, P{"action": a.Atp.Action, "resource": strOrNil(a.Atp.Resource)})
					return finish(Deny, nil)
				}
				if boundElsewhere(a.Atp) {
					fail("identity", "identity.federated_attestation_request_hash", "Federated attestation is bound to a different request", "attestation_invalid:request_hash", "single-use attestation "+a.Jti+" was issued for another request", P{"jti": a.Jti}, a.Jti)
					return finish(Deny, nil)
				}
				agent = &AgentInfo{ID: a.Sub, StableID: a.Sub, Lifecycle: "active", RiskTier: "medium", Labels: map[string]string{"federated_org": hdr.Iss}}
				federation, federationIss = peer, hdr.Iss
				attIat = a.Iat
				fedCaps, fedChain, fedPrincipal = a.Atp.Capabilities, a.Atp.DelegationChain, a.Atp.Principal
				if fedChain == nil {
					fedChain = []string{}
				}
				fedApproved = a.Atp.HumanApproval != nil && a.Atp.HumanApproval.Approved
				res.Attestation.Valid, res.Attestation.Jti, res.Attestation.ExpiresIn, res.Attestation.Use, attExp = true, strp(a.Jti), &expIn, useOf(a.Atp), a.Exp
				approvalOf(a.Atp)
				res.Reasons = append(res.Reasons, "identity_federated", "attestation_valid")
				push(Evidence{Step: "identity", Status: "pass", Title: fmt.Sprintf("Federated agent — attested by %s (trust level %d)", peer.Name, peer.TrustLevel), Detail: a.Sub, Refs: []string{a.Jti}, Code: "identity.federated", Params: P{"peer": peer.Name, "level": peer.TrustLevel, "issuer": hdr.Iss, "sub": a.Sub}})
			}
		}
	}
	if agent == nil {
		fail("identity", "identity.unknown", "Agent unknown", "agent_unknown", fmt.Sprintf("No agent matches %q", req.Agent), P{"agent": req.Agent})
		return finish(Deny, nil)
	}
	if federation == nil {
		if agent.Lifecycle != "active" {
			fail("identity", "identity.lifecycle", "Agent is "+agent.Lifecycle, "agent_"+agent.Lifecycle, "", P{"lifecycle": agent.Lifecycle}, agent.ID)
		} else {
			push(Evidence{Step: "identity", Status: "pass", Title: "Agent identity resolved", Detail: agent.StableID, Refs: []string{agent.ID}, Code: "identity.resolved", Params: P{"stable_id": agent.StableID}})
		}
	}

	if federation != nil {
		push(Evidence{Step: "credential", Status: "pass", Title: "Issuer attestation stands in for a local credential (" + federation.Name + ")", Code: "credential.federated_issuer", Params: P{"peer": federation.Name, "issuer": federationIss}})
		if opts.Request != nil && opts.Request.Proof != nil {
			push(Evidence{Step: "proof", Status: "skipped", Title: "Request proof not checked for federated agents", Detail: "The agent's key lives in the peer registry.", Code: "proof.federated_skipped", Params: P{}})
		} else if opts.RequireProof {
			fail("proof", "proof.unsigned_required", "Unsigned request", "request_unsigned", "This organization requires signed requests", P{})
		}
		if fedPrincipal != nil {
			push(Evidence{Step: "principal", Status: "pass", Title: "Principal " + *fedPrincipal + " asserted by " + federation.Name, Detail: "Not resolved locally", Code: "principal.federated", Params: P{"principal": *fedPrincipal, "peer": federation.Name}})
		} else {
			push(Evidence{Step: "principal", Status: "warn", Title: "No principal in the federated attestation", Code: "principal.federated_none", Params: P{}})
			res.Reasons = append(res.Reasons, "principal_unbound")
		}
		effective, chainIDs, delegationValid = fedCaps, fedChain, len(fedChain) > 0
		if effective == nil {
			effective = CapSet{}
		}
		if len(fedChain) > 0 {
			push(Evidence{Step: "delegation", Status: "pass", Title: fmt.Sprintf("Delegation chain attested by issuer (%d link%s)", len(fedChain), plural(len(fedChain))), Refs: fedChain, Code: "delegation.federated", Params: P{"links": len(fedChain)}})
			res.Reasons = append(res.Reasons, "delegation_attested")
		} else {
			push(Evidence{Step: "delegation", Status: "warn", Title: "No delegation chain in the attestation — issuer-asserted capabilities", Refs: []string{}, Code: "delegation.federated_none", Params: P{}})
			res.Reasons = append(res.Reasons, "no_delegation")
		}
		if fedApproved {
			res.Reasons = append(res.Reasons, "human_approved_by_issuer")
		}
	} else {
		// 4. credential
		cred = deps.GetActiveCredential(agent.ID)
		var presented *string
		if opts.Request != nil {
			presented = opts.Request.Credential
		}
		if presented != nil && deps.VerifyPresentedCredential != nil {
			v := deps.VerifyPresentedCredential(*presented)
			if !v.OK {
				d := v.Reason
				if v.Issuer != "" {
					d = "issuer " + v.Issuer + ": " + v.Reason
				}
				var issuer any
				if v.Issuer != "" {
					issuer = v.Issuer
				}
				fail("credential", "credential.presented_invalid", "Presented credential invalid", "credential_presented_invalid:"+v.Reason, d, P{"reason": v.Reason, "issuer": issuer}, agent.ID)
			} else if v.Sub != agent.StableID && v.Sub != agent.ID {
				fail("credential", "credential.presented_subject", "Presented credential names a different agent", "credential_presented_invalid:subject", "sub "+v.Sub, P{"sub": v.Sub}, agent.ID)
			} else {
				if cred == nil {
					var na *string
					if v.Exp != nil {
						na = strp(time.Unix(*v.Exp, 0).UTC().Format(time.RFC3339))
					}
					cred = &CredentialInfo{ID: "presented:" + v.Kind, Kind: v.Kind, Status: "active", NotAfter: na, Issuer: strp(v.Issuer)}
				}
				title, code := "Issuer token verified against "+v.Issuer, "credential.token_verified"
				if v.Kind == "jwt_svid" {
					title, code = "JWT-SVID verified against "+v.Issuer, "credential.svid_verified"
				}
				var kid, exp any
				if v.Kid != "" {
					kid = v.Kid
				}
				if v.Exp != nil {
					exp = time.Unix(*v.Exp, 0).UTC().Format("2006-01-02T15:04:05Z")
				}
				push(Evidence{Step: "credential", Status: "pass", Title: title, Refs: []string{agent.ID}, Code: code, Params: P{"kind": v.Kind, "issuer": v.Issuer, "kid": kid, "exp": exp}})
				res.Reasons = append(res.Reasons, "credential_presented_verified")
			}
		} else if cred == nil {
			fail("credential", "credential.missing", "No active credential", "credential_missing", "", P{}, agent.ID)
		} else if cred.NotAfter != nil && !now.Before(ParseISO(*cred.NotAfter)) {
			fail("credential", "credential.expired", "Credential expired", "credential_expired", "expired "+*cred.NotAfter, P{"not_after": *cred.NotAfter}, cred.ID)
		} else if deps.IsTrustedIssuer != nil && !deps.IsTrustedIssuer(cred.Issuer) {
			d := "credential has no issuer"
			if cred.Issuer != nil {
				d = "issuer " + *cred.Issuer + " is not a configured trust domain"
			}
			fail("credential", "credential.issuer_untrusted", "Credential issuer not trusted", "credential_issuer_untrusted", d, P{"issuer": strOrNil(cred.Issuer)}, cred.ID)
		} else {
			d := ""
			var notAfter any
			if cred.NotAfter != nil && len(*cred.NotAfter) >= 10 {
				d = "valid until " + (*cred.NotAfter)[:10]
				notAfter = (*cred.NotAfter)[:10]
			}
			push(Evidence{Step: "credential", Status: "pass", Title: "Credential fresh (" + cred.Kind + ")", Detail: d, Refs: []string{cred.ID}, Code: "credential.fresh", Params: P{"kind": cred.Kind, "not_after": notAfter}})
		}

		// 4b. request proof
		if opts.Request != nil && opts.Request.Proof != nil {
			r := opts.Request
			out := VerifyRequestProof(ProofInput{Proof: *r.Proof, Htm: r.Htm, Htu: r.Htu, BodyHash: r.BodyHash, Now: now,
				ResolveKey: func(kid string) *JWK {
					if deps.GetCredentialKey == nil {
						return nil
					}
					return deps.GetCredentialKey(agent.ID, kid)
				}, SeenJti: deps.SeenJti})
			refs := []string{}
			var kid any
			if out.Kid != "" {
				refs = []string{out.Kid}
				kid = out.Kid
			}
			if !out.OK {
				fail("proof", "proof.invalid", "Request signature invalid", "proof_invalid:"+out.Reason, out.Reason, P{"reason": out.Reason, "kid": kid}, refs...)
			} else if out.Claims.Iss != agent.ID && out.Claims.Iss != agent.StableID {
				fail("proof", "proof.issuer_mismatch", "Request signed by a different agent", "proof_invalid:issuer", "iss "+out.Claims.Iss, P{"iss": out.Claims.Iss, "kid": kid}, refs...)
			} else {
				res.Proof.Verified = true
				if out.Kid != "" {
					res.Proof.Kid = strp(out.Kid)
				}
				res.Proof.Alg = strp(out.Alg)
				res.Reasons = append(res.Reasons, "request_signed")
				push(Evidence{Step: "proof", Status: "pass", Title: "Request signature verified (" + out.Alg + ")", Detail: "kid " + out.Kid, Refs: refs, Code: "proof.verified", Params: P{"alg": out.Alg, "kid": kid}})
			}
		} else if opts.RequireProof {
			fail("proof", "proof.unsigned_required", "Unsigned request", "request_unsigned", "This organization requires signed requests", P{})
		} else {
			push(Evidence{Step: "proof", Status: "warn", Title: "Request not signed", Detail: "No Agent-Proof header — possession of the agent key was not proven.", Code: "proof.unsigned", Params: P{}})
			res.Reasons = append(res.Reasons, "request_unsigned")
		}

		// 4c. presented attestation
		if req.Attestation != nil {
			if deps.GetOrgKey == nil {
				fail("attestation_token", "attestation_token.no_resolver", "Attestation cannot be verified", "attestation_invalid:no_resolver", "", P{})
			} else {
				a, expIn, r := VerifyAttestation(*req.Attestation, KeyResolver(deps.GetOrgKey), now)
				switch {
				case r != "":
					fail("attestation_token", "attestation_token.invalid", "Authorization attestation invalid", "attestation_invalid:"+r, r, P{"reason": r})
				case a.Sub != agent.ID && a.Sub != agent.StableID:
					fail("attestation_token", "attestation_token.subject", "Attestation issued to a different agent", "attestation_invalid:subject", "sub "+a.Sub, P{"sub": a.Sub})
				case !audOk(a.Aud):
					fail("attestation_token", "attestation_token.audience", "Attestation is for a different audience", "attestation_invalid:audience", "aud "+audText(a.Aud)+"; expected "+opts.Audience, P{"aud": audText(a.Aud), "expected": opts.Audience}, a.Jti)
				case a.Atp.Action != req.Action:
					fail("attestation_token", "attestation_token.action", "Attestation covers a different action", "attestation_invalid:action", "attested "+a.Atp.Action, P{"action": a.Atp.Action})
				case a.Atp.Resource != nil && req.Resource != nil && !ResourceContains(*a.Atp.Resource, *req.Resource):
					fail("attestation_token", "attestation_token.resource", "Attestation does not cover this resource", "attestation_invalid:resource", "attested "+*a.Atp.Resource, P{"resource": *a.Atp.Resource})
				case boundElsewhere(a.Atp):
					fail("attestation_token", "attestation_token.request_hash", "Attestation bound to a different request", "attestation_invalid:request_hash", "single-use attestation "+a.Jti+" was issued for another request", P{"jti": a.Jti}, a.Jti)
				case deps.IsAttestationRevoked != nil && deps.IsAttestationRevoked(a.Jti):
					fail("attestation_token", "attestation_token.revoked", "Attestation revoked", "attestation_invalid:revoked", "", P{"jti": a.Jti}, a.Jti)
				default:
					res.Attestation.Valid, res.Attestation.Jti, res.Attestation.ExpiresIn, res.Attestation.Use, attExp = true, strp(a.Jti), &expIn, useOf(a.Atp), a.Exp
					approvalOf(a.Atp)
					res.Reasons = append(res.Reasons, "attestation_valid")
					approved := a.Atp.HumanApproval != nil && a.Atp.HumanApproval.Approved
					push(Evidence{Step: "attestation_token", Status: "pass", Title: fmt.Sprintf("Authorization attestation valid (expires in %ds)", expIn), Detail: "issued by " + a.Iss + " for " + a.Atp.Action, Refs: []string{a.Jti}, Code: "attestation_token.valid", Params: P{"jti": a.Jti, "expires_in": expIn, "issuer": a.Iss, "action": a.Atp.Action, "human_approved": approved}})
				}
			}
		}

		// 5. principal
		if agent.OwnerPrincipalID != nil {
			principal = deps.GetPrincipal(*agent.OwnerPrincipalID)
		}
		if principal != nil {
			push(Evidence{Step: "principal", Status: "pass", Title: "Principal binding active (" + principal.DisplayName + ")", Refs: []string{principal.ID}, Code: "principal.bound", Params: P{"name": principal.DisplayName, "id": principal.ID}})
		} else {
			push(Evidence{Step: "principal", Status: "warn", Title: "No delegating principal", Detail: "Authority is not bound to a human or service owner.", Code: "principal.unbound", Params: P{}})
			res.Reasons = append(res.Reasons, "principal_unbound")
		}

		// 6–8. delegation chain
		// §17: without an explicit delegation id, prefer the delegation that covers this action.
		if req.DelegationID == nil && deps.GetCoveringDelegation != nil {
			leaf = deps.GetCoveringDelegation(agent.ID, req.Action, req.Resource)
		}
		if leaf == nil {
			leaf = deps.GetLeafDelegation(agent.ID, req.DelegationID)
		}
		if leaf != nil {
			anc := deps.GetDelegationAncestry(leaf.ID)
			byID := map[string]*Delegation{}
			for i := range anc {
				byID[anc[i].ID] = &anc[i]
			}
			chain := ResolveChain(leaf.ID, func(id string) *Delegation { return byID[id] }, MaxChainDepth)
			if !chain.OK {
				fail("delegation", "delegation.chain_invalid", "Delegation chain "+chain.Reason, "delegation_chain_"+chain.Reason, "at "+chain.At, P{"reason": chain.Reason, "at": chain.At}, leaf.ID)
			} else {
				for _, d := range chain.Chain {
					chainIDs = append(chainIDs, d.ID)
				}
				effective = ComputeEffectiveAuthority(chain.Chain, now)
				var bad *Delegation
				for i := range chain.Chain {
					d := chain.Chain[i]
					if d.Status != "active" || (d.NotAfter != nil && !now.Before(ParseISO(*d.NotAfter))) || (d.NotBefore != nil && now.Before(ParseISO(*d.NotBefore))) {
						bad = &chain.Chain[i]
						break
					}
				}
				if bad != nil {
					what := bad.Status
					params := P{"link": bad.ID, "status": what}
					if what == "active" {
						fail("delegation", "delegation.link_outside_window", "Delegation outside validity window", "delegation_expired", "", params, bad.ID)
					} else if what == "expired" {
						fail("delegation", "delegation.link_expired", "Delegation "+what, "delegation_"+what, "", params, bad.ID)
					} else {
						fail("delegation", "delegation.link_revoked", "Delegation "+what, "delegation_"+what, "", params, bad.ID)
					}
				} else {
					delegationValid = true
					push(Evidence{Step: "delegation", Status: "pass", Title: fmt.Sprintf("Delegation chain valid (%d link%s)", len(chain.Chain), plural(len(chain.Chain))), Refs: chainIDs, Code: "delegation.valid", Params: P{"links": len(chain.Chain)}})
				}
			}
		} else {
			effective = deps.GetAgentCapabilities(agent.ID)
			if effective == nil {
				effective = CapSet{}
			}
			push(Evidence{Step: "delegation", Status: "warn", Title: "No delegation — using directly assigned capabilities", Refs: []string{agent.ID}, Code: "delegation.none", Params: P{}})
			res.Reasons = append(res.Reasons, "no_delegation")
		}
	}

	// 9. capability + constraints
	requestedRes := "*"
	if req.Resource != nil {
		requestedRes = *req.Resource
	}
	covering := CapSet{}
	for _, c := range effective {
		if c.Action != req.Action {
			continue
		}
		if req.Resource == nil || CapabilityCovered(Capability{Action: c.Action, Resource: c.Resource}, Capability{Action: req.Action, Resource: requestedRes}) {
			covering = append(covering, c)
		}
	}
	if len(covering) == 0 {
		d := ""
		if req.Resource != nil {
			d = "for " + *req.Resource
		}
		fail("capability", "capability.missing", "Capability "+req.Action+" not granted", "capability_missing", d, P{"action": req.Action, "resource": strOrNil(req.Resource)})
	} else {
		reqC := Constraints{}
		if req.Amount != nil {
			reqC["max_value"] = *req.Amount
		}
		if req.Currency != nil {
			reqC["currency"] = *req.Currency
		}
		if req.Context != nil {
			if rg, ok := req.Context["region"].(string); ok {
				reqC["region"] = []string{rg}
			}
		}
		var within *Capability
		for i := range covering {
			merged := Constraints{}
			for k, v := range covering[i].Constraints {
				merged[k] = v
			}
			for k, v := range reqC {
				merged[k] = v
			}
			if ConstraintsTighter(covering[i].Constraints, merged) {
				within = &covering[i]
				break
			}
		}
		if within == nil {
			limits := fmtConstraints(covering[0].Constraints)
			var lp any
			if limits != "" {
				lp = limits
			}
			fail("constraints", "constraints.violated", "Request exceeds capability constraints", "constraint_violated", limits, P{"limits": lp})
		} else if mt, ok := asFloat(within.Constraints["max_total"]); ok && req.Amount != nil && deps.SpentSoFar != nil {
			var leafID *string
			if leaf != nil {
				leafID = strp(leaf.ID)
			}
			spent := deps.SpentSoFar(leafID, agent.ID, req.Action, req.Currency)
			left := mt - spent
			cur := ""
			if req.Currency != nil {
				cur = " " + *req.Currency
			}
			if *req.Amount > left {
				fail("constraints", "constraints.budget_exhausted", "Budget exhausted", "budget_exceeded", fmt.Sprintf("%v of %v%s already spent; %v left", spent, mt, cur, left), P{"spent": spent, "total": mt, "left": left, "currency": strOrNil(req.Currency)})
			} else {
				authorized = true
				l := left - *req.Amount
				remaining = &l
				push(Evidence{Step: "capability", Status: "pass", Title: "Capability " + req.Action + " granted", Detail: within.Resource, Code: "capability.granted", Params: P{"action": req.Action, "resource": within.Resource}})
				push(Evidence{Step: "constraints", Status: "pass", Title: "Constraints satisfied", Detail: fmt.Sprintf("budget %v of %v%s used", spent+*req.Amount, mt, cur), Code: "constraints.budget_ok", Params: P{"used": spent + *req.Amount, "total": mt, "left": l, "currency": strOrNil(req.Currency)}})
			}
		} else {
			authorized = true
			if mv, ok := asFloat(within.Constraints["max_value"]); ok && req.Amount != nil {
				l := mv - *req.Amount
				remaining = &l
			}
			push(Evidence{Step: "capability", Status: "pass", Title: "Capability " + req.Action + " granted", Detail: within.Resource, Code: "capability.granted", Params: P{"action": req.Action, "resource": within.Resource}})
			var limits any
			if within.Constraints != nil {
				limits = fmtConstraints(within.Constraints)
			}
			push(Evidence{Step: "constraints", Status: "pass", Title: "Constraints satisfied", Detail: fmtConstraints(within.Constraints), Code: "constraints.satisfied", Params: P{"limits": limits}})
		}
	}

	// 10. revocation
	if federation != nil && deps.PeerAttestationStatus != nil {
		// §12.1 (v0.2): the issuing peer is asked about this jti; unreachable is a refusal unless inside the peer's stale window.
		jti := *res.Attestation.Jti
		switch deps.PeerAttestationStatus(federationIss, jti) {
		case "active":
			push(Evidence{Step: "revocation", Status: "pass", Title: "Peer revocation checked with " + federation.Name + " — none found", Refs: []string{jti}, Code: "revocation.peer_none", Params: P{"peer": federation.Name, "jti": jti}})
		case "revoked":
			revoked = true
			fail("revocation", "revocation.peer_revoked", "Attestation revoked by "+federation.Name, "revoked", "", P{"peer": federation.Name, "jti": jti}, jti)
		default:
			age := now.Unix() - attIat
			if age < 0 {
				age = 0
			}
			d := fmt.Sprintf("issued %ds ago; stale window %ds", age, federation.StaleOkSeconds)
			if federation.StaleOkSeconds > 0 && age <= int64(federation.StaleOkSeconds) {
				push(Evidence{Step: "revocation", Status: "warn", Title: federation.Name + " unreachable — attestation accepted inside the stale window", Detail: d, Refs: []string{jti}, Code: "revocation.peer_unreachable_stale_ok", Params: P{"peer": federation.Name, "age": age, "stale_ok": federation.StaleOkSeconds}})
				res.Reasons = append(res.Reasons, "revocation_remote_unreachable")
			} else {
				revoked = true
				fail("revocation", "revocation.peer_unreachable", federation.Name+" unreachable — revocation status unknown", "revocation_remote_unreachable", d, P{"peer": federation.Name, "age": age, "stale_ok": federation.StaleOkSeconds}, jti)
			}
		}
	} else if federation != nil {
		exp := "?"
		if res.Attestation.ExpiresIn != nil {
			exp = fmt.Sprintf("%d", *res.Attestation.ExpiresIn)
		}
		var expIn any
		if res.Attestation.ExpiresIn != nil {
			expIn = *res.Attestation.ExpiresIn
		}
		push(Evidence{Step: "revocation", Status: "warn", Title: "Peer revocation not consulted", Detail: "Attestation is short-lived (expires in " + exp + "s); " + federation.Name + "'s revocation list is not queried in v0.1.", Code: "revocation.peer_unchecked", Params: P{"peer": federation.Name, "expires_in": expIn}})
		res.Reasons = append(res.Reasons, "revocation_remote_unchecked")
	} else {
		revokedRef := ""
		if deps.IsRevoked("agent", agent.ID) {
			revokedRef = agent.ID
		} else if cred != nil && deps.IsRevoked("credential", cred.ID) {
			revokedRef = cred.ID
		} else {
			ids := chainIDs
			if len(ids) == 0 && leaf != nil {
				ids = []string{leaf.ID}
			}
			for _, id := range ids {
				if deps.IsRevoked("delegation", id) {
					revokedRef = id
					break
				}
			}
		}
		revoked = revokedRef != ""
		if revoked {
			title, code := "A delegation in the chain is revoked", "revocation.delegation"
			if revokedRef == agent.ID {
				title, code = "Agent is revoked", "revocation.agent"
			} else if cred != nil && revokedRef == cred.ID {
				title, code = "Credential is revoked", "revocation.credential"
			}
			fail("revocation", code, title, "revoked", "", P{"ref": revokedRef}, revokedRef)
		} else {
			push(Evidence{Step: "revocation", Status: "pass", Title: "Revocation checked — none found", Code: "revocation.none", Params: P{}})
		}
	}

	// 11. attestation (evidence only)
	atts := []AttestationInfo{}
	for _, a := range deps.GetAttestations(agent.ID) {
		if a.Verified && (a.ExpiresAt == nil || now.Before(ParseISO(*a.ExpiresAt))) {
			atts = append(atts, a)
		}
	}
	kinds := []string{}
	refs := []string{}
	for _, a := range atts {
		kinds = append(kinds, a.Kind)
		refs = append(refs, a.ID)
	}
	if len(atts) > 0 {
		push(Evidence{Step: "attestation", Status: "pass", Title: "Runtime attested (" + strings.Join(kinds, ", ") + ")", Refs: refs, Code: "attestation.present", Params: P{"kinds": strings.Join(kinds, ", ")}})
	} else {
		push(Evidence{Step: "attestation", Status: "skipped", Title: "No runtime attestation", Detail: "Not required by policy.", Code: "attestation.none", Params: P{}})
	}

	// 11b. effect path (§15, v0.2): the caller declares how the effect is enforced; the evidence shows it on every decision.
	effectPath := ""
	if req.Context != nil {
		if s, ok := req.Context["effect_path"].(string); ok {
			effectPath = s
		}
	}
	switch effectPath {
	case "custody":
		push(Evidence{Step: "enforcement", Status: "pass", Title: "Effect path: the enforcement point holds the effect credential", Detail: "the agent never holds it, so the effector is reachable only through a decision", Code: "enforcement.custody", Params: P{"path": "custody"}})
	case "attested":
		push(Evidence{Step: "enforcement", Status: "pass", Title: "Effect path: the effector verifies the attestation", Detail: "the effector executes only with an attestation bound to this request", Code: "enforcement.attested", Params: P{"path": "attested"}})
	default:
		path := "undeclared"
		if effectPath == "none" {
			path = "none"
		}
		push(Evidence{Step: "enforcement", Status: "warn", Title: "A direct path to the effector may exist", Detail: "effect path " + path + "; this decision relies on deployment isolation", Code: "enforcement.none", Params: P{"path": path}})
	}

	// 12. policy
	pol = deps.GetPolicy()
	policyEffect := "allow"
	if pol != nil {
		var region *string
		if req.Context != nil {
			if rg, ok := req.Context["region"].(string); ok {
				region = strp(rg)
			}
		}
		out := Evaluate(pol.Doc, PolicyInput{Action: req.Action, Resource: req.Resource, Amount: req.Amount, Currency: req.Currency, Region: region, RiskTier: agent.RiskTier, AgentLabels: agent.Labels, DelegationDepth: len(chainIDs), Attestations: kinds, Time: now})
		policyEffect = out.Effect
		res.Reasons = append(res.Reasons, out.Reasons...)
		status, title, code := "pass", "Policy allows", "policy.allow"
		if out.Effect == "deny" {
			status, title, code = "fail", "Policy denies", "policy.deny"
		} else if out.Effect == "require_approval" {
			status, title, code = "warn", "Policy requires human approval", "policy.require_approval"
		}
		d := "no rule fired"
		var fired any
		if len(out.Fired) > 0 {
			d = "fired: " + strings.Join(out.Fired, ", ")
			fired = strings.Join(out.Fired, ", ")
		}
		var prefs []string
		if pol.VersionID != nil {
			prefs = []string{*pol.VersionID}
		}
		if out.Effect == "require_approval" && res.Attestation.Valid && attApproved && attBound && res.Attestation.Jti != nil {
			// §9.2: the presented attestation carries the approval this policy asks for, for this very request.
			policyEffect = "allow"
			res.Reasons = append(res.Reasons, "human_approved_by_attestation")
			apr := "?"
			if attApprovalID != nil {
				apr = *attApprovalID
			}
			dd := "approval " + apr + " carried by " + *res.Attestation.Jti
			if len(out.Fired) > 0 {
				dd = "fired: " + strings.Join(out.Fired, ", ") + "; " + dd
			}
			var aid any
			if attApprovalID != nil {
				aid = *attApprovalID
			}
			push(Evidence{Step: "policy", Status: "pass", Title: "Policy's approval requirement is met by a human-approved attestation", Detail: dd, Refs: append(prefs, *res.Attestation.Jti), Code: "policy.approved_by_attestation", Params: P{"fired": fired, "version": strOrNil(pol.VersionID), "jti": *res.Attestation.Jti, "approval_id": aid}})
		} else {
			push(Evidence{Step: "policy", Status: status, Title: title, Detail: d, Refs: prefs, Code: code, Params: P{"fired": fired, "version": strOrNil(pol.VersionID)}})
		}
		if out.Effect == "deny" {
			hardFail = true
		}
	} else {
		push(Evidence{Step: "policy", Status: "skipped", Title: "No active policy", Code: "policy.none", Params: P{}})
	}

	// 13. decide
	decision := Allow
	if hardFail {
		decision = Deny
	} else if policyEffect == "require_approval" {
		decision = RequireApproval
	}
	// 14. single-use attestation (§9.2): spent only when the effect is about to be allowed, atomically, so a replay finds it spent.
	if decision == Allow && res.Attestation.Valid && res.Attestation.Use != nil && *res.Attestation.Use == "single" && res.Attestation.Jti != nil {
		jti := *res.Attestation.Jti
		if deps.ConsumeAttestation == nil {
			fail("single_use", "single_use.no_store", "Single-use attestation cannot be consumed here", "attestation_invalid:no_consume_store", "No consumption store: single-use attestation "+jti+" is refused where its use cannot be recorded", P{"jti": jti}, jti)
			decision = Deny
		} else if deps.ConsumeAttestation(jti, attExp) == "seen" {
			fail("single_use", "single_use.consumed", "Attestation already used", "attestation_invalid:consumed", "Single-use attestation "+jti+" was consumed by an earlier request", P{"jti": jti}, jti)
			decision = Deny
		} else {
			res.Attestation.Consumed = true
			res.Reasons = append(res.Reasons, "attestation_consumed")
			push(Evidence{Step: "single_use", Status: "pass", Title: "Single-use attestation consumed", Detail: jti + " cannot be presented again", Refs: []string{jti}, Code: "single_use.recorded", Params: P{"jti": jti}})
		}
	}
	if decision == Allow {
		res.Reasons = append([]string{"identity_verified", "authority_valid"}, res.Reasons...)
	}
	return finish(decision, agent)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

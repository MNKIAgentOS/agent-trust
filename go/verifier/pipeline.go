package verifier

import (
	"fmt"
	"strings"
	"time"
)

// Evidence is one row per check.
type Evidence struct {
	Step   string   `json:"step"`
	Status string   `json:"status"` // pass | warn | fail | skipped
	Title  string   `json:"title"`
	Detail string   `json:"detail,omitempty"`
	Refs   []string `json:"refs,omitempty"`
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
}

// Deps is everything the pipeline needs from storage. Nil funcs are optional capabilities.
type Deps struct {
	GetAgent                  func(ref string) *AgentInfo
	GetActiveCredential       func(agentID string) *CredentialInfo
	GetPrincipal              func(id string) *PrincipalInfo
	GetLeafDelegation         func(agentID string, delegationID *string) *Delegation
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
	fail := func(step, title, reason, detail string, refs ...string) {
		push(Evidence{Step: step, Status: "fail", Title: title, Detail: detail, Refs: refs})
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
	push(Evidence{Step: "request", Status: "pass", Title: "Request parsed", Detail: detail})

	// 3. identity — local registry, or a federated agent attested by a level-2 peer
	agent := deps.GetAgent(req.Agent)
	if agent == nil && req.Attestation != nil && deps.GetFederatedIssuer != nil && deps.GetOrgKey != nil {
		var hdr struct {
			Iss string `json:"iss"`
		}
		if _, ok := DecodeJWT(*req.Attestation, &hdr); ok && hdr.Iss != "" {
			if peer := deps.GetFederatedIssuer(hdr.Iss); peer != nil {
				if peer.TrustLevel < 2 {
					fail("identity", "Peer organization is trusted at level 1 only", "federation_level_insufficient", peer.Name+" may not act here; raise it to trust level 2")
					return finish(Deny, nil)
				}
				a, expIn, r := VerifyAttestation(*req.Attestation, KeyResolver(deps.GetOrgKey), now)
				if r != "" {
					fail("identity", "Federated attestation invalid", "attestation_invalid:"+r, "issuer "+hdr.Iss+": "+r)
					return finish(Deny, nil)
				}
				if a.Sub != req.Agent {
					fail("identity", "Federated attestation names a different agent", "attestation_invalid:subject", "sub "+a.Sub)
					return finish(Deny, nil)
				}
				if a.Atp.Action != req.Action || (a.Atp.Resource != nil && req.Resource != nil && !ResourceContains(*a.Atp.Resource, *req.Resource)) {
					fail("identity", "Federated attestation does not cover this action", "attestation_invalid:action", "attested "+a.Atp.Action)
					return finish(Deny, nil)
				}
				agent = &AgentInfo{ID: a.Sub, StableID: a.Sub, Lifecycle: "active", RiskTier: "medium", Labels: map[string]string{"federated_org": hdr.Iss}}
				federation, federationIss = peer, hdr.Iss
				fedCaps, fedChain, fedPrincipal = a.Atp.Capabilities, a.Atp.DelegationChain, a.Atp.Principal
				if fedChain == nil {
					fedChain = []string{}
				}
				fedApproved = a.Atp.HumanApproval != nil && a.Atp.HumanApproval.Approved
				res.Attestation.Valid, res.Attestation.Jti, res.Attestation.ExpiresIn = true, strp(a.Jti), &expIn
				res.Reasons = append(res.Reasons, "identity_federated", "attestation_valid")
				push(Evidence{Step: "identity", Status: "pass", Title: fmt.Sprintf("Federated agent — attested by %s (trust level %d)", peer.Name, peer.TrustLevel), Detail: a.Sub, Refs: []string{a.Jti}})
			}
		}
	}
	if agent == nil {
		fail("identity", "Agent unknown", "agent_unknown", fmt.Sprintf("No agent matches %q", req.Agent))
		return finish(Deny, nil)
	}
	if federation == nil {
		if agent.Lifecycle != "active" {
			fail("identity", "Agent is "+agent.Lifecycle, "agent_"+agent.Lifecycle, "", agent.ID)
		} else {
			push(Evidence{Step: "identity", Status: "pass", Title: "Agent identity resolved", Detail: agent.StableID, Refs: []string{agent.ID}})
		}
	}

	if federation != nil {
		push(Evidence{Step: "credential", Status: "pass", Title: "Issuer attestation stands in for a local credential (" + federation.Name + ")"})
		if opts.Request != nil && opts.Request.Proof != nil {
			push(Evidence{Step: "proof", Status: "skipped", Title: "Request proof not checked for federated agents", Detail: "The agent's key lives in the peer registry."})
		} else if opts.RequireProof {
			fail("proof", "Unsigned request", "request_unsigned", "This organization requires signed requests")
		}
		if fedPrincipal != nil {
			push(Evidence{Step: "principal", Status: "pass", Title: "Principal " + *fedPrincipal + " asserted by " + federation.Name, Detail: "Not resolved locally"})
		} else {
			push(Evidence{Step: "principal", Status: "warn", Title: "No principal in the federated attestation"})
			res.Reasons = append(res.Reasons, "principal_unbound")
		}
		effective, chainIDs, delegationValid = fedCaps, fedChain, len(fedChain) > 0
		if effective == nil {
			effective = CapSet{}
		}
		if len(fedChain) > 0 {
			push(Evidence{Step: "delegation", Status: "pass", Title: fmt.Sprintf("Delegation chain attested by issuer (%d link%s)", len(fedChain), plural(len(fedChain))), Refs: fedChain})
			res.Reasons = append(res.Reasons, "delegation_attested")
		} else {
			push(Evidence{Step: "delegation", Status: "warn", Title: "No delegation chain in the attestation — issuer-asserted capabilities", Refs: []string{}})
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
				fail("credential", "Presented credential invalid", "credential_presented_invalid:"+v.Reason, d, agent.ID)
			} else if v.Sub != agent.StableID && v.Sub != agent.ID {
				fail("credential", "Presented credential names a different agent", "credential_presented_invalid:subject", "sub "+v.Sub, agent.ID)
			} else {
				if cred == nil {
					var na *string
					if v.Exp != nil {
						na = strp(time.Unix(*v.Exp, 0).UTC().Format(time.RFC3339))
					}
					cred = &CredentialInfo{ID: "presented:" + v.Kind, Kind: v.Kind, Status: "active", NotAfter: na, Issuer: strp(v.Issuer)}
				}
				title := "Issuer token verified against " + v.Issuer
				if v.Kind == "jwt_svid" {
					title = "JWT-SVID verified against " + v.Issuer
				}
				push(Evidence{Step: "credential", Status: "pass", Title: title, Refs: []string{agent.ID}})
				res.Reasons = append(res.Reasons, "credential_presented_verified")
			}
		} else if cred == nil {
			fail("credential", "No active credential", "credential_missing", "", agent.ID)
		} else if cred.NotAfter != nil && !now.Before(ParseISO(*cred.NotAfter)) {
			fail("credential", "Credential expired", "credential_expired", "expired "+*cred.NotAfter, cred.ID)
		} else if deps.IsTrustedIssuer != nil && !deps.IsTrustedIssuer(cred.Issuer) {
			d := "credential has no issuer"
			if cred.Issuer != nil {
				d = "issuer " + *cred.Issuer + " is not a configured trust domain"
			}
			fail("credential", "Credential issuer not trusted", "credential_issuer_untrusted", d, cred.ID)
		} else {
			d := ""
			if cred.NotAfter != nil && len(*cred.NotAfter) >= 10 {
				d = "valid until " + (*cred.NotAfter)[:10]
			}
			push(Evidence{Step: "credential", Status: "pass", Title: "Credential fresh (" + cred.Kind + ")", Detail: d, Refs: []string{cred.ID}})
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
			if out.Kid != "" {
				refs = []string{out.Kid}
			}
			if !out.OK {
				fail("proof", "Request signature invalid", "proof_invalid:"+out.Reason, out.Reason, refs...)
			} else if out.Claims.Iss != agent.ID && out.Claims.Iss != agent.StableID {
				fail("proof", "Request signed by a different agent", "proof_invalid:issuer", "iss "+out.Claims.Iss, refs...)
			} else {
				res.Proof.Verified = true
				if out.Kid != "" {
					res.Proof.Kid = strp(out.Kid)
				}
				res.Proof.Alg = strp(out.Alg)
				res.Reasons = append(res.Reasons, "request_signed")
				push(Evidence{Step: "proof", Status: "pass", Title: "Request signature verified (" + out.Alg + ")", Detail: "kid " + out.Kid, Refs: refs})
			}
		} else if opts.RequireProof {
			fail("proof", "Unsigned request", "request_unsigned", "This organization requires signed requests")
		} else {
			push(Evidence{Step: "proof", Status: "warn", Title: "Request not signed", Detail: "No Agent-Proof header — possession of the agent key was not proven."})
			res.Reasons = append(res.Reasons, "request_unsigned")
		}

		// 4c. presented attestation
		if req.Attestation != nil {
			if deps.GetOrgKey == nil {
				fail("attestation_token", "Attestation cannot be verified", "attestation_invalid:no_resolver", "")
			} else {
				a, expIn, r := VerifyAttestation(*req.Attestation, KeyResolver(deps.GetOrgKey), now)
				switch {
				case r != "":
					fail("attestation_token", "Authorization attestation invalid", "attestation_invalid:"+r, r)
				case a.Sub != agent.ID && a.Sub != agent.StableID:
					fail("attestation_token", "Attestation issued to a different agent", "attestation_invalid:subject", "sub "+a.Sub)
				case a.Atp.Action != req.Action:
					fail("attestation_token", "Attestation covers a different action", "attestation_invalid:action", "attested "+a.Atp.Action)
				case a.Atp.Resource != nil && req.Resource != nil && !ResourceContains(*a.Atp.Resource, *req.Resource):
					fail("attestation_token", "Attestation does not cover this resource", "attestation_invalid:resource", "attested "+*a.Atp.Resource)
				case deps.IsAttestationRevoked != nil && deps.IsAttestationRevoked(a.Jti):
					fail("attestation_token", "Attestation revoked", "attestation_invalid:revoked", "", a.Jti)
				default:
					res.Attestation.Valid, res.Attestation.Jti, res.Attestation.ExpiresIn = true, strp(a.Jti), &expIn
					res.Reasons = append(res.Reasons, "attestation_valid")
					push(Evidence{Step: "attestation_token", Status: "pass", Title: fmt.Sprintf("Authorization attestation valid (expires in %ds)", expIn), Detail: "issued by " + a.Iss + " for " + a.Atp.Action, Refs: []string{a.Jti}})
				}
			}
		}

		// 5. principal
		if agent.OwnerPrincipalID != nil {
			principal = deps.GetPrincipal(*agent.OwnerPrincipalID)
		}
		if principal != nil {
			push(Evidence{Step: "principal", Status: "pass", Title: "Principal binding active (" + principal.DisplayName + ")", Refs: []string{principal.ID}})
		} else {
			push(Evidence{Step: "principal", Status: "warn", Title: "No delegating principal", Detail: "Authority is not bound to a human or service owner."})
			res.Reasons = append(res.Reasons, "principal_unbound")
		}

		// 6–8. delegation chain
		leaf = deps.GetLeafDelegation(agent.ID, req.DelegationID)
		if leaf != nil {
			anc := deps.GetDelegationAncestry(leaf.ID)
			byID := map[string]*Delegation{}
			for i := range anc {
				byID[anc[i].ID] = &anc[i]
			}
			chain := ResolveChain(leaf.ID, func(id string) *Delegation { return byID[id] }, MaxChainDepth)
			if !chain.OK {
				fail("delegation", "Delegation chain "+chain.Reason, "delegation_chain_"+chain.Reason, "at "+chain.At, leaf.ID)
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
					if what == "active" {
						fail("delegation", "Delegation outside validity window", "delegation_expired", "", bad.ID)
					} else {
						fail("delegation", "Delegation "+what, "delegation_"+what, "", bad.ID)
					}
				} else {
					delegationValid = true
					push(Evidence{Step: "delegation", Status: "pass", Title: fmt.Sprintf("Delegation chain valid (%d link%s)", len(chain.Chain), plural(len(chain.Chain))), Refs: chainIDs})
				}
			}
		} else {
			effective = deps.GetAgentCapabilities(agent.ID)
			if effective == nil {
				effective = CapSet{}
			}
			push(Evidence{Step: "delegation", Status: "warn", Title: "No delegation — using directly assigned capabilities", Refs: []string{agent.ID}})
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
		fail("capability", "Capability "+req.Action+" not granted", "capability_missing", d)
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
			fail("constraints", "Request exceeds capability constraints", "constraint_violated", fmtConstraints(covering[0].Constraints))
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
				fail("constraints", "Budget exhausted", "budget_exceeded", fmt.Sprintf("%v of %v%s already spent; %v left", spent, mt, cur, left))
			} else {
				authorized = true
				l := left - *req.Amount
				remaining = &l
				push(Evidence{Step: "capability", Status: "pass", Title: "Capability " + req.Action + " granted", Detail: within.Resource})
				push(Evidence{Step: "constraints", Status: "pass", Title: "Constraints satisfied", Detail: fmt.Sprintf("budget %v of %v%s used", spent+*req.Amount, mt, cur)})
			}
		} else {
			authorized = true
			if mv, ok := asFloat(within.Constraints["max_value"]); ok && req.Amount != nil {
				l := mv - *req.Amount
				remaining = &l
			}
			push(Evidence{Step: "capability", Status: "pass", Title: "Capability " + req.Action + " granted", Detail: within.Resource})
			push(Evidence{Step: "constraints", Status: "pass", Title: "Constraints satisfied", Detail: fmtConstraints(within.Constraints)})
		}
	}

	// 10. revocation
	if federation != nil {
		exp := "?"
		if res.Attestation.ExpiresIn != nil {
			exp = fmt.Sprintf("%d", *res.Attestation.ExpiresIn)
		}
		push(Evidence{Step: "revocation", Status: "warn", Title: "Peer revocation not consulted", Detail: "Attestation is short-lived (expires in " + exp + "s); " + federation.Name + "'s revocation list is not queried in v0.1."})
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
			title := "A delegation in the chain is revoked"
			if revokedRef == agent.ID {
				title = "Agent is revoked"
			} else if cred != nil && revokedRef == cred.ID {
				title = "Credential is revoked"
			}
			fail("revocation", title, "revoked", "", revokedRef)
		} else {
			push(Evidence{Step: "revocation", Status: "pass", Title: "Revocation checked — none found"})
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
		push(Evidence{Step: "attestation", Status: "pass", Title: "Runtime attested (" + strings.Join(kinds, ", ") + ")", Refs: refs})
	} else {
		push(Evidence{Step: "attestation", Status: "skipped", Title: "No runtime attestation", Detail: "Not required by policy."})
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
		status, title := "pass", "Policy allows"
		if out.Effect == "deny" {
			status, title = "fail", "Policy denies"
		} else if out.Effect == "require_approval" {
			status, title = "warn", "Policy requires human approval"
		}
		d := "no rule fired"
		if len(out.Fired) > 0 {
			d = "fired: " + strings.Join(out.Fired, ", ")
		}
		var prefs []string
		if pol.VersionID != nil {
			prefs = []string{*pol.VersionID}
		}
		push(Evidence{Step: "policy", Status: status, Title: title, Detail: d, Refs: prefs})
		if out.Effect == "deny" {
			hardFail = true
		}
	} else {
		push(Evidence{Step: "policy", Status: "skipped", Title: "No active policy"})
	}

	// 13. decide
	decision := Allow
	if hardFail {
		decision = Deny
	} else if policyEffect == "require_approval" {
		decision = RequireApproval
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

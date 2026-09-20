package verifier

import (
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// Snapshot is the exported "edge snapshot" of one organization (the JSON produced by the console's
// /api/admin/snapshot/export). at-verify serves decisions from it without a database.
type Snapshot struct {
	V      int    `json:"v"`
	OrgID  string `json:"org_id"`
	At     string `json:"at"`
	Agents []struct {
		AgentInfo
		Name string `json:"name"`
	} `json:"agents"`
	Credentials []struct {
		ID       string  `json:"id"`
		AgentID  string  `json:"agent_id"`
		Kind     string  `json:"kind"`
		Status   string  `json:"status"`
		NotAfter *string `json:"not_after"`
		Issuer   *string `json:"issuer"`
		Kid      *string `json:"kid"`
		JWK      *JWK    `json:"jwk"`
	} `json:"credentials"`
	Principals  []PrincipalInfo `json:"principals"`
	Delegations []struct {
		Delegation
		CreatedAt string `json:"created_at"`
	} `json:"delegations"`
	Capabilities []struct {
		OwnerID     string      `json:"owner_id"`
		Action      string      `json:"action"`
		Resource    string      `json:"resource"`
		Constraints Constraints `json:"constraints"`
	} `json:"capabilities"`
	Revocations []struct {
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
	} `json:"revocations"`
	Attestations []struct {
		AttestationInfo
		AgentID string `json:"agent_id"`
	} `json:"attestations"`
	Policies []struct {
		VersionID string          `json:"version_id"`
		Hash      string          `json:"hash"`
		Doc       json.RawMessage `json:"doc"`
	} `json:"policies"`
	Settings struct {
		PolicyDefault         string   `json:"policyDefault"`
		MaxDelegationDepth    int      `json:"maxDelegationDepth"`
		ApprovalRiskTiers     []string `json:"approvalRiskTiers"`
		AttestationRiskTiers  []string `json:"attestationRiskTiers"`
		EnforceTrustedIssuers bool     `json:"enforceTrustedIssuers"`
		RequireSignedRequests bool     `json:"requireSignedRequests"`
	} `json:"settings"`
	Anchors struct {
		Issuers      []string `json:"issuers"`
		TrustDomains []string `json:"trustDomains"`
	} `json:"anchors"`
	Keys []struct {
		Kid string `json:"kid"`
		JWK JWK    `json:"jwk"`
	} `json:"keys"`
	RevokedAttestations []string `json:"revoked_attestations"`
	Peers               []struct {
		EntityID   string `json:"entity_id"`
		Name       string `json:"name"`
		TrustLevel int    `json:"trust_level"`
		StaleOk    int    `json:"stale_ok_seconds"`
	} `json:"peers"`
}

// OrgDefaultRules compiles the organization's security defaults into org-default:* rules (same as the console).
func OrgDefaultRules(s Snapshot) []Rule {
	rules := []Rule{}
	if s.Settings.MaxDelegationDepth > 0 && s.Settings.MaxDelegationDepth < 8 {
		rules = append(rules, Rule{ID: "org-default:max-delegation-depth", Conditions: []Condition{{Kind: "delegation_depth_gt", Value: float64(s.Settings.MaxDelegationDepth)}}, Effect: "deny"})
	}
	if len(s.Settings.ApprovalRiskTiers) > 0 {
		rules = append(rules, Rule{ID: "org-default:approval-by-risk-tier", Match: &RuleMatch{RiskTier: s.Settings.ApprovalRiskTiers}, Effect: "require_approval"})
	}
	if len(s.Settings.AttestationRiskTiers) > 0 {
		rules = append(rules, Rule{ID: "org-default:attestation-by-risk-tier", Match: &RuleMatch{RiskTier: s.Settings.AttestationRiskTiers}, Conditions: []Condition{{Kind: "missing_attestation"}}, Effect: "require_approval"})
	}
	return rules
}

func issuerTrusted(issuer *string, issuers, domains []string) bool {
	if issuer == nil {
		return false
	}
	norm := func(x string) string {
		for len(x) > 0 && x[len(x)-1] == '/' {
			x = x[:len(x)-1]
		}
		return toLower(x)
	}
	i := norm(*issuer)
	for _, t := range issuers {
		if norm(t) == i {
			return true
		}
	}
	host := i
	if idx := indexOf(host, "://"); idx >= 0 {
		host = host[idx+3:]
	}
	if idx := indexOf(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	for _, td := range domains {
		d := norm(td)
		if idx := indexOf(d, "://"); idx >= 0 {
			d = d[idx+3:]
		}
		if idx := indexOf(d, "/"); idx >= 0 {
			d = d[:idx]
		}
		if d != "" && (host == d || hasSuffix(host, "."+d)) {
			return true
		}
	}
	return false
}

// SnapshotDeps builds Deps over a snapshot — the same semantics as the console's snapshotDeps.
func SnapshotDeps(s Snapshot) Deps {
	revoked := map[string]bool{}
	for _, r := range s.Revocations {
		revoked[r.SubjectType+":"+r.SubjectID] = true
	}
	byID := map[string]*Delegation{}
	for i := range s.Delegations {
		byID[s.Delegations[i].ID] = &s.Delegations[i].Delegation
	}
	revokedAtt := map[string]bool{}
	for _, id := range s.RevokedAttestations {
		revokedAtt[id] = true
	}
	var jtiMu sync.Mutex
	seenJti := map[string]int64{}
	var policy *ActivePolicy
	docs := []PolicyDoc{}
	for _, p := range s.Policies {
		if d, bad := ParsePolicyDoc(p.Doc); bad == "" {
			docs = append(docs, d)
		}
	}
	synthetic := OrgDefaultRules(s)
	if len(docs) > 0 || len(synthetic) > 0 || (s.Settings.PolicyDefault != "" && s.Settings.PolicyDefault != "allow") {
		def := s.Settings.PolicyDefault
		if def == "" {
			def = "allow"
		}
		for _, d := range docs {
			if effectRank[d.Default] > effectRank[def] {
				def = d.Default
			}
		}
		merged := PolicyDoc{Version: 1, Default: def, Rules: append([]Rule{}, synthetic...)}
		for _, d := range docs {
			merged.Rules = append(merged.Rules, d.Rules...)
		}
		policy = &ActivePolicy{Doc: merged}
		if len(s.Policies) > 0 {
			policy.VersionID = strp(s.Policies[0].VersionID)
			if len(s.Policies) == 1 {
				policy.Hash = strp(s.Policies[0].Hash)
			}
		}
	}
	return Deps{
		GetAgent: func(ref string) *AgentInfo {
			for i := range s.Agents {
				a := &s.Agents[i]
				if a.ID == ref || a.StableID == ref || a.Name == ref {
					info := a.AgentInfo
					return &info
				}
			}
			return nil
		},
		GetActiveCredential: func(agentID string) *CredentialInfo {
			best := -1
			for i, c := range s.Credentials {
				if c.AgentID == agentID && c.Status == "active" && (best < 0 || c.ID > s.Credentials[best].ID) {
					best = i
				}
			}
			if best < 0 {
				return nil
			}
			c := s.Credentials[best]
			return &CredentialInfo{ID: c.ID, Kind: c.Kind, Status: c.Status, NotAfter: c.NotAfter, Issuer: c.Issuer}
		},
		GetPrincipal: func(id string) *PrincipalInfo {
			for i := range s.Principals {
				if s.Principals[i].ID == id {
					return &s.Principals[i]
				}
			}
			return nil
		},
		GetLeafDelegation: func(agentID string, delegationID *string) *Delegation {
			if delegationID != nil {
				if d := byID[*delegationID]; d != nil && d.SubjectAgentID == agentID {
					return d
				}
				return nil
			}
			cands := []int{}
			for i := range s.Delegations {
				if s.Delegations[i].SubjectAgentID == agentID {
					cands = append(cands, i)
				}
			}
			if len(cands) == 0 {
				return nil
			}
			sort.Slice(cands, func(a, b int) bool {
				da, db := s.Delegations[cands[a]], s.Delegations[cands[b]]
				if (da.Status == "active") != (db.Status == "active") {
					return da.Status == "active"
				}
				return da.CreatedAt > db.CreatedAt
			})
			return &s.Delegations[cands[0]].Delegation
		},
		GetDelegationAncestry: func(leafID string) []Delegation {
			out := []Delegation{}
			seen := map[string]bool{}
			cur := byID[leafID]
			for cur != nil && !seen[cur.ID] {
				seen[cur.ID] = true
				out = append(out, *cur)
				if cur.ParentID == nil {
					break
				}
				cur = byID[*cur.ParentID]
			}
			return out
		},
		GetAgentCapabilities: func(agentID string) CapSet {
			out := CapSet{}
			for _, c := range s.Capabilities {
				if c.OwnerID == agentID {
					out = append(out, Capability{Action: c.Action, Resource: c.Resource, Constraints: c.Constraints})
				}
			}
			return out
		},
		IsRevoked: func(t, id string) bool { return revoked[t+":"+id] },
		GetAttestations: func(agentID string) []AttestationInfo {
			out := []AttestationInfo{}
			for _, a := range s.Attestations {
				if a.AgentID == agentID {
					out = append(out, a.AttestationInfo)
				}
			}
			return out
		},
		GetPolicy: func() *ActivePolicy { return policy },
		IsTrustedIssuer: func(issuer *string) bool {
			return !s.Settings.EnforceTrustedIssuers || issuerTrusted(issuer, s.Anchors.Issuers, s.Anchors.TrustDomains)
		},
		GetCredentialKey: func(agentID, kid string) *JWK {
			for _, c := range s.Credentials {
				if c.AgentID == agentID && c.JWK != nil && (kid == "" || (c.Kid != nil && *c.Kid == kid)) {
					return c.JWK
				}
			}
			return nil
		},
		SeenJti: func(jti string, exp int64) bool {
			jtiMu.Lock()
			defer jtiMu.Unlock()
			nowU := time.Now().Unix()
			for k, e := range seenJti {
				if e < nowU {
					delete(seenJti, k)
				}
			}
			if _, ok := seenJti[jti]; ok {
				return true
			}
			seenJti[jti] = exp
			return false
		},
		GetOrgKey: func(kid, iss string) *JWK {
			if iss != s.OrgID {
				return nil
			}
			for i := range s.Keys {
				if s.Keys[i].Kid == kid {
					k := s.Keys[i].JWK
					return &k
				}
			}
			return nil
		},
		IsAttestationRevoked: func(jti string) bool { return revokedAtt[jti] },
		GetFederatedIssuer: func(iss string) *FederatedIssuer {
			for _, p := range s.Peers {
				if p.EntityID == iss {
					return &FederatedIssuer{Name: p.Name, TrustLevel: p.TrustLevel, StaleOkSeconds: p.StaleOk}
				}
			}
			return nil
		},
	}
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
func hasSuffix(s, suf string) bool { return len(s) >= len(suf) && s[len(s)-len(suf):] == suf }

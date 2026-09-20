package verifier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

type vectorWorld struct {
	Agent        *AgentInfo        `json:"agent"`
	Credential   *CredentialInfo   `json:"credential"`
	Principals   []PrincipalInfo   `json:"principals"`
	Delegations  []Delegation      `json:"delegations"`
	Capabilities CapSet            `json:"capabilities"`
	Revoked      []string          `json:"revoked"`
	Attestations []AttestationInfo `json:"attestations"`
	Policy       *ActivePolicy     `json:"policy"`
}
type vector struct {
	ID      string         `json:"id"`
	Title   string         `json:"title"`
	Now     string         `json:"now"`
	World   vectorWorld    `json:"world"`
	Request map[string]any `json:"request"`
	Expect  struct {
		Decision       string            `json:"decision"`
		ReasonsInclude []string          `json:"reasons_include"`
		ReasonsExact   []string          `json:"reasons_exact"`
		Evidence       map[string]string `json:"evidence"`
	} `json:"expect"`
}

// depsFrom builds the same in-memory world the TypeScript runner builds.
func depsFrom(w vectorWorld) Deps {
	revoked := map[string]bool{}
	for _, r := range w.Revoked {
		revoked[r] = true
	}
	return Deps{
		GetAgent: func(ref string) *AgentInfo {
			if w.Agent != nil && (ref == w.Agent.ID || ref == w.Agent.StableID) {
				return w.Agent
			}
			return nil
		},
		GetActiveCredential: func(string) *CredentialInfo { return w.Credential },
		GetPrincipal: func(id string) *PrincipalInfo {
			for i := range w.Principals {
				if w.Principals[i].ID == id {
					return &w.Principals[i]
				}
			}
			return nil
		},
		GetLeafDelegation: func(agentID string, delegationID *string) *Delegation {
			for i := range w.Delegations {
				d := w.Delegations[i]
				if delegationID != nil {
					if d.ID == *delegationID {
						return &w.Delegations[i]
					}
				} else if d.SubjectAgentID == agentID && d.ParentID != nil {
					return &w.Delegations[i]
				}
			}
			if delegationID != nil {
				return nil
			}
			for i := range w.Delegations {
				if w.Delegations[i].SubjectAgentID == agentID {
					return &w.Delegations[i]
				}
			}
			return nil
		},
		GetDelegationAncestry: func(string) []Delegation { return w.Delegations },
		GetCoveringDelegation: func(agentID, action string, resource *string) *Delegation {
			for i := range w.Delegations {
				d := w.Delegations[i]
				if d.SubjectAgentID != agentID || d.Status != "active" {
					continue
				}
				for _, c := range d.Capabilities {
					if c.Action == action && (resource == nil || ResourceContains(c.Resource, *resource)) {
						return &w.Delegations[i]
					}
				}
			}
			return nil
		},
		GetAgentCapabilities:  func(string) CapSet { return w.Capabilities },
		IsRevoked:             func(_, id string) bool { return revoked[id] },
		GetAttestations:       func(string) []AttestationInfo { return w.Attestations },
		GetPolicy:             func() *ActivePolicy { return w.Policy },
	}
}

func TestConformanceVectors(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "conformance", "vectors", "*.json"))
	if err != nil || len(files) < 14 {
		t.Fatalf("expected the reference vector set under conformance/vectors, found %d (%v)", len(files), err)
	}
	sort.Strings(files)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v vector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		t.Run(v.ID+" "+v.Title, func(t *testing.T) {
			req, bad := ParseVerifyRequest(v.Request)
			if bad != "" {
				t.Fatalf("request invalid: %s", bad)
			}
			now := ParseISO(v.Now)
			if now.IsZero() {
				now = time.Now()
			}
			r := Verify(req, depsFrom(v.World), Options{Now: now})
			if r.Decision != v.Expect.Decision {
				t.Fatalf("decision %s, want %s (reasons %v)", r.Decision, v.Expect.Decision, r.Reasons)
			}
			has := func(s string) bool {
				for _, x := range r.Reasons {
					if x == s {
						return true
					}
				}
				return false
			}
			for _, reason := range v.Expect.ReasonsInclude {
				if !has(reason) {
					t.Errorf("missing reason %q in %v", reason, r.Reasons)
				}
			}
			if v.Expect.ReasonsExact != nil {
				got, _ := json.Marshal(r.Reasons)
				want, _ := json.Marshal(v.Expect.ReasonsExact)
				if string(got) != string(want) {
					t.Errorf("reasons %s, want %s", got, want)
				}
			}
			for step, status := range v.Expect.Evidence {
				found := ""
				for _, e := range r.Evidence {
					if e.Step == step {
						found = e.Status
						break
					}
				}
				if found != status {
					t.Errorf("step %s: %q, want %q", step, found, status)
				}
			}
		})
	}
}

func TestSignedObjects(t *testing.T) {
	org, orgPub, _ := GenerateKey("ES256")
	orgPub.Kid = "org-1"
	resolve := func(kid, iss string) *JWK {
		if kid == "org-1" && iss == "org_acme" {
			return &orgPub
		}
		return nil
	}
	now := ParseISO("2026-09-14T12:00:00Z")
	root := CapSet{{Action: "purchase.create", Resource: "supplier:*", Constraints: Constraints{"max_value": 5000.0, "currency": "EUR", "region": []string{"EU"}}}}
	child := CapSet{{Action: "purchase.create", Resource: "supplier:1*", Constraints: Constraints{"max_value": 1200.0, "currency": "EUR", "region": []string{"EU"}}}}
	exp := now.Unix() + 86400
	rootTok, _ := SignJWT(org, "org-1", DelegationTyp, DelegationJWT{Iss: "org_acme", Sub: "agt_parent", Jti: "dlg_root", Iat: now.Unix(), Exp: &exp, Atp: DelegationClaims{V: 1, Issuer: struct{ Type, ID string }{"principal", "prn_alice"}, Capabilities: root, Effective: root}})
	ph := BodyHash([]byte(rootTok))
	parent := "dlg_root"
	childTok, _ := SignJWT(org, "org-1", DelegationTyp, DelegationJWT{Iss: "org_acme", Sub: "agt_child", Jti: "dlg_child", Iat: now.Unix(), Atp: DelegationClaims{V: 1, Issuer: struct{ Type, ID string }{"agent", "agt_parent"}, Capabilities: child, Effective: child, Parent: &parent, ParentHash: &ph, Depth: 1}})
	r := VerifyDelegationChain([]string{rootTok, childTok}, resolve, now)
	if !r.OK || r.Subject != "agt_child" || len(r.Chain) != 2 {
		t.Fatalf("chain: %+v", r)
	}
	wide := CapSet{{Action: "purchase.create", Resource: "supplier:*", Constraints: Constraints{"max_value": 9000.0, "currency": "EUR", "region": []string{"EU"}}}}
	wideTok, _ := SignJWT(org, "org-1", DelegationTyp, DelegationJWT{Iss: "org_acme", Sub: "agt_child", Jti: "dlg_w", Iat: now.Unix(), Atp: DelegationClaims{V: 1, Issuer: struct{ Type, ID string }{"agent", "agt_parent"}, Capabilities: wide, Effective: wide, Parent: &parent, ParentHash: &ph, Depth: 1}})
	if r := VerifyDelegationChain([]string{rootTok, wideTok}, resolve, now); r.OK || r.Reason != "exceeds_parent" {
		t.Fatalf("widening accepted: %+v", r)
	}
	// request proof round trip
	agentKey, agentPub, _ := GenerateKey("EdDSA")
	body := []byte(`{"agent":"agt_1","action":"purchase.create"}`)
	proof, _ := SignRequestProof(agentKey, "kid-1", "agt_1", "post", "https://Staging.MNKI.com/v1/verify?x=1", body, now, 60)
	pr := VerifyRequestProof(ProofInput{Proof: proof, ResolveKey: func(string) *JWK { return &agentPub }, Htm: "POST", Htu: "https://staging.mnki.com/v1/verify", BodyHash: BodyHash(body), Now: now})
	if !pr.OK || pr.Alg != "EdDSA" {
		t.Fatalf("proof: %+v", pr)
	}
	if pr := VerifyRequestProof(ProofInput{Proof: proof, ResolveKey: func(string) *JWK { return &agentPub }, Htm: "POST", Htu: "https://staging.mnki.com/v1/verify", BodyHash: BodyHash([]byte("x")), Now: now}); pr.OK || pr.Reason != "body_hash" {
		t.Fatalf("tampered body accepted: %+v", pr)
	}
	// attestation
	att, _ := SignJWT(org, "org-1", AttestationTyp, AttestationJWT{Iss: "org_acme", Sub: "agt_1", Jti: "aat_1", Iat: now.Unix(), Exp: now.Unix() + 600, Atp: AttestationClaims{V: 1, Organization: "org_acme", Action: "purchase.create", Decision: "ALLOW", Capabilities: child, DelegationChain: []string{"dlg_root"}, DecisionID: "dec_1"}})
	if _, left, reason := VerifyAttestation(att, resolve, now); reason != "" || left != 600 {
		t.Fatalf("attestation: %s %d", reason, left)
	}
	if _, _, reason := VerifyAttestation(att, resolve, now.Add(601*time.Second)); reason != "expired" {
		t.Fatalf("expired attestation accepted: %s", reason)
	}
}

package verifier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

type cryptoVector struct {
	ID    string                    `json:"id"`
	Level int                       `json:"level"`
	Title string                    `json:"title"`
	Now   string                    `json:"now"`
	Keys  map[string]map[string]JWK `json:"keys"`
	Case  *struct {
		Kind      string         `json:"kind"`
		Tokens    []string       `json:"tokens"`
		Proof     string         `json:"proof"`
		AgentKeys map[string]JWK `json:"agent_keys"`
		Htm, Htu  string
		BodyHash  string `json:"body_hash"`
		Token     string `json:"token"`
	} `json:"case"`
	World *struct {
		vectorWorld
		Peers []struct {
			EntityID   string `json:"entity_id"`
			Name       string `json:"name"`
			TrustLevel int    `json:"trust_level"`
		} `json:"peers"`
	} `json:"world"`
	Request map[string]any  `json:"request"`
	Expect  json.RawMessage `json:"expect"`
}

func TestConformanceCryptoVectors(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "conformance", "crypto", "*.json"))
	if len(files) < 17 {
		t.Fatalf("expected the level 2/3 vector set, found %d", len(files))
	}
	sort.Strings(files)
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		var v cryptoVector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		t.Run(v.ID+" "+v.Title, func(t *testing.T) {
			now := ParseISO(v.Now)
			resolve := func(kid, iss string) *JWK {
				if k, ok := v.Keys[iss][kid]; ok {
					return &k
				}
				return nil
			}
			var e map[string]any
			_ = json.Unmarshal(v.Expect, &e)
			want := func(k string) any { return e[k] }
			if v.Case != nil {
				switch v.Case.Kind {
				case "delegation_chain":
					r := VerifyDelegationChain(v.Case.Tokens, resolve, now)
					if r.OK != want("ok").(bool) {
						t.Fatalf("ok=%v reason=%s at=%d", r.OK, r.Reason, r.At)
					}
					if r.OK {
						wc, _ := json.Marshal(want("chain"))
						gc, _ := json.Marshal(r.Chain)
						if string(wc) != string(gc) || r.Subject != want("subject").(string) {
							t.Fatalf("chain %s subject %s", gc, r.Subject)
						}
					} else if r.Reason != want("reason").(string) || float64(r.At) != want("at").(float64) {
						t.Fatalf("reason %s at %d", r.Reason, r.At)
					}
				case "request_proof":
					r := VerifyRequestProof(ProofInput{Proof: v.Case.Proof, ResolveKey: func(kid string) *JWK {
						if k, ok := v.Case.AgentKeys[kid]; ok {
							return &k
						}
						return nil
					}, Htm: v.Case.Htm, Htu: v.Case.Htu, BodyHash: v.Case.BodyHash, Now: now})
					if r.OK != want("ok").(bool) {
						t.Fatalf("ok=%v reason=%s", r.OK, r.Reason)
					}
					if r.OK {
						if r.Claims.Iss != want("iss").(string) || r.Alg != want("alg").(string) {
							t.Fatalf("iss %s alg %s", r.Claims.Iss, r.Alg)
						}
					} else if r.Reason != want("reason").(string) {
						t.Fatalf("reason %s", r.Reason)
					}
				case "attestation":
					p, left, reason := VerifyAttestation(v.Case.Token, resolve, now)
					if (reason == "") != want("ok").(bool) {
						t.Fatalf("reason=%q", reason)
					}
					if reason == "" {
						if p.Sub != want("sub").(string) || p.Atp.Action != want("action").(string) || float64(left) != want("expires_in").(float64) {
							t.Fatalf("sub %s action %s left %d", p.Sub, p.Atp.Action, left)
						}
					} else if reason != want("reason").(string) {
						t.Fatalf("reason %s", reason)
					}
				}
				return
			}
			// level 3
			deps := depsFrom(v.World.vectorWorld)
			deps.GetOrgKey = resolve
			deps.GetFederatedIssuer = func(iss string) *FederatedIssuer {
				for _, p := range v.World.Peers {
					if p.EntityID == iss {
						return &FederatedIssuer{Name: p.Name, TrustLevel: p.TrustLevel}
					}
				}
				return nil
			}
			req, bad := ParseVerifyRequest(v.Request)
			if bad != "" {
				t.Fatal(bad)
			}
			r := Verify(req, deps, Options{Now: now})
			if r.Decision != want("decision").(string) {
				t.Fatalf("decision %s (%v)", r.Decision, r.Reasons)
			}
			if inc, ok := want("reasons_include").([]any); ok {
				for _, x := range inc {
					found := false
					for _, rr := range r.Reasons {
						if rr == x.(string) {
							found = true
						}
					}
					if !found {
						t.Errorf("missing reason %v in %v", x, r.Reasons)
					}
				}
			}
			if ev, ok := want("evidence").(map[string]any); ok {
				for step, status := range ev {
					got := ""
					for _, x := range r.Evidence {
						if x.Step == step {
							got = x.Status
							break
						}
					}
					if got != status.(string) {
						t.Errorf("step %s: %q want %q", step, got, status)
					}
				}
			}
		})
	}
}

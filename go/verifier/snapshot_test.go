package verifier

import (
	"encoding/json"
	"testing"
)

const miniSnapshot = `{
  "v": 1, "org_id": "org_x", "at": "2026-09-14T12:00:00Z",
  "agents": [{"id":"agt_1","stable_id":"spiffe://acme.corp/agent/proc","name":"proc","lifecycle":"active","risk_tier":"low","owner_principal_id":"prn_1","labels":{}}],
  "credentials": [{"id":"crd_1","agent_id":"agt_1","kind":"jwt_svid","status":"active","not_after":"2027-01-01T00:00:00Z","issuer":"internal-ca.acme.corp","kid":null,"jwk":null}],
  "principals": [{"id":"prn_1","display_name":"Maria Chen","kind":"user"}],
  "delegations": [{"id":"dlg_root","parent_id":null,"subject_agent_id":"agt_1","capabilities":[{"action":"purchase.create","resource":"supplier:*","constraints":{"max_value":5000,"currency":"EUR","region":["EU"]}}],"not_after":"2027-01-01T00:00:00Z","status":"active","created_at":"2026-09-01T00:00:00Z"}],
  "capabilities": [], "revocations": [], "attestations": [],
  "policies": [{"version_id":"pv_1","hash":"h","doc":{"version":1,"rules":[{"id":"cap","match":{"action":"purchase.create"},"conditions":[{"kind":"amount_gt","value":3000}],"effect":"require_approval"}]}}],
  "settings": {"policyDefault":"allow","maxDelegationDepth":8,"approvalRiskTiers":[],"attestationRiskTiers":[],"enforceTrustedIssuers":true,"requireSignedRequests":false},
  "anchors": {"issuers":[],"trustDomains":["spiffe://acme.corp"]},
  "keys": [], "revoked_attestations": [], "peers": []
}`

func TestSnapshotDeps(t *testing.T) {
	var s Snapshot
	if err := json.Unmarshal([]byte(miniSnapshot), &s); err != nil {
		t.Fatal(err)
	}
	deps := SnapshotDeps(s)
	now := ParseISO("2026-09-14T12:00:00Z")
	req := func(amount float64) VerifyRequest {
		a := amount
		return VerifyRequest{Agent: "proc", Action: "purchase.create", Resource: strp("supplier:4711"), Amount: &a, Currency: strp("EUR"), Context: map[string]any{"region": "EU"}}
	}
	for _, tc := range []struct {
		amount float64
		want   string
	}{{2450, Allow}, {3200, RequireApproval}, {9000, Deny}} {
		if r := Verify(req(tc.amount), deps, Options{Now: now}); r.Decision != tc.want {
			t.Fatalf("amount %v: %s (%v)", tc.amount, r.Decision, r.Reasons)
		}
	}
	// issuer enforcement through the SPIFFE trust domain
	if !deps.IsTrustedIssuer(strp("internal-ca.acme.corp")) || deps.IsTrustedIssuer(strp("https://evil.example")) {
		t.Fatal("issuer trust")
	}
	s.Settings.ApprovalRiskTiers = []string{"low"}
	if r := Verify(req(100), SnapshotDeps(s), Options{Now: now}); r.Decision != RequireApproval {
		t.Fatalf("org default not applied: %s %v", r.Decision, r.Reasons)
	}
}

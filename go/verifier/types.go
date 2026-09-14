// Package verifier is the Go reference implementation of the Agent Trust Profile v0.1
// verification core — a deterministic function of its inputs, no I/O beyond the injected Deps.
// It mirrors packages/verifier (TypeScript) step for step and passes the same conformance vectors.
package verifier

import "time"

// Constraints are machine-readable limits on a capability. Known keys: max_value, max_total
// (numbers), currency (string), region ([]string). Unknown keys are carried and compared for equality.
type Constraints map[string]any

// Capability is one unit of authority.
type Capability struct {
	Action      string      `json:"action"`
	Resource    string      `json:"resource"`
	Constraints Constraints `json:"constraints,omitempty"`
}

// CapSet is a set of capabilities.
type CapSet []Capability

// Delegation is one link of an authority chain.
type Delegation struct {
	ID             string      `json:"id"`
	ParentID       *string     `json:"parent_id"`
	SubjectAgentID string      `json:"subject_agent_id"`
	Capabilities   CapSet      `json:"capabilities"`
	Constraints    Constraints `json:"constraints,omitempty"`
	NotBefore      *string     `json:"not_before,omitempty"`
	NotAfter       *string     `json:"not_after,omitempty"`
	Status         string      `json:"status"` // active | expired | revoked
}

// VerifyRequest is the untrusted input, after parsing.
type VerifyRequest struct {
	Agent        string         `json:"agent"`
	Action       string         `json:"action"`
	Resource     *string        `json:"resource,omitempty"`
	Principal    *string        `json:"principal,omitempty"`
	DelegationID *string        `json:"delegation_id,omitempty"`
	Amount       *float64       `json:"amount,omitempty"`
	Currency     *string        `json:"currency,omitempty"`
	Context      map[string]any `json:"context,omitempty"`
	Attestation  *string        `json:"attestation,omitempty"`
}

// Decision outcomes.
const (
	Allow           = "ALLOW"
	Deny            = "DENY"
	RequireApproval = "REQUIRE_APPROVAL"
)

// AgentInfo, CredentialInfo, PrincipalInfo, AttestationInfo, ActivePolicy: what Deps return.
type AgentInfo struct {
	ID               string            `json:"id"`
	StableID         string            `json:"stable_id"`
	Lifecycle        string            `json:"lifecycle"`
	RiskTier         string            `json:"risk_tier"`
	OwnerPrincipalID *string           `json:"owner_principal_id"`
	Labels           map[string]string `json:"labels"`
}
type CredentialInfo struct {
	ID       string  `json:"id"`
	Kind     string  `json:"kind"`
	Status   string  `json:"status"`
	NotAfter *string `json:"not_after"`
	Issuer   *string `json:"issuer,omitempty"`
}
type PrincipalInfo struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Kind        string `json:"kind"`
}
type AttestationInfo struct {
	ID        string  `json:"id"`
	Kind      string  `json:"kind"`
	Verified  bool    `json:"verified"`
	ExpiresAt *string `json:"expires_at"`
}
type ActivePolicy struct {
	VersionID *string   `json:"version_id"`
	Hash      *string   `json:"hash"`
	Doc       PolicyDoc `json:"doc"`
}

// ParseISO parses the ISO-8601 timestamps used throughout the profile. Zero time when unparsable.
func ParseISO(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z07:00", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func strp(s string) *string { return &s }

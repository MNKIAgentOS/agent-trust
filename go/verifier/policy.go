package verifier

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Effect ranks: deny > require_approval > allow.
var effectRank = map[string]int{"allow": 0, "require_approval": 1, "deny": 2}

// Condition of a policy rule.
type Condition struct {
	Kind        string   `json:"kind"`
	Value       float64  `json:"value,omitempty"`
	Values      []string `json:"values,omitempty"`
	Attestation string   `json:"attestation,omitempty"`
	Start       string   `json:"start,omitempty"`
	End         string   `json:"end,omitempty"`
}

// RuleMatch selects the requests a rule applies to.
type RuleMatch struct {
	Action      any               `json:"action,omitempty"` // string or []string; trailing-* prefix
	Resource    *string           `json:"resource,omitempty"`
	RiskTier    []string          `json:"risk_tier,omitempty"`
	AgentLabels map[string]string `json:"agent_labels,omitempty"`
}

// Rule fires when match and every condition hold.
type Rule struct {
	ID          string      `json:"id"`
	Description string      `json:"description,omitempty"`
	Match       *RuleMatch  `json:"match,omitempty"`
	Conditions  []Condition `json:"conditions,omitempty"`
	Effect      string      `json:"effect"`
}

// PolicyDoc is the policy document (version 1).
type PolicyDoc struct {
	Version int    `json:"version"`
	Default string `json:"default,omitempty"`
	Rules   []Rule `json:"rules"`
}

// PolicyInput is what a rule is evaluated against.
type PolicyInput struct {
	Action          string
	Resource        *string
	Amount          *float64
	Currency        *string
	Region          *string
	RiskTier        string
	AgentLabels     map[string]string
	DelegationDepth int
	Attestations    []string
	Time            time.Time
}

// PolicyOutcome of Evaluate.
type PolicyOutcome struct {
	Effect  string
	Fired   []string
	Reasons []string
}

// ParsePolicyDoc validates untrusted JSON. Never panics.
func ParsePolicyDoc(raw []byte) (PolicyDoc, string) {
	var d PolicyDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return d, "not_object"
	}
	if d.Version != 1 {
		return d, "version"
	}
	if d.Default != "" {
		if _, ok := effectRank[d.Default]; !ok {
			return d, "default"
		}
	}
	for i, r := range d.Rules {
		if r.ID == "" {
			return d, "rules[" + strconv.Itoa(i) + "].id"
		}
		if _, ok := effectRank[r.Effect]; !ok {
			return d, "rules[" + strconv.Itoa(i) + "].effect"
		}
	}
	return d, ""
}

func actionMatches(pattern any, action string) bool {
	if pattern == nil {
		return true
	}
	var list []string
	switch p := pattern.(type) {
	case string:
		list = []string{p}
	case []string:
		list = p
	case []any:
		for _, x := range p {
			if s, ok := x.(string); ok {
				list = append(list, s)
			}
		}
	}
	for _, p := range list {
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(action, p[:len(p)-1]) {
				return true
			}
		} else if p == action {
			return true
		}
	}
	return false
}

func minutesUTC(t time.Time) int { u := t.UTC(); return u.Hour()*60 + u.Minute() }
func parseHM(s string) int {
	parts := strings.SplitN(s, ":", 2)
	h, _ := strconv.Atoi(parts[0])
	m := 0
	if len(parts) > 1 {
		m, _ = strconv.Atoi(parts[1])
	}
	return h*60 + m
}
func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ConditionHolds evaluates one condition; unknown kinds never hold.
func ConditionHolds(c Condition, i PolicyInput) bool {
	switch c.Kind {
	case "amount_lte":
		return i.Amount != nil && *i.Amount <= c.Value
	case "amount_gt":
		return i.Amount != nil && *i.Amount > c.Value
	case "currency_in":
		return i.Currency != nil && contains(c.Values, *i.Currency)
	case "region_in":
		return i.Region != nil && contains(c.Values, *i.Region)
	case "requires_attestation":
		if c.Attestation != "" {
			return contains(i.Attestations, c.Attestation)
		}
		return len(i.Attestations) > 0
	case "missing_attestation":
		if c.Attestation != "" {
			return !contains(i.Attestations, c.Attestation)
		}
		return len(i.Attestations) == 0
	case "delegation_depth_lte":
		return float64(i.DelegationDepth) <= c.Value
	case "delegation_depth_gt":
		return float64(i.DelegationDepth) > c.Value
	case "time_window":
		t, a, b := minutesUTC(i.Time), parseHM(c.Start), parseHM(c.End)
		if a <= b {
			return t >= a && t < b
		}
		return t >= a || t < b
	}
	return false
}

// RuleMatches applies the match block.
func RuleMatches(r Rule, i PolicyInput) bool {
	m := r.Match
	if m == nil {
		return true
	}
	if !actionMatches(m.Action, i.Action) {
		return false
	}
	if m.Resource != nil && (i.Resource == nil || !ResourceContains(*m.Resource, *i.Resource)) {
		return false
	}
	if len(m.RiskTier) > 0 && !contains(m.RiskTier, i.RiskTier) {
		return false
	}
	for k, v := range m.AgentLabels {
		if i.AgentLabels[k] != v {
			return false
		}
	}
	return true
}

// Evaluate is deterministic: same doc + input + clock ⇒ same outcome.
func Evaluate(doc PolicyDoc, in PolicyInput) PolicyOutcome {
	out := PolicyOutcome{Fired: []string{}, Reasons: []string{}}
	effect := ""
	for _, r := range doc.Rules {
		if !RuleMatches(r, in) {
			continue
		}
		hold := true
		for _, c := range r.Conditions {
			if !ConditionHolds(c, in) {
				hold = false
				break
			}
		}
		if !hold {
			continue
		}
		out.Fired = append(out.Fired, r.ID)
		out.Reasons = append(out.Reasons, "policy:"+r.ID+":"+r.Effect)
		if effect == "" || effectRank[r.Effect] > effectRank[effect] {
			effect = r.Effect
		}
	}
	if effect == "" {
		effect = doc.Default
		if effect == "" {
			effect = "allow"
		}
		out.Reasons = append(out.Reasons, "policy:default:"+effect)
	}
	out.Effect = effect
	return out
}

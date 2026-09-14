package verifier

import (
	"regexp"
	"strings"
)

var currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)
var jwsRe = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

func nonEmpty(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" || len(s) > 512 {
		return "", false
	}
	return strings.TrimSpace(s), true
}

// ParseVerifyRequest validates an untrusted request; the second value is the failing field ("" when ok).
func ParseVerifyRequest(o map[string]any) (VerifyRequest, string) {
	var r VerifyRequest
	if o == nil {
		return r, "not_object"
	}
	var ok bool
	if r.Agent, ok = nonEmpty(o["agent"]); !ok {
		return r, "agent"
	}
	if r.Action, ok = nonEmpty(o["action"]); !ok {
		return r, "action"
	}
	for _, f := range []struct {
		key string
		dst **string
	}{{"resource", &r.Resource}, {"principal", &r.Principal}, {"delegation_id", &r.DelegationID}} {
		if v, present := o[f.key]; present && v != nil {
			s, ok := nonEmpty(v)
			if !ok {
				return r, f.key
			}
			*f.dst = strp(s)
		}
	}
	if v, present := o["amount"]; present && v != nil {
		f, ok := asFloat(v)
		if !ok || f < 0 {
			return r, "amount"
		}
		r.Amount = &f
	}
	if v, present := o["currency"]; present && v != nil {
		s, ok := v.(string)
		if !ok || !currencyRe.MatchString(s) {
			return r, "currency"
		}
		r.Currency = strp(s)
	}
	if v, present := o["attestation"]; present && v != nil {
		s, ok := v.(string)
		if !ok || !jwsRe.MatchString(s) || len(s) > 16384 {
			return r, "attestation"
		}
		r.Attestation = strp(s)
	}
	if v, present := o["context"]; present && v != nil {
		m, ok := v.(map[string]any)
		if !ok {
			return r, "context"
		}
		r.Context = m
	}
	return r, ""
}

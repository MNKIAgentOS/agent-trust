package verifier

import (
	"encoding/json"
	"reflect"
	"strings"
)

func globPrefix(resource string) (string, bool) {
	if strings.HasSuffix(resource, "*") {
		return resource[:len(resource)-1], true
	}
	return "", false
}

// ResourceContains reports whether the parent resource pattern covers the child. Only a trailing "*" is a glob.
func ResourceContains(parent, child string) bool {
	if parent == child {
		return true
	}
	pp, ok := globPrefix(parent)
	if !ok {
		return false
	}
	cp, cok := globPrefix(child)
	if !cok {
		cp = child
	}
	return strings.HasPrefix(cp, pp)
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func asStrings(v any) ([]string, bool) {
	switch s := v.(type) {
	case []string:
		return s, true
	case []any:
		out := make([]string, 0, len(s))
		for _, x := range s {
			str, ok := x.(string)
			if !ok {
				return nil, false
			}
			out = append(out, str)
		}
		return out, true
	}
	return nil, false
}

// ConstraintsTighter: are the child's constraints at least as tight as the parent's?
func ConstraintsTighter(parent, child Constraints) bool {
	if parent == nil {
		return true
	}
	if child == nil {
		child = Constraints{}
	}
	for key, p := range parent {
		if p == nil {
			continue
		}
		switch key {
		case "max_value", "max_total":
			pv, _ := asFloat(p)
			cv, ok := asFloat(child[key])
			if !ok || !(cv <= pv) {
				return false
			}
		case "region":
			pr, _ := asStrings(p)
			set := map[string]bool{}
			for _, r := range pr {
				set[r] = true
			}
			cr, ok := asStrings(child["region"])
			if !ok || len(cr) == 0 {
				return false
			}
			for _, r := range cr {
				if !set[r] {
					return false
				}
			}
		default:
			if !jsonEqual(child[key], p) {
				return false
			}
		}
	}
	return true
}

func jsonEqual(a, b any) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	ja, ea := json.Marshal(a)
	jb, eb := json.Marshal(b)
	return ea == nil && eb == nil && string(ja) == string(jb)
}

// CapabilityCovered: is child covered by parent?
func CapabilityCovered(parent, child Capability) bool {
	return parent.Action == child.Action && ResourceContains(parent.Resource, child.Resource) && ConstraintsTighter(parent.Constraints, child.Constraints)
}

// IsSubset: every child capability is covered by some parent capability.
func IsSubset(child, parent CapSet) bool {
	for _, c := range child {
		covered := false
		for _, p := range parent {
			if CapabilityCovered(p, c) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// Attenuate keeps only the requested capabilities the parent covers.
func Attenuate(parent, requested CapSet) CapSet {
	out := CapSet{}
	for _, c := range requested {
		for _, p := range parent {
			if CapabilityCovered(p, c) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

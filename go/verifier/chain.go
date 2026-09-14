package verifier

import "time"

// MaxChainDepth is the hard ceiling on delegation chain length.
const MaxChainDepth = 8

// ChainResult is the outcome of ResolveChain.
type ChainResult struct {
	OK     bool
	Chain  []Delegation // root → leaf
	Reason string       // missing | cycle | depth
	At     string
}

// ResolveChain walks parent links from the leaf to the root. Bounded, cycle-safe.
func ResolveChain(leafID string, get func(id string) *Delegation, maxDepth int) ChainResult {
	if maxDepth <= 0 {
		maxDepth = MaxChainDepth
	}
	seen := map[string]bool{}
	chain := []Delegation{}
	cursor := &leafID
	for cursor != nil {
		id := *cursor
		if seen[id] {
			return ChainResult{Reason: "cycle", At: id}
		}
		if len(chain) >= maxDepth {
			return ChainResult{Reason: "depth", At: id}
		}
		d := get(id)
		if d == nil {
			return ChainResult{Reason: "missing", At: id}
		}
		seen[id] = true
		chain = append(chain, *d)
		cursor = d.ParentID
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return ChainResult{OK: true, Chain: chain}
}

// LinkValidAt: a link confers authority only while active and inside its validity window.
func LinkValidAt(d Delegation, now time.Time) bool {
	if d.Status != "active" {
		return false
	}
	if d.NotBefore != nil && now.Before(ParseISO(*d.NotBefore)) {
		return false
	}
	if d.NotAfter != nil && !now.Before(ParseISO(*d.NotAfter)) {
		return false
	}
	return true
}

// ComputeEffectiveAuthority: the root's capabilities attenuated through every link; any invalid link yields none.
func ComputeEffectiveAuthority(chain []Delegation, now time.Time) CapSet {
	if len(chain) == 0 {
		return CapSet{}
	}
	for _, d := range chain {
		if !LinkValidAt(d, now) {
			return CapSet{}
		}
	}
	eff := chain[0].Capabilities
	for i := 1; i < len(chain); i++ {
		eff = Attenuate(eff, chain[i].Capabilities)
	}
	return eff
}

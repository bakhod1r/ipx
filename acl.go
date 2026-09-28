package ipx

import (
	"net/netip"
	"slices"
	"sync"
)

// Action is an ACL verdict.
type Action uint8

const (
	Deny Action = iota
	Allow
)

func (a Action) String() string {
	if a == Allow {
		return "allow"
	}
	return "deny"
}

// Strategy selects how an ACL picks among matching rules.
type Strategy uint8

const (
	// LongestPrefix: the most specific matching prefix wins; among equal
	// prefixes the lowest Priority value wins.
	LongestPrefix Strategy = iota
	// FirstMatch: rules are evaluated by ascending Priority (then insertion
	// order); the first match wins.
	FirstMatch
)

// Rule is one ACL entry.
type Rule struct {
	Prefix   netip.Prefix
	Action   Action
	Priority int    // lower is evaluated first
	Group    string // free-form label, e.g. "office", "cloud-metadata"
}

// ACL is an allow/deny list. Safe for concurrent use.
type ACL struct {
	mu       sync.RWMutex
	strategy Strategy
	def      Action
	rules    []Rule
	seq      []int
}

// NewACL returns an ACL returning def when no rule matches.
func NewACL(s Strategy, def Action) *ACL { return &ACL{strategy: s, def: def} }

// Allowlist denies everything except the given networks.
func Allowlist(ps ...netip.Prefix) *ACL {
	a := NewACL(LongestPrefix, Deny)
	for _, p := range ps {
		a.Add(Rule{Prefix: p, Action: Allow})
	}
	return a
}

// Denylist allows everything except the given networks.
func Denylist(ps ...netip.Prefix) *ACL {
	a := NewACL(LongestPrefix, Allow)
	for _, p := range ps {
		a.Add(Rule{Prefix: p, Action: Deny})
	}
	return a
}

// Add appends a rule; invalid prefixes are rejected.
func (a *ACL) Add(r Rule) error {
	r.Prefix = NormalizePrefix(r.Prefix)
	if !r.Prefix.IsValid() {
		return ErrInvalidPrefix
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rules = append(a.rules, r)
	a.seq = append(a.seq, len(a.seq))
	return nil
}

// RemoveGroup deletes all rules in group and returns how many.
func (a *ACL) RemoveGroup(group string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for i := 0; i < len(a.rules); {
		if a.rules[i].Group == group {
			a.rules = slices.Delete(a.rules, i, i+1)
			a.seq = slices.Delete(a.seq, i, i+1)
			n++
			continue
		}
		i++
	}
	return n
}

// Rules returns a copy of the rules in insertion order.
func (a *ACL) Rules() []Rule {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return slices.Clone(a.rules)
}

// Match returns the deciding rule for addr; ok is false if the default applied.
func (a *ACL) Match(addr netip.Addr) (Rule, bool) {
	addr = Normalize(addr)
	a.mu.RLock()
	defer a.mu.RUnlock()
	best := -1
	for i, r := range a.rules {
		if !r.Prefix.Contains(addr) {
			continue
		}
		if best < 0 || a.better(i, best) {
			best = i
		}
	}
	if best < 0 {
		return Rule{}, false
	}
	return a.rules[best], true
}

func (a *ACL) better(i, j int) bool {
	ri, rj := a.rules[i], a.rules[j]
	if a.strategy == LongestPrefix && ri.Prefix.Bits() != rj.Prefix.Bits() {
		return ri.Prefix.Bits() > rj.Prefix.Bits()
	}
	if ri.Priority != rj.Priority {
		return ri.Priority < rj.Priority
	}
	return a.seq[i] < a.seq[j]
}

// Decide returns the verdict for addr. Invalid addresses are always denied.
func (a *ACL) Decide(addr netip.Addr) Action {
	if !addr.IsValid() {
		return Deny
	}
	if r, ok := a.Match(addr); ok {
		return r.Action
	}
	return a.def
}

// Allowed is Decide(addr) == Allow.
func (a *ACL) Allowed(addr netip.Addr) bool { return a.Decide(addr) == Allow }

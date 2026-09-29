package ipx

import (
	"net/netip"
	"slices"
)

// Overlap is a pair of overlapping prefixes; Outer contains Inner (they are
// equal for duplicates). CIDR blocks never partially overlap.
type Overlap struct {
	Outer, Inner netip.Prefix
}

// FindOverlaps reports every overlapping pair in ps (duplicates included),
// sorted by Outer then Inner. Inputs are normalized; invalid ones skipped.
// O(n log n + k) for k reported pairs.
func FindOverlaps(ps []netip.Prefix) []Overlap {
	sorted := normalizedSorted(ps)
	var (
		out   []Overlap //nolint:prealloc // pair count unknown up front
		stack []netip.Prefix
	)
	for _, p := range sorted {
		for len(stack) > 0 && !ContainsPrefix(stack[len(stack)-1], p) {
			stack = stack[:len(stack)-1]
		}
		for _, s := range stack {
			out = append(out, Overlap{s, p})
		}
		stack = append(stack, p)
	}
	slices.SortFunc(out, func(a, b Overlap) int {
		if c := ComparePrefix(a.Outer, b.Outer); c != 0 {
			return c
		}
		return ComparePrefix(a.Inner, b.Inner)
	})
	return out
}

func normalizedSorted(ps []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		if p = NormalizePrefix(p); p.IsValid() {
			out = append(out, p)
		}
	}
	SortPrefixes(out)
	return out
}

// PrefixNode is one network in a hierarchy built by BuildTree.
type PrefixNode struct {
	Prefix   netip.Prefix
	Children []*PrefixNode
}

// BuildTree arranges prefixes into a containment forest: each node's
// children are the largest prefixes it directly contains. Duplicates are
// merged; roots and children are in address order.
func BuildTree(ps []netip.Prefix) []*PrefixNode {
	sorted := slices.Compact(normalizedSorted(ps))
	var (
		roots []*PrefixNode
		stack []*PrefixNode
	)
	for _, p := range sorted {
		n := &PrefixNode{Prefix: p}
		for len(stack) > 0 && !ContainsPrefix(stack[len(stack)-1].Prefix, p) {
			stack = stack[:len(stack)-1]
		}
		if len(stack) == 0 {
			roots = append(roots, n)
		} else {
			parent := stack[len(stack)-1]
			parent.Children = append(parent.Children, n)
		}
		stack = append(stack, n)
	}
	return roots
}

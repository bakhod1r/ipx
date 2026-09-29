package ipx

import (
	"iter"
	"math/big"
	"net/netip"
	"slices"
	"strings"
)

// IPSet is an immutable set of addresses stored as sorted, merged ranges.
// The zero value is the empty set. All operations return new sets, so an
// IPSet is safe for concurrent use.
//
// Inputs are normalized: IPv4-mapped IPv6 is treated as IPv4, zones dropped.
type IPSet struct {
	rs []Range // canonical: sorted, non-overlapping, non-adjacent
}

// NewIPSet builds a set from any mix of addresses, prefixes and ranges.
func NewIPSet(items ...any) *IPSet {
	var b Builder
	for _, it := range items {
		switch v := it.(type) {
		case netip.Addr:
			b.AddAddr(v)
		case netip.Prefix:
			b.AddPrefix(v)
		case Range:
			b.AddRange(v)
		case []netip.Addr:
			for _, a := range v {
				b.AddAddr(a)
			}
		case []netip.Prefix:
			for _, p := range v {
				b.AddPrefix(p)
			}
		case []Range:
			for _, r := range v {
				b.AddRange(r)
			}
		case *IPSet:
			b.AddSet(v)
		}
	}
	return b.IPSet()
}

// ParseIPSet parses a comma/space separated list of addresses, CIDRs and
// "a-b" ranges.
func ParseIPSet(s string) (*IPSet, error) {
	var b Builder
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		r, err := ParseRange(f)
		if err != nil {
			return nil, err
		}
		b.AddRange(r)
	}
	return b.IPSet(), nil
}

// Builder accumulates items for an IPSet. Not safe for concurrent use.
type Builder struct {
	add, remove []Range
}

func (b *Builder) AddAddr(a netip.Addr) {
	if r, err := NewRange(a, a); err == nil {
		b.add = append(b.add, r)
	}
}
func (b *Builder) AddPrefix(p netip.Prefix) {
	if r := RangeOf(p); r.IsValid() {
		b.add = append(b.add, r)
	}
}
func (b *Builder) AddRange(r Range) {
	if r.IsValid() {
		b.add = append(b.add, r)
	}
}
func (b *Builder) AddSet(s *IPSet) {
	if s != nil {
		b.add = append(b.add, s.rs...)
	}
}

// Remove* calls apply after all adds when IPSet is called.
func (b *Builder) RemoveAddr(a netip.Addr) {
	if r, err := NewRange(a, a); err == nil {
		b.remove = append(b.remove, r)
	}
}
func (b *Builder) RemovePrefix(p netip.Prefix) {
	if r := RangeOf(p); r.IsValid() {
		b.remove = append(b.remove, r)
	}
}
func (b *Builder) RemoveRange(r Range) {
	if r.IsValid() {
		b.remove = append(b.remove, r)
	}
}
func (b *Builder) RemoveSet(s *IPSet) {
	if s != nil {
		b.remove = append(b.remove, s.rs...)
	}
}

// IPSet returns the built set. The builder can keep being used.
func (b *Builder) IPSet() *IPSet {
	s := &IPSet{rs: MergeRanges(b.add)}
	if len(b.remove) > 0 {
		s = s.Difference(&IPSet{rs: MergeRanges(b.remove)})
	}
	return s
}

func (s *IPSet) ranges() []Range {
	if s == nil {
		return nil
	}
	return s.rs
}

// Ranges returns a copy of the canonical ranges.
func (s *IPSet) Ranges() []Range { return slices.Clone(s.ranges()) }

// Prefixes returns the minimal sorted CIDR list covering the set.
func (s *IPSet) Prefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, r := range s.ranges() {
		out = appendRangePrefixes(out, r)
	}
	return out
}

// IsEmpty reports whether the set has no addresses.
func (s *IPSet) IsEmpty() bool { return len(s.ranges()) == 0 }

// Equal reports whether both sets hold the same addresses.
func (s *IPSet) Equal(o *IPSet) bool { return slices.Equal(s.ranges(), o.ranges()) }

// Size returns the number of addresses.
func (s *IPSet) Size() *big.Int {
	n := new(big.Int)
	for _, r := range s.ranges() {
		n.Add(n, r.Size())
	}
	return n
}

// Contains reports whether a is in the set. O(log n).
func (s *IPSet) Contains(a netip.Addr) bool {
	if a.Is4In6() || a.Zone() != "" {
		a = Normalize(a)
	}
	rs := s.ranges()
	i := s.index(a)
	return i < len(rs) && a.IsValid() && !a.Less(rs[i].from) && rs[i].from.Is4() == a.Is4()
}

// ContainsPrefix reports whether all of p is in the set.
func (s *IPSet) ContainsPrefix(p netip.Prefix) bool { return s.ContainsRange(RangeOf(p)) }

// ContainsRange reports whether all of r is in the set.
func (s *IPSet) ContainsRange(r Range) bool {
	if !r.IsValid() {
		return false
	}
	rs := s.ranges()
	i := s.index(r.from)
	return i < len(rs) && rs[i].ContainsRange(r)
}

// index returns the position of the range containing a, or where it would be.
func (s *IPSet) index(a netip.Addr) int {
	rs := s.ranges()
	// First range whose end is ≥ a; one comparison per step.
	lo, hi := 0, len(rs)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if rs[m].to.Less(a) {
			lo = m + 1
		} else {
			hi = m
		}
	}
	return lo
}

// MarshalText encodes the set as its comma-separated prefix list.
func (s *IPSet) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText accepts anything ParseIPSet accepts.
func (s *IPSet) UnmarshalText(b []byte) error {
	v, err := ParseIPSet(string(b))
	if err != nil {
		return err
	}
	*s = *v
	return nil
}

// Overlaps reports whether the sets share any address.
func (s *IPSet) Overlaps(o *IPSet) bool { return !s.Intersect(o).IsEmpty() }

// Union returns s ∪ o.
func (s *IPSet) Union(o *IPSet) *IPSet {
	return &IPSet{rs: MergeRanges(append(slices.Clone(s.ranges()), o.ranges()...))}
}

// Intersect returns s ∩ o.
func (s *IPSet) Intersect(o *IPSet) *IPSet {
	a, b := s.ranges(), o.ranges()
	var out []Range
	for i, j := 0, 0; i < len(a) && j < len(b); {
		if x, ok := a[i].Intersect(b[j]); ok {
			out = append(out, x)
		}
		if a[i].to.Compare(b[j].to) < 0 {
			i++
		} else {
			j++
		}
	}
	return &IPSet{rs: out}
}

// Difference returns s \ o.
func (s *IPSet) Difference(o *IPSet) *IPSet {
	b := o.ranges()
	var out []Range
	j := 0
	for _, r := range s.ranges() {
		cur := []Range{r}
		for j < len(b) && b[j].to.Compare(r.from) < 0 {
			j++
		}
		for k := j; k < len(b) && b[k].from.Compare(r.to) <= 0 && len(cur) > 0; k++ {
			last := cur[len(cur)-1]
			cur = append(cur[:len(cur)-1], last.Subtract(b[k])...)
		}
		out = append(out, cur...)
	}
	return &IPSet{rs: out}
}

// SymmetricDifference returns (s \ o) ∪ (o \ s).
func (s *IPSet) SymmetricDifference(o *IPSet) *IPSet {
	return s.Difference(o).Union(o.Difference(s))
}

var (
	allIPv4 = Range{netip.IPv4Unspecified(), netip.AddrFrom4([4]byte{255, 255, 255, 255})}
	allIPv6 = Range{netip.IPv6Unspecified(), fromU128(u128Max, false)}
)

// Complement returns every address (IPv4 and IPv6) not in s.
func (s *IPSet) Complement() *IPSet {
	return (&IPSet{rs: []Range{allIPv4, allIPv6}}).Difference(s)
}

// All lazily yields every address in the set.
func (s *IPSet) All() iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		for _, r := range s.ranges() {
			for a := range r.All() {
				if !yield(a) {
					return
				}
			}
		}
	}
}

// String lists the set's prefixes, comma-separated.
func (s *IPSet) String() string {
	ps := s.Prefixes()
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, ", ")
}

// Aggregate returns the minimal CIDR list covering all input prefixes:
// merges adjacent blocks, removes nested/duplicate ones and sorts.
func Aggregate(ps []netip.Prefix) []netip.Prefix { return NewIPSet(ps).Prefixes() }

// AggregateAddrs returns the minimal CIDR list covering the addresses.
func AggregateAddrs(as []netip.Addr) []netip.Prefix { return NewIPSet(as).Prefixes() }

// SubtractPrefixes returns the minimal CIDR list for from \ remove.
func SubtractPrefixes(from, remove []netip.Prefix) []netip.Prefix {
	return NewIPSet(from).Difference(NewIPSet(remove)).Prefixes()
}

// IntersectPrefix returns a ∩ b as a prefix (the longer one) if they overlap.
func IntersectPrefix(a, b netip.Prefix) (netip.Prefix, bool) {
	switch {
	case ContainsPrefix(a, b):
		return b.Masked(), true
	case ContainsPrefix(b, a):
		return a.Masked(), true
	}
	return netip.Prefix{}, false
}

// ContainsBatch reports membership for each address, in order.
func (s *IPSet) ContainsBatch(as []netip.Addr) []bool {
	out := make([]bool, len(as))
	for i, a := range as {
		out[i] = s.Contains(a)
	}
	return out
}

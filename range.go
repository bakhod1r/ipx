package ipx

import (
	"context"
	"fmt"
	"iter"
	"math/big"
	"net/netip"
	"slices"
	"strings"
)

// Range is an inclusive span of addresses of one family. The zero Range is
// invalid. Build one with NewRange, RangeOf or ParseRange.
type Range struct {
	from, to netip.Addr
}

// NewRange validates and returns [from, to]. Inputs are normalized
// (IPv4-mapped unmapped, zones dropped).
func NewRange(from, to netip.Addr) (Range, error) {
	from, to = Normalize(from), Normalize(to)
	if !from.IsValid() || !to.IsValid() {
		return Range{}, ErrInvalidRange
	}
	if from.Is4() != to.Is4() {
		return Range{}, fmt.Errorf("%w: %s-%s", ErrFamilyMismatch, from, to)
	}
	if from.Compare(to) > 0 {
		return Range{}, fmt.Errorf("%w: %s > %s", ErrInvalidRange, from, to)
	}
	return Range{from, to}, nil
}

// RangeOf returns the address range covered by prefix p.
func RangeOf(p netip.Prefix) Range {
	p = NormalizePrefix(p)
	if !p.IsValid() {
		return Range{}
	}
	return Range{First(p), Last(p)}
}

// ParseRange accepts "a-b", a CIDR, or a single address.
func ParseRange(s string) (Range, error) {
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		a, err := ParseAddr(strings.TrimSpace(lo))
		if err != nil {
			return Range{}, fmt.Errorf("%w: %q", ErrInvalidRange, s)
		}
		b, err := ParseAddr(strings.TrimSpace(hi))
		if err != nil {
			return Range{}, fmt.Errorf("%w: %q", ErrInvalidRange, s)
		}
		return NewRange(a, b)
	}
	p, err := ParseNetwork(s)
	if err != nil {
		return Range{}, fmt.Errorf("%w: %q", ErrInvalidRange, s)
	}
	return RangeOf(p), nil
}

func (r Range) From() netip.Addr { return r.from }
func (r Range) To() netip.Addr   { return r.to }
func (r Range) IsValid() bool    { return r.from.IsValid() }

// String formats as "from-to".
func (r Range) String() string {
	if !r.IsValid() {
		return "invalid Range"
	}
	return r.from.String() + "-" + r.to.String()
}

// MarshalText implements encoding.TextMarshaler.
func (r Range) MarshalText() ([]byte, error) {
	if !r.IsValid() {
		return []byte{}, nil
	}
	return []byte(r.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (r *Range) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*r = Range{}
		return nil
	}
	v, err := ParseRange(string(b))
	if err != nil {
		return err
	}
	*r = v
	return nil
}

// MarshalBinary encodes as from||to raw bytes (8 or 32 bytes).
func (r Range) MarshalBinary() ([]byte, error) {
	if !r.IsValid() {
		return []byte{}, nil
	}
	return append(r.from.AsSlice(), r.to.AsSlice()...), nil
}

// UnmarshalBinary decodes MarshalBinary output.
func (r *Range) UnmarshalBinary(b []byte) error {
	if len(b) == 0 {
		*r = Range{}
		return nil
	}
	if len(b) != 8 && len(b) != 32 {
		return ErrInvalidRange
	}
	from, _ := netip.AddrFromSlice(b[:len(b)/2])
	to, _ := netip.AddrFromSlice(b[len(b)/2:])
	v, err := NewRange(from, to)
	if err != nil {
		return err
	}
	*r = v
	return nil
}

// Size returns the number of addresses.
func (r Range) Size() *big.Int {
	if !r.IsValid() {
		return new(big.Int)
	}
	d, _ := Distance(r.from, r.to)
	return d.Add(d, big.NewInt(1))
}

// Contains reports whether a is inside r (IPv4-mapped input is unmapped).
func (r Range) Contains(a netip.Addr) bool {
	a = Normalize(a)
	return r.IsValid() && a.IsValid() && a.Is4() == r.from.Is4() &&
		r.from.Compare(a) <= 0 && a.Compare(r.to) <= 0
}

// ContainsRange reports whether o lies fully inside r.
func (r Range) ContainsRange(o Range) bool {
	return o.IsValid() && r.Contains(o.from) && r.Contains(o.to)
}

func (r Range) sameFamily(o Range) bool {
	return r.IsValid() && o.IsValid() && r.from.Is4() == o.from.Is4()
}

// Overlaps reports whether r and o share any address.
func (r Range) Overlaps(o Range) bool {
	return r.sameFamily(o) && r.from.Compare(o.to) <= 0 && o.from.Compare(r.to) <= 0
}

// Adjacent reports whether r and o are disjoint and touch.
func (r Range) Adjacent(o Range) bool {
	if !r.sameFamily(o) {
		return false
	}
	if n, err := Next(r.to); err == nil && n == o.from {
		return true
	}
	n, err := Next(o.to)
	return err == nil && n == r.from
}

// Intersect returns the overlap of r and o; false if disjoint.
func (r Range) Intersect(o Range) (Range, bool) {
	if !r.Overlaps(o) {
		return Range{}, false
	}
	return Range{maxAddr(r.from, o.from), minAddr(r.to, o.to)}, true
}

// Merge joins overlapping or adjacent ranges; false if there is a gap.
func (r Range) Merge(o Range) (Range, bool) {
	if !r.Overlaps(o) && !r.Adjacent(o) {
		return Range{}, false
	}
	return Range{minAddr(r.from, o.from), maxAddr(r.to, o.to)}, true
}

// Subtract returns r minus o: zero, one or two ranges.
func (r Range) Subtract(o Range) []Range {
	if !r.IsValid() {
		return nil
	}
	if !r.Overlaps(o) {
		return []Range{r}
	}
	var out []Range
	if r.from.Compare(o.from) < 0 {
		p, _ := Prev(o.from)
		out = append(out, Range{r.from, p})
	}
	if o.to.Compare(r.to) < 0 {
		n, _ := Next(o.to)
		out = append(out, Range{n, r.to})
	}
	return out
}

// Prefix returns the single CIDR equal to r, if one exists.
func (r Range) Prefix() (netip.Prefix, bool) {
	ps := r.Prefixes()
	if len(ps) != 1 {
		return netip.Prefix{}, false
	}
	return ps[0], true
}

// Prefixes returns the minimal list of CIDRs exactly covering r.
func (r Range) Prefixes() []netip.Prefix {
	if !r.IsValid() {
		return nil
	}
	return appendRangePrefixes(nil, r)
}

func appendRangePrefixes(dst []netip.Prefix, r Range) []netip.Prefix {
	is4, w := r.from.Is4(), r.from.BitLen()
	cur, end := toU128(r.from), toU128(r.to)
	for {
		bits := w
		for b := 0; b <= w; b++ {
			hm := hostMask(b, w)
			if cur.and(hm).isZero() && cur.or(hm).cmp(end) <= 0 {
				bits = b
				break
			}
		}
		dst = append(dst, netip.PrefixFrom(fromU128(cur, is4), bits))
		last := cur.or(hostMask(bits, w))
		if last.cmp(end) >= 0 {
			return dst
		}
		cur, _ = last.add(u128{0, 1})
	}
}

// All lazily yields every address in r.
func (r Range) All() iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		if !r.IsValid() {
			return
		}
		for a := r.from; ; {
			if !yield(a) || a == r.to {
				return
			}
			a = a.Next()
		}
	}
}

// Walk calls fn for each address until fn returns false or ctx is done.
// It checks ctx every 1024 addresses and returns ctx.Err() if cancelled.
func (r Range) Walk(ctx context.Context, fn func(netip.Addr) bool) error {
	i := 0
	for a := range r.All() {
		if i++; i&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if !fn(a) {
			return nil
		}
	}
	return ctx.Err()
}

// SplitRange cuts r into chunks of at most n addresses.
func (r Range) SplitRange(n uint64) []Range {
	if !r.IsValid() || n == 0 {
		return nil
	}
	var out []Range
	cur := r.from
	for {
		end, err := Add(cur, int64(min(n-1, 1<<62)))
		if err != nil || end.Compare(r.to) >= 0 {
			return append(out, Range{cur, r.to})
		}
		out = append(out, Range{cur, end})
		cur = end.Next()
	}
}

// CompareRange orders by start, then end.
func CompareRange(a, b Range) int {
	if c := a.from.Compare(b.from); c != 0 {
		return c
	}
	return a.to.Compare(b.to)
}

// MergeRanges sorts, merges overlapping/adjacent ranges and drops invalid
// ones, returning a new canonical slice.
func MergeRanges(rs []Range) []Range {
	in := slices.DeleteFunc(slices.Clone(rs), func(r Range) bool { return !r.IsValid() })
	slices.SortFunc(in, CompareRange)
	out := make([]Range, 0, len(in))
	for _, r := range in {
		if n := len(out); n > 0 {
			if m, ok := out[n-1].Merge(r); ok {
				out[n-1] = m
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

func minAddr(a, b netip.Addr) netip.Addr {
	if a.Compare(b) <= 0 {
		return a
	}
	return b
}

func maxAddr(a, b netip.Addr) netip.Addr {
	if a.Compare(b) >= 0 {
		return a
	}
	return b
}

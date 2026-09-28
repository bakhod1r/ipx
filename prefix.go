package ipx

import (
	"fmt"
	"iter"
	"math/big"
	"net/netip"
	"slices"
)

// First returns the network address of p.
func First(p netip.Prefix) netip.Addr { return p.Masked().Addr() }

// Last returns the last address of p (the IPv4 broadcast address).
func Last(p netip.Prefix) netip.Addr {
	a := p.Addr()
	return fromU128(toU128(a).or(hostMask(p.Bits(), a.BitLen())), a.Is4())
}

// Broadcast is Last for IPv4 prefixes; IPv6 has no broadcast so ok is false.
func Broadcast(p netip.Prefix) (netip.Addr, bool) {
	if !p.IsValid() || !p.Addr().Is4() {
		return netip.Addr{}, false
	}
	return Last(p), true
}

// usableBounds reports the first and last usable host. IPv4 /31 and /32
// (RFC 3021) and all IPv6 prefixes use every address.
func usableBounds(p netip.Prefix) (netip.Addr, netip.Addr) {
	f, l := First(p), Last(p)
	if p.Addr().Is4() && p.Bits() <= 30 {
		f, _ = Next(f)
		l, _ = Prev(l)
	}
	return f, l
}

// FirstUsable returns the first assignable host address.
func FirstUsable(p netip.Prefix) netip.Addr { f, _ := usableBounds(p); return f }

// LastUsable returns the last assignable host address.
func LastUsable(p netip.Prefix) netip.Addr { _, l := usableBounds(p); return l }

// Size returns the number of addresses in p (2^(width-bits)).
func Size(p netip.Prefix) *big.Int {
	if !p.IsValid() {
		return new(big.Int)
	}
	return new(big.Int).Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits()))
}

// UsableHosts returns the number of assignable hosts (Size minus network and
// broadcast for IPv4 prefixes shorter than /31).
func UsableHosts(p netip.Prefix) *big.Int {
	n := Size(p)
	if p.IsValid() && p.Addr().Is4() && p.Bits() <= 30 {
		n.Sub(n, big.NewInt(2))
	}
	return n
}

// Netmask returns the subnet mask as an address (255.255.255.0 for /24).
func Netmask(p netip.Prefix) netip.Addr {
	w := p.Addr().BitLen()
	return fromU128(hostMask(p.Bits(), w).not().and(lowOnes(w)), p.Addr().Is4())
}

// Hostmask returns the wildcard mask (0.0.0.255 for /24).
func Hostmask(p netip.Prefix) netip.Addr {
	return fromU128(hostMask(p.Bits(), p.Addr().BitLen()), p.Addr().Is4())
}

// PrefixFromMask builds a prefix from an address and a dotted netmask such
// as 255.255.255.0. Non-contiguous masks are rejected.
func PrefixFromMask(a, mask netip.Addr) (netip.Prefix, error) {
	if !a.IsValid() || !mask.IsValid() || a.Is4() != mask.Is4() {
		return netip.Prefix{}, ErrFamilyMismatch
	}
	w := a.BitLen()
	m := toU128(mask)
	for bits := 0; bits <= w; bits++ {
		if hostMask(bits, w).not().and(lowOnes(w)) == m {
			return netip.PrefixFrom(a, bits).Masked(), nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("%w: non-contiguous mask %s", ErrInvalidPrefix, mask)
}

// ContainsPrefix reports whether outer fully contains inner.
func ContainsPrefix(outer, inner netip.Prefix) bool {
	return outer.IsValid() && inner.IsValid() &&
		outer.Addr().Is4() == inner.Addr().Is4() &&
		outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// ComparePrefix orders prefixes: IPv4 first, then by network address, then
// shorter prefix first. Suitable for slices.SortFunc.
func ComparePrefix(a, b netip.Prefix) int {
	if c := a.Masked().Addr().Compare(b.Masked().Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

// SortPrefixes sorts in place with ComparePrefix.
func SortPrefixes(ps []netip.Prefix) { slices.SortFunc(ps, ComparePrefix) }

// Parent returns the enclosing prefix one bit shorter; false for /0.
func Parent(p netip.Prefix) (netip.Prefix, bool) {
	if !p.IsValid() || p.Bits() == 0 {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(p.Addr(), p.Bits()-1).Masked(), true
}

// Supernet returns the enclosing prefix of the given length.
func Supernet(p netip.Prefix, bits int) (netip.Prefix, error) {
	if !p.IsValid() || bits < 0 || bits > p.Bits() {
		return netip.Prefix{}, fmt.Errorf("%w: cannot widen %s to /%d", ErrInvalidPrefix, p, bits)
	}
	return netip.PrefixFrom(p.Addr(), bits).Masked(), nil
}

// Children returns the two halves of p; false for a host prefix.
func Children(p netip.Prefix) (lo, hi netip.Prefix, ok bool) {
	if !p.IsValid() || p.Bits() == p.Addr().BitLen() {
		return netip.Prefix{}, netip.Prefix{}, false
	}
	p = p.Masked()
	a, w := p.Addr(), p.Addr().BitLen()
	lo = netip.PrefixFrom(a, p.Bits()+1)
	hi = netip.PrefixFrom(fromU128(toU128(a).setBit(p.Bits(), w), a.Is4()), p.Bits()+1)
	return lo, hi, true
}

// Sibling returns the other half of p's parent; false for /0.
func Sibling(p netip.Prefix) (netip.Prefix, bool) {
	par, ok := Parent(p)
	if !ok {
		return netip.Prefix{}, false
	}
	lo, hi, _ := Children(par)
	if lo == p.Masked() {
		return hi, true
	}
	return lo, true
}

// Adjacent reports whether a and b are disjoint and touch end-to-start.
func Adjacent(a, b netip.Prefix) bool {
	return RangeOf(a).Adjacent(RangeOf(b))
}

// CommonPrefix returns the longest prefix containing both addresses.
func CommonPrefix(a, b netip.Addr) (netip.Prefix, error) {
	if !a.IsValid() || !b.IsValid() {
		return netip.Prefix{}, ErrInvalidAddr
	}
	if a.Is4() != b.Is4() {
		return netip.Prefix{}, ErrFamilyMismatch
	}
	w := a.BitLen()
	x, y := toU128(a), toU128(b)
	bits := 0
	for bits < w && x.bit(bits, w) == y.bit(bits, w) {
		bits++
	}
	return netip.PrefixFrom(a.WithZone(""), bits).Masked(), nil
}

// CommonAncestor returns the longest prefix containing every input.
func CommonAncestor(ps ...netip.Prefix) (netip.Prefix, error) {
	if len(ps) == 0 {
		return netip.Prefix{}, ErrInvalidPrefix
	}
	acc := ps[0].Masked()
	for _, p := range ps[1:] {
		c, err := CommonPrefix(acc.Addr(), p.Addr())
		if err != nil {
			return netip.Prefix{}, err
		}
		bits := min(c.Bits(), acc.Bits(), p.Bits())
		acc = netip.PrefixFrom(c.Addr(), bits).Masked()
	}
	return acc, nil
}

// Offset returns the position of a inside p (0 for the network address).
func Offset(p netip.Prefix, a netip.Addr) (*big.Int, error) {
	if !p.Contains(a) {
		return nil, fmt.Errorf("%w: %s not in %s", ErrNotInPool, a, p)
	}
	return Distance(First(p), a)
}

// Nth returns the address at offset n inside p.
func Nth(p netip.Prefix, n *big.Int) (netip.Addr, error) {
	if n.Sign() < 0 || n.Cmp(Size(p)) >= 0 {
		return netip.Addr{}, ErrOverflow
	}
	return AddBig(First(p), n)
}

// SubnetCount returns how many /newBits subnets fit in p.
func SubnetCount(p netip.Prefix, newBits int) (*big.Int, error) {
	if err := checkSplit(p, newBits); err != nil {
		return nil, err
	}
	return new(big.Int).Lsh(big.NewInt(1), uint(newBits-p.Bits())), nil
}

func checkSplit(p netip.Prefix, newBits int) error {
	if !p.IsValid() || newBits < p.Bits() || newBits > p.Addr().BitLen() {
		return fmt.Errorf("%w: cannot split %s into /%d", ErrInvalidPrefix, p, newBits)
	}
	return nil
}

// Split lazily yields every /newBits subnet of p in order. Splitting
// 2001:db8::/32 into /64 yields 2^32 values, so stop early when needed.
func Split(p netip.Prefix, newBits int) (iter.Seq[netip.Prefix], error) {
	if err := checkSplit(p, newBits); err != nil {
		return nil, err
	}
	p = p.Masked()
	is4, w := p.Addr().Is4(), p.Addr().BitLen()
	step := hostMask(newBits, w)
	step, _ = step.add(u128{0, 1})
	last := toU128(Last(p))
	return func(yield func(netip.Prefix) bool) {
		cur := toU128(p.Addr())
		for {
			if !yield(netip.PrefixFrom(fromU128(cur, is4), newBits)) {
				return
			}
			next, c := cur.add(step)
			if c || next.cmp(last) > 0 || (newBits == 0) {
				return
			}
			cur = next
		}
	}, nil
}

// SplitN splits p into /newBits subnets and returns at most limit of them
// (limit ≤ 0 means no limit — use carefully on IPv6).
func SplitN(p netip.Prefix, newBits, limit int) ([]netip.Prefix, error) {
	seq, err := Split(p, newBits)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for s := range seq {
		out = append(out, s)
		if limit > 0 && len(out) == limit {
			break
		}
	}
	return out, nil
}

// SubnetIndex returns which /newBits subnet of p contains a (0-based).
func SubnetIndex(p netip.Prefix, newBits int, a netip.Addr) (*big.Int, error) {
	if err := checkSplit(p, newBits); err != nil {
		return nil, err
	}
	off, err := Offset(p, a)
	if err != nil {
		return nil, err
	}
	return off.Rsh(off, uint(a.BitLen()-newBits)), nil
}

// Hosts lazily yields every usable host of p (see FirstUsable).
func Hosts(p netip.Prefix) iter.Seq[netip.Addr] {
	if !p.IsValid() {
		return func(func(netip.Addr) bool) {}
	}
	f, l := usableBounds(p)
	if f.Compare(l) > 0 {
		return func(func(netip.Addr) bool) {}
	}
	return Range{f, l}.All()
}

// PrefixLenForHosts returns the longest prefix length whose usable host count
// is at least hosts. ipv6 selects the family.
func PrefixLenForHosts(hosts uint64, ipv6 bool) (int, error) {
	w := 32
	if ipv6 {
		w = 128
	}
	need := new(big.Int).SetUint64(hosts)
	for bits := w; bits >= 0; bits-- {
		var p netip.Prefix
		if ipv6 {
			p = netip.PrefixFrom(netip.IPv6Unspecified(), bits)
		} else {
			p = netip.PrefixFrom(netip.IPv4Unspecified(), bits)
		}
		if UsableHosts(p).Cmp(need) >= 0 {
			return bits, nil
		}
	}
	return 0, ErrExhausted
}

// PlanSubnets carves variable-size subnets (VLSM) out of parent. lengths are
// the requested prefix lengths; the result is in the same order. Largest
// blocks are placed first so alignment waste is minimal.
func PlanSubnets(parent netip.Prefix, lengths []int) ([]netip.Prefix, error) {
	if !parent.IsValid() {
		return nil, ErrInvalidPrefix
	}
	parent = parent.Masked()
	order := make([]int, len(lengths))
	for i := range order {
		order[i] = i
		if lengths[i] < parent.Bits() || lengths[i] > parent.Addr().BitLen() {
			return nil, fmt.Errorf("%w: /%d does not fit in %s", ErrInvalidPrefix, lengths[i], parent)
		}
	}
	slices.SortStableFunc(order, func(a, b int) int { return lengths[a] - lengths[b] })

	free := []netip.Prefix{parent}
	out := make([]netip.Prefix, len(lengths))
	for _, idx := range order {
		want := lengths[idx]
		// Pick the smallest free block that fits, lowest address first.
		best := -1
		for i, f := range free {
			if f.Bits() <= want && (best < 0 || f.Bits() > free[best].Bits()) {
				best = i
			}
		}
		if best < 0 {
			return nil, fmt.Errorf("%w: no room for /%d in %s", ErrExhausted, want, parent)
		}
		blk := free[best]
		free = slices.Delete(free, best, best+1)
		for blk.Bits() < want { // buddy split, keep upper halves free
			lo, hi, _ := Children(blk)
			free = append(free, hi)
			blk = lo
		}
		out[idx] = blk
		SortPrefixes(free)
	}
	return out, nil
}

package ipx

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// Next returns a+1, or ErrOverflow at 255.255.255.255 / ffff:…:ffff.
func Next(a netip.Addr) (netip.Addr, error) { return Add(a, 1) }

// Prev returns a-1, or ErrOverflow at 0.0.0.0 / ::.
func Prev(a netip.Addr) (netip.Addr, error) { return Add(a, -1) }

// Add returns a+n within a's family, or ErrOverflow if the result leaves it.
func Add(a netip.Addr, n int64) (netip.Addr, error) {
	if !a.IsValid() {
		return netip.Addr{}, ErrInvalidAddr
	}
	if n < 0 {
		return subU(a, u128{0, uint64(-(n + 1)) + 1})
	}
	return addU(a, u128{0, uint64(n)})
}

// AddBig returns a+n for arbitrarily large (possibly negative) n.
func AddBig(a netip.Addr, n *big.Int) (netip.Addr, error) {
	if !a.IsValid() || n == nil {
		return netip.Addr{}, ErrInvalidAddr
	}
	if n.Sign() < 0 {
		u, ok := u128FromBig(new(big.Int).Neg(n))
		if !ok {
			return netip.Addr{}, ErrOverflow
		}
		return subU(a, u)
	}
	u, ok := u128FromBig(n)
	if !ok {
		return netip.Addr{}, ErrOverflow
	}
	return addU(a, u)
}

func addU(a netip.Addr, n u128) (netip.Addr, error) {
	r, c := toU128(a).add(n)
	if c || r.cmp(lowOnes(a.BitLen())) > 0 {
		return netip.Addr{}, ErrOverflow
	}
	return fromU128(r, a.Is4()).WithZone(a.Zone()), nil
}

func subU(a netip.Addr, n u128) (netip.Addr, error) {
	r, b := toU128(a).sub(n)
	if b {
		return netip.Addr{}, ErrOverflow
	}
	return fromU128(r, a.Is4()).WithZone(a.Zone()), nil
}

// Distance returns b-a (negative when b < a). Both must share a family.
func Distance(a, b netip.Addr) (*big.Int, error) {
	if !a.IsValid() || !b.IsValid() {
		return nil, ErrInvalidAddr
	}
	if a.Is4() != b.Is4() {
		return nil, ErrFamilyMismatch
	}
	return new(big.Int).Sub(toU128(b).big(), toU128(a).big()), nil
}

// IPv4ToUint32 converts an IPv4 (or IPv4-mapped) address to uint32.
func IPv4ToUint32(a netip.Addr) (uint32, error) {
	a = a.Unmap()
	if !a.Is4() {
		return 0, fmt.Errorf("%w: %s is not IPv4", ErrFamilyMismatch, a)
	}
	b := a.As4()
	return binary.BigEndian.Uint32(b[:]), nil
}

// Uint32ToIPv4 converts n to an IPv4 address.
func Uint32ToIPv4(n uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return netip.AddrFrom4(b)
}

// ToBig returns the integer value of a.
func ToBig(a netip.Addr) *big.Int { return toU128(a).big() }

// FromBig converts an integer to an address; ipv6 selects the family.
func FromBig(n *big.Int, ipv6 bool) (netip.Addr, error) {
	u, ok := u128FromBig(n)
	w := 32
	if ipv6 {
		w = 128
	}
	if !ok || u.cmp(lowOnes(w)) > 0 {
		return netip.Addr{}, ErrOverflow
	}
	return fromU128(u, !ipv6), nil
}

// ToHex returns the address bytes in lowercase hex (c0a80001 for 192.168.0.1).
func ToHex(a netip.Addr) string { return hex.EncodeToString(a.AsSlice()) }

// FromHex parses 8 (IPv4) or 32 (IPv6) hex digits, with optional 0x prefix.
func FromHex(s string) (netip.Addr, error) {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %q", ErrInvalidAddr, s)
	}
	a, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.Addr{}, fmt.Errorf("%w: %q", ErrInvalidAddr, s)
	}
	return a, nil
}

// IPv4ToMapped returns ::ffff:a.b.c.d for an IPv4 address.
func IPv4ToMapped(a netip.Addr) (netip.Addr, error) {
	if !a.Is4() {
		return netip.Addr{}, ErrFamilyMismatch
	}
	return netip.AddrFrom16(a.As16()), nil
}

// FromStdIP converts a net.IP, unmapping 16-byte IPv4 forms.
func FromStdIP(ip net.IP) (netip.Addr, bool) {
	a, ok := netip.AddrFromSlice(ip)
	return a.Unmap(), ok
}

// ToStdIP converts to net.IP (4 bytes for IPv4). Zones are dropped.
func ToStdIP(a netip.Addr) net.IP {
	if !a.IsValid() {
		return nil
	}
	return net.IP(a.AsSlice())
}

// FromIPNet converts a *net.IPNet to a prefix.
func FromIPNet(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	a, ok := FromStdIP(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	if bits == 0 {
		return netip.Prefix{}, false // non-canonical mask
	}
	if bits == 128 && a.Is4() {
		ones -= 96
	}
	if ones < 0 {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, ones), true
}

// ToIPNet converts a prefix to *net.IPNet (masked).
func ToIPNet(p netip.Prefix) *net.IPNet {
	if !p.IsValid() {
		return nil
	}
	p = p.Masked()
	return &net.IPNet{IP: ToStdIP(p.Addr()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// ExpandIPv6 returns the fully expanded form (2001:0db8:0000:…:0001).
// IPv4 addresses are returned in dotted form unchanged.
func ExpandIPv6(a netip.Addr) string {
	if !a.Is6() {
		return a.String()
	}
	b := a.As16()
	var sb strings.Builder
	for i := 0; i < 16; i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		fmt.Fprintf(&sb, "%02x%02x", b[i], b[i+1])
	}
	if z := a.Zone(); z != "" {
		sb.WriteString("%" + z)
	}
	return sb.String()
}

// CompareAddr orders addresses: IPv4 before IPv6, then numerically.
func CompareAddr(a, b netip.Addr) int { return a.Compare(b) }

// SortAddrs sorts in place.
func SortAddrs(as []netip.Addr) { slices.SortFunc(as, netip.Addr.Compare) }

// DedupAddrs normalizes (unmaps, drops zone), sorts and removes duplicates,
// returning a new slice.
func DedupAddrs(as []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(as))
	for _, a := range as {
		if a.IsValid() {
			out = append(out, Normalize(a))
		}
	}
	SortAddrs(out)
	return slices.Compact(out)
}

// MinAddr returns the smallest valid address, or false if none.
func MinAddr(as []netip.Addr) (netip.Addr, bool) { return pick(as, -1) }

// MaxAddr returns the largest valid address, or false if none.
func MaxAddr(as []netip.Addr) (netip.Addr, bool) { return pick(as, 1) }

func pick(as []netip.Addr, sign int) (netip.Addr, bool) {
	var best netip.Addr
	for _, a := range as {
		if a.IsValid() && (!best.IsValid() || a.Compare(best)*sign > 0) {
			best = a
		}
	}
	return best, best.IsValid()
}

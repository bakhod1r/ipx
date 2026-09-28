package ipx

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ParseAddr parses an IPv4 or IPv6 address. It is strict: leading zeros in
// IPv4 octets, surrounding whitespace and brackets are rejected.
func ParseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %q", ErrInvalidAddr, s)
	}
	return a, nil
}

// ParsePrefix parses a CIDR prefix. Host bits are allowed and preserved
// (192.168.1.10/24 is valid); use ParsePrefixStrict to reject them.
func ParsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: %q", ErrInvalidPrefix, s)
	}
	return p, nil
}

// ParsePrefixStrict parses a CIDR prefix and rejects host bits
// (192.168.1.10/24 fails, 192.168.1.0/24 succeeds).
func ParsePrefixStrict(s string) (netip.Prefix, error) {
	p, err := ParsePrefix(s)
	if err != nil {
		return p, err
	}
	if p.Masked() != p {
		return netip.Prefix{}, fmt.Errorf("%w: %q", ErrHostBitsSet, s)
	}
	return p, nil
}

// ParseNetwork accepts either a CIDR or a bare address (treated as /32 or
// /128) and returns the masked prefix.
func ParseNetwork(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// MustParseAddr is ParseAddr for trusted constants; it panics on error.
func MustParseAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// MustParsePrefix is ParsePrefix for trusted constants; it panics on error.
func MustParsePrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// IsValidAddr reports whether s is a valid IP address.
func IsValidAddr(s string) bool { _, err := netip.ParseAddr(s); return err == nil }

// IsValidPrefix reports whether s is a valid CIDR prefix.
func IsValidPrefix(s string) bool { _, err := netip.ParsePrefix(s); return err == nil }

// Normalize unmaps IPv4-mapped IPv6 addresses (::ffff:1.2.3.4 → 1.2.3.4) and
// drops the zone. Use it before any security comparison.
func Normalize(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

// NormalizePrefix masks host bits and unmaps IPv4-mapped IPv6 prefixes
// (::ffff:10.0.0.0/104 → 10.0.0.0/8). An invalid prefix is returned unchanged.
func NormalizePrefix(p netip.Prefix) netip.Prefix {
	if !p.IsValid() {
		return p
	}
	a := p.Addr().WithZone("")
	bits := p.Bits()
	if a.Is4In6() {
		if bits < 96 {
			return netip.PrefixFrom(a, bits).Masked()
		}
		a, bits = a.Unmap(), bits-96
	}
	return netip.PrefixFrom(a, bits).Masked()
}

// ParseAddrs parses every string and returns all failures joined.
func ParseAddrs(ss []string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(ss))
	var errs []error
	for i, s := range ss {
		a, err := ParseAddr(s)
		if err != nil {
			errs = append(errs, fmt.Errorf("index %d: %w", i, err))
			continue
		}
		out = append(out, a)
	}
	return out, errors.Join(errs...)
}

// ParsePrefixes parses every string (CIDR or bare address) and returns all
// failures joined.
func ParsePrefixes(ss []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(ss))
	var errs []error
	for i, s := range ss {
		p, err := ParseNetwork(s)
		if err != nil {
			errs = append(errs, fmt.Errorf("index %d: %w", i, err))
			continue
		}
		out = append(out, p)
	}
	return out, errors.Join(errs...)
}

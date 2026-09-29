package ipx

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const hexDigits = "0123456789abcdef"

// ReverseName returns the PTR owner name, with trailing dot:
// 8.8.8.8 → "8.8.8.8.in-addr.arpa.", 2001:db8::1 → "1.0.0.…ip6.arpa.".
func ReverseName(a netip.Addr) (string, error) {
	a = Normalize(a)
	if !a.IsValid() {
		return "", ErrInvalidAddr
	}
	var sb strings.Builder
	if a.Is4() {
		b := a.As4()
		fmt.Fprintf(&sb, "%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0])
		return sb.String(), nil
	}
	b := a.As16()
	for i := 15; i >= 0; i-- {
		sb.WriteByte(hexDigits[b[i]&0xf])
		sb.WriteByte('.')
		sb.WriteByte(hexDigits[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa.")
	return sb.String(), nil
}

// ParseReverseName parses a full PTR name (trailing dot optional,
// case-insensitive) back to an address.
func ParseReverseName(s string) (netip.Addr, error) {
	name := strings.TrimSuffix(strings.ToLower(s), ".")
	fail := fmt.Errorf("%w: %q", ErrInvalidReverse, s)
	switch {
	case strings.HasSuffix(name, ".in-addr.arpa"):
		labels := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
		if len(labels) != 4 {
			return netip.Addr{}, fail
		}
		var b [4]byte
		for i, l := range labels {
			if len(l) == 0 || len(l) > 1 && l[0] == '0' {
				return netip.Addr{}, fail
			}
			n, err := strconv.ParseUint(l, 10, 8)
			if err != nil {
				return netip.Addr{}, fail
			}
			b[3-i] = byte(n)
		}
		return netip.AddrFrom4(b), nil
	case strings.HasSuffix(name, ".ip6.arpa"):
		labels := strings.Split(strings.TrimSuffix(name, ".ip6.arpa"), ".")
		if len(labels) != 32 {
			return netip.Addr{}, fail
		}
		var b [16]byte
		for i, l := range labels {
			if len(l) != 1 {
				return netip.Addr{}, fail
			}
			v := strings.IndexByte(hexDigits, l[0])
			if v < 0 {
				return netip.Addr{}, fail
			}
			pos := 31 - i // nibble index from MSB
			if pos%2 == 0 {
				b[pos/2] |= byte(v) << 4
			} else {
				b[pos/2] |= byte(v)
			}
		}
		return netip.AddrFrom16(b), nil
	}
	return netip.Addr{}, fail
}

// ReverseZones returns the reverse zone names delegating p. The prefix is
// rounded to the next octet (IPv4) or nibble (IPv6) boundary, so 10.0.0.0/23
// yields two /24 zones. RFC 2317 classless delegation is not generated.
func ReverseZones(p netip.Prefix) ([]string, error) {
	p = NormalizePrefix(p)
	if !p.IsValid() {
		return nil, ErrInvalidPrefix
	}
	step := 4
	if p.Addr().Is4() {
		step = 8
	}
	bits := (p.Bits() + step - 1) / step * step
	subs, _ := SplitN(p, bits, 0) // bits is within [p.Bits(), width] by construction
	out := make([]string, 0, len(subs))
	for _, s := range subs {
		full, _ := ReverseName(s.Addr())
		labels := strings.Split(strings.TrimSuffix(full, "."), ".")
		// Drop the host-part labels: address labels count minus network labels.
		addrLabels := p.Addr().BitLen() / step
		drop := addrLabels - bits/step
		out = append(out, strings.Join(labels[drop:], ".")+".")
	}
	return out, nil
}

// CNAME is one RFC 2317 delegation record: Name → Target.
type CNAME struct {
	Name, Target string
}

// RFC2317Zone returns the classless child zone name for an IPv4 prefix
// longer than /24 (RFC 2317), e.g. 192.0.2.64/26 → "64-127.2.0.192.in-addr.arpa.".
// The hyphen form is used because "/" needs escaping in many DNS tools.
func RFC2317Zone(p netip.Prefix) (string, error) {
	p = NormalizePrefix(p)
	if !p.IsValid() || !p.Addr().Is4() || p.Bits() <= 24 {
		return "", fmt.Errorf("%w: RFC 2317 needs an IPv4 prefix longer than /24, got %s", ErrInvalidPrefix, p)
	}
	b, l := p.Addr().As4(), Last(p).As4()
	return fmt.Sprintf("%d-%d.%d.%d.%d.in-addr.arpa.", b[3], l[3], b[2], b[1], b[0]), nil
}

// RFC2317CNAMEs returns the CNAMEs the parent /24 zone publishes so each
// address in p resolves through the classless child zone.
func RFC2317CNAMEs(p netip.Prefix) ([]CNAME, error) {
	zone, err := RFC2317Zone(p)
	if err != nil {
		return nil, err
	}
	p = NormalizePrefix(p)
	out := make([]CNAME, 0, 1<<(32-p.Bits()))
	for a := range RangeOf(p).All() {
		name, _ := ReverseName(a)
		host := a.As4()[3]
		out = append(out, CNAME{name, fmt.Sprintf("%d.%s", host, zone)})
	}
	return out, nil
}

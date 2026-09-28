package ipx

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ParseEndpoint parses "ip:port" or "[ipv6]:port" (zone allowed). The
// address is normalized (IPv4-mapped unmapped).
func ParseEndpoint(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %q", ErrInvalidEndpoint, s)
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// ParsePort parses a decimal port 1-65535. Leading zeros and signs are rejected.
func ParsePort(s string) (uint16, error) {
	if s == "" || s[0] == '0' || s[0] == '+' || s[0] == '-' {
		return 0, fmt.Errorf("%w: %q", ErrInvalidPort, s)
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("%w: %q", ErrInvalidPort, s)
	}
	return uint16(n), nil
}

// FormatEndpoint formats a host and port, bracketing IPv6.
func FormatEndpoint(a netip.Addr, port uint16) string {
	return netip.AddrPortFrom(a, port).String()
}

// SplitHostPort splits "host:port", "[v6]:port", "v4", "v6" or "[v6]".
// Port is 0 when absent. Host is returned without brackets.
func SplitHostPort(s string) (host string, port uint16, err error) {
	if s == "" {
		return "", 0, ErrInvalidEndpoint
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return s[1 : len(s)-1], 0, nil
	}
	if strings.Count(s, ":") > 1 && !strings.HasPrefix(s, "[") {
		return s, 0, nil // bare IPv6
	}
	if !strings.Contains(s, ":") {
		return s, 0, nil
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %q", ErrInvalidEndpoint, s)
	}
	pn, err := ParsePort(p)
	if err != nil {
		return "", 0, err
	}
	return h, pn, nil
}

// ParseHost extracts and normalizes the IP from any of the SplitHostPort
// forms. Hostnames are rejected.
func ParseHost(s string) (netip.Addr, error) {
	h, _, err := SplitHostPort(s)
	if err != nil {
		return netip.Addr{}, err
	}
	a, err := ParseAddr(h)
	if err != nil {
		return netip.Addr{}, err
	}
	return a.Unmap(), nil
}

// CompareEndpoint orders by address, then port.
func CompareEndpoint(a, b netip.AddrPort) int { return a.Compare(b) }

// NormalizeEndpoint unmaps the address.
func NormalizeEndpoint(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

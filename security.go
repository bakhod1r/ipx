package ipx

import (
	"net/netip"
)

// CloudMetadata lists well-known cloud instance-metadata endpoints.
var CloudMetadata = []netip.Prefix{
	MustParsePrefix("169.254.169.254/32"), // AWS, GCP, Azure, OCI, DigitalOcean
	MustParsePrefix("169.254.170.2/32"),   // AWS ECS task metadata
	MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud
	MustParsePrefix("fd00:ec2::254/128"),  // AWS IPv6 IMDS
}

var metadataSet = NewIPSet(CloudMetadata)

// IsCloudMetadata reports whether a is a known cloud metadata endpoint,
// including when embedded in IPv4-mapped/compatible/NAT64/6to4 form.
func IsCloudMetadata(a netip.Addr) bool {
	n := Normalize(a)
	if metadataSet.Contains(n) {
		return true
	}
	v4, ok := EmbeddedIPv4(n)
	return ok && metadataSet.Contains(v4)
}

// EmbeddedIPv4 extracts an IPv4 address carried inside an IPv6 address via
// IPv4-mapped, IPv4-compatible, NAT64 (64:ff9b::/96) or 6to4 (2002::/16).
func EmbeddedIPv4(a netip.Addr) (netip.Addr, bool) {
	if !a.Is6() {
		return netip.Addr{}, false
	}
	b := a.As16()
	switch {
	case a.Is4In6(), IsIPv4Compatible(a), nat64.Contains(a):
		return netip.AddrFrom4([4]byte(b[12:16])), true
	case sixToFour.Contains(a):
		return netip.AddrFrom4([4]byte(b[2:6])), true
	}
	return netip.Addr{}, false
}

var (
	nat64     = MustParsePrefix("64:ff9b::/96")
	sixToFour = MustParsePrefix("2002::/16")
)

// IsInternal reports whether a must not be reached from a server fetching
// user-supplied URLs (SSRF guard). True for invalid, loopback, private,
// link-local, shared, reserved, multicast, unspecified, documentation,
// benchmarking and cloud metadata addresses — also when hidden inside
// IPv4-mapped, IPv4-compatible, NAT64 or 6to4 IPv6 forms.
//
// Resolve hostnames first and check every resolved address, then connect to
// the checked address (not the hostname) to avoid DNS rebinding.
func IsInternal(a netip.Addr) bool {
	if !a.IsValid() {
		return true
	}
	n := Normalize(a)
	if !IsPublic(n) || IsCloudMetadata(n) {
		return true
	}
	v4, ok := EmbeddedIPv4(n)
	return ok && !IsPublic(v4)
}

// IsSafeTarget is !IsInternal.
func IsSafeTarget(a netip.Addr) bool { return !IsInternal(a) }

package ipx

import "net/netip"

// Category labels a special-purpose block.
type Category uint16

const (
	CatThisNetwork Category = 1 << iota
	CatPrivate              // RFC 1918
	CatShared               // RFC 6598 carrier-grade NAT
	CatLoopback
	CatLinkLocal
	CatDocumentation
	CatBenchmarking
	CatMulticast
	CatReserved
	CatBroadcast
	CatUniqueLocal // RFC 4193 fc00::/7
	CatIPv4Mapped
	CatTranslation // NAT64, 6to4
	CatProtocol    // IETF protocol assignments
	CatDiscard
	CatUnspecified
)

// SpecialBlock is one entry of the IANA special-purpose registries.
type SpecialBlock struct {
	Prefix   netip.Prefix
	Name     string
	RFC      string
	Category Category
	// Global mirrors the registry's "Globally Reachable" column.
	Global bool
}

// SpecialBlocks lists the IANA IPv4/IPv6 special-purpose address blocks.
// Treat it as read-only.
var SpecialBlocks = []SpecialBlock{
	{MustParsePrefix("0.0.0.0/8"), "This network", "RFC 791", CatThisNetwork, false},
	{MustParsePrefix("10.0.0.0/8"), "Private-Use", "RFC 1918", CatPrivate, false},
	{MustParsePrefix("100.64.0.0/10"), "Shared Address Space", "RFC 6598", CatShared, false},
	{MustParsePrefix("127.0.0.0/8"), "Loopback", "RFC 1122", CatLoopback, false},
	{MustParsePrefix("169.254.0.0/16"), "Link Local", "RFC 3927", CatLinkLocal, false},
	{MustParsePrefix("172.16.0.0/12"), "Private-Use", "RFC 1918", CatPrivate, false},
	{MustParsePrefix("192.0.0.0/24"), "IETF Protocol Assignments", "RFC 6890", CatProtocol, false},
	{MustParsePrefix("192.0.2.0/24"), "Documentation (TEST-NET-1)", "RFC 5737", CatDocumentation, false},
	{MustParsePrefix("192.88.99.0/24"), "6to4 Relay Anycast (deprecated)", "RFC 7526", CatTranslation, false},
	{MustParsePrefix("192.168.0.0/16"), "Private-Use", "RFC 1918", CatPrivate, false},
	{MustParsePrefix("198.18.0.0/15"), "Benchmarking", "RFC 2544", CatBenchmarking, false},
	{MustParsePrefix("198.51.100.0/24"), "Documentation (TEST-NET-2)", "RFC 5737", CatDocumentation, false},
	{MustParsePrefix("203.0.113.0/24"), "Documentation (TEST-NET-3)", "RFC 5737", CatDocumentation, false},
	{MustParsePrefix("224.0.0.0/4"), "Multicast", "RFC 5771", CatMulticast, false},
	{MustParsePrefix("240.0.0.0/4"), "Reserved", "RFC 1112", CatReserved, false},
	{MustParsePrefix("255.255.255.255/32"), "Limited Broadcast", "RFC 919", CatBroadcast, false},

	{MustParsePrefix("::/128"), "Unspecified", "RFC 4291", CatUnspecified, false},
	{MustParsePrefix("::1/128"), "Loopback", "RFC 4291", CatLoopback, false},
	{MustParsePrefix("::ffff:0:0/96"), "IPv4-mapped", "RFC 4291", CatIPv4Mapped, false},
	{MustParsePrefix("64:ff9b::/96"), "IPv4-IPv6 Translation", "RFC 6052", CatTranslation, true},
	{MustParsePrefix("64:ff9b:1::/48"), "Local-use IPv4/IPv6 Translation", "RFC 8215", CatTranslation, false},
	{MustParsePrefix("100::/64"), "Discard-Only", "RFC 6666", CatDiscard, false},
	{MustParsePrefix("2001::/23"), "IETF Protocol Assignments", "RFC 2928", CatProtocol, false},
	{MustParsePrefix("2001:2::/48"), "Benchmarking", "RFC 5180", CatBenchmarking, false},
	{MustParsePrefix("2001:db8::/32"), "Documentation", "RFC 3849", CatDocumentation, false},
	{MustParsePrefix("2002::/16"), "6to4", "RFC 3056", CatTranslation, false},
	{MustParsePrefix("3fff::/20"), "Documentation", "RFC 9637", CatDocumentation, false},
	{MustParsePrefix("fc00::/7"), "Unique-Local", "RFC 4193", CatUniqueLocal, false},
	{MustParsePrefix("fe80::/10"), "Link-Local Unicast", "RFC 4291", CatLinkLocal, false},
	{MustParsePrefix("ff00::/8"), "Multicast", "RFC 4291", CatMulticast, false},
}

var specialTable = func() *Table[SpecialBlock] {
	t := &Table[SpecialBlock]{}
	for _, b := range SpecialBlocks {
		if b.Prefix.Addr().Is4In6() {
			continue // ::ffff:0:0/96 would normalize to 0.0.0.0/0; lookups unmap anyway
		}
		t.Insert(b.Prefix, b)
	}
	return t
}()

// Special returns the most specific special-purpose block containing a.
// IPv4-mapped input is unmapped first.
func Special(a netip.Addr) (SpecialBlock, bool) {
	_, b, ok := specialTable.Lookup(Normalize(a))
	return b, ok
}

// Categories returns the category bits of every special block containing a.
func Categories(a netip.Addr) Category {
	var c Category
	specialTable.walk(Normalize(a), func(_ int, b SpecialBlock) bool { c |= b.Category; return true })
	return c
}

func has(a netip.Addr, c Category) bool { return Categories(a)&c != 0 }

// IsIPv4 reports whether a is IPv4 or IPv4-mapped IPv6.
func IsIPv4(a netip.Addr) bool { return a.Unmap().Is4() }

// IsIPv6 reports whether a is a native (non-mapped) IPv6 address.
func IsIPv6(a netip.Addr) bool { return a.Is6() && !a.Is4In6() }

func IsLoopback(a netip.Addr) bool       { return Normalize(a).IsLoopback() }
func IsMulticast(a netip.Addr) bool      { return Normalize(a).IsMulticast() }
func IsUnspecified(a netip.Addr) bool    { return Normalize(a).IsUnspecified() }
func IsInterfaceLocal(a netip.Addr) bool { return a.IsInterfaceLocalMulticast() }
func IsGlobalUnicast(a netip.Addr) bool  { return Normalize(a).IsGlobalUnicast() }

// IsLinkLocal covers unicast and multicast link-local scopes.
func IsLinkLocal(a netip.Addr) bool {
	a = Normalize(a)
	return a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast()
}

// IsPrivate reports RFC 1918 IPv4 and RFC 4193 IPv6 unique-local addresses.
func IsPrivate(a netip.Addr) bool { return Normalize(a).IsPrivate() }

// IsUnicast reports a valid address that is not multicast, broadcast or
// unspecified.
func IsUnicast(a netip.Addr) bool {
	a = Normalize(a)
	return a.IsValid() && !a.IsMulticast() && !a.IsUnspecified() && !has(a, CatBroadcast)
}

func IsDocumentation(a netip.Addr) bool { return has(a, CatDocumentation) }
func IsBenchmarking(a netip.Addr) bool  { return has(a, CatBenchmarking) }
func IsShared(a netip.Addr) bool        { return has(a, CatShared) }
func IsReserved(a netip.Addr) bool      { return has(a, CatReserved|CatThisNetwork|CatBroadcast|CatDiscard) }

// IsSpecial reports whether a falls in any IANA special-purpose block.
func IsSpecial(a netip.Addr) bool { _, ok := Special(a); return ok }

// IsPublic reports whether a is a globally reachable unicast address: global
// unicast and not inside any special block marked non-global.
func IsPublic(a netip.Addr) bool {
	a = Normalize(a)
	if !a.IsValid() || !a.IsGlobalUnicast() {
		return false
	}
	public := true
	specialTable.walk(a, func(_ int, b SpecialBlock) bool { public = b.Global; return public })
	return public
}

// IsIPv4Mapped reports ::ffff:a.b.c.d.
func IsIPv4Mapped(a netip.Addr) bool { return a.Is4In6() }

// IsIPv4Compatible reports deprecated IPv4-compatible IPv6 (::a.b.c.d),
// excluding :: and ::1.
func IsIPv4Compatible(a netip.Addr) bool {
	if !a.Is6() || a.Is4In6() {
		return false
	}
	b := a.As16()
	for _, x := range b[:12] {
		if x != 0 {
			return false
		}
	}
	u := toU128(a)
	return u.lo > 1
}

// Family returns 4 or 6 (after unmapping), or 0 for an invalid address.
func Family(a netip.Addr) int {
	a = a.Unmap()
	switch {
	case a.Is4():
		return 4
	case a.Is6():
		return 6
	}
	return 0
}

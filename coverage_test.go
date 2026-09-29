package ipx

import (
	"context"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"testing"
)

// Edge cases and error paths not exercised by the feature tests.

func TestAddrEdges(t *testing.T) {
	var bad netip.Addr
	if _, err := Add(bad, 1); !errors.Is(err, ErrInvalidAddr) {
		t.Error(err)
	}
	if _, err := AddBig(bad, big.NewInt(1)); !errors.Is(err, ErrInvalidAddr) {
		t.Error(err)
	}
	if _, err := AddBig(A("::1"), nil); !errors.Is(err, ErrInvalidAddr) {
		t.Error(err)
	}
	huge := new(big.Int).Lsh(big.NewInt(1), 130)
	if _, err := AddBig(A("::1"), huge); !errors.Is(err, ErrOverflow) {
		t.Error(err)
	}
	if _, err := AddBig(A("::1"), new(big.Int).Neg(huge)); !errors.Is(err, ErrOverflow) {
		t.Error(err)
	}
	if a, _ := AddBig(A("10.0.0.10"), big.NewInt(-10)); a != A("10.0.0.0") {
		t.Error(a)
	}
	if _, err := Distance(bad, A("::1")); !errors.Is(err, ErrInvalidAddr) {
		t.Error(err)
	}
	if _, err := IPv4ToUint32(A("::1")); !errors.Is(err, ErrFamilyMismatch) {
		t.Error(err)
	}
	if _, err := FromBig(nil, true); !errors.Is(err, ErrOverflow) {
		t.Error(err)
	}
	for _, s := range []string{"zz", "0102"} {
		if _, err := FromHex(s); !errors.Is(err, ErrInvalidAddr) {
			t.Error(s, err)
		}
	}
	if _, err := IPv4ToMapped(A("::1")); !errors.Is(err, ErrFamilyMismatch) {
		t.Error(err)
	}
	if ToStdIP(bad) != nil || ToIPNet(netip.Prefix{}) != nil {
		t.Error("nil expected")
	}
	if _, ok := FromIPNet(nil); ok {
		t.Error("nil IPNet")
	}
	if _, ok := FromIPNet(&net.IPNet{IP: net.IP{1, 2, 3}, Mask: net.CIDRMask(8, 32)}); ok {
		t.Error("bad IP")
	}
	if _, ok := FromIPNet(&net.IPNet{IP: net.IPv4(1, 2, 3, 4).To4(), Mask: net.IPMask{255, 0, 255, 0}}); ok {
		t.Error("non-canonical mask")
	}
	if p, ok := FromIPNet(&net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(104, 128)}); !ok || p != P("10.0.0.0/8") {
		t.Error("16-byte v4 with 128-bit mask", p)
	}
	if _, ok := FromIPNet(&net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 128)}); ok {
		t.Error("v4 with short v6 mask")
	}
	if ExpandIPv6(A("fe80::1%eth0")) != "fe80:0000:0000:0000:0000:0000:0000:0001%eth0" || ExpandIPv6(A("1.2.3.4")) != "1.2.3.4" {
		t.Error("ExpandIPv6")
	}
	if CompareAddr(A("1.1.1.1"), A("::1")) >= 0 {
		t.Error("CompareAddr")
	}
	if _, ok := MinAddr(nil); ok {
		t.Error("MinAddr empty")
	}
}

func TestParseEdges(t *testing.T) {
	if _, err := ParsePrefixStrict("bad"); !errors.Is(err, ErrInvalidPrefix) {
		t.Error(err)
	}
	if p, err := ParsePrefixStrict("10.0.0.0/8"); err != nil || p != P("10.0.0.0/8") {
		t.Error(p, err)
	}
	if _, err := ParseNetwork("bad"); err == nil {
		t.Error("ParseNetwork bad")
	}
	if MustParseAddr("1.1.1.1") != A("1.1.1.1") || MustParsePrefix("1.0.0.0/8") != P("1.0.0.0/8") {
		t.Error("Must*")
	}
	if !IsValidAddr("::1") || IsValidAddr("x") || !IsValidPrefix("::/0") || IsValidPrefix("x") {
		t.Error("IsValid*")
	}
	if NormalizePrefix(netip.Prefix{}).IsValid() {
		t.Error("invalid prefix normalized to valid")
	}
	if got := NormalizePrefix(P("::ffff:0:0/80")); got != P("::/80") {
		t.Error("short mapped prefix stays IPv6:", got)
	}
	ps, err := ParsePrefixes([]string{"10.0.0.1", "10.0.0.0/8", "x"})
	if err == nil || len(ps) != 2 || ps[0] != P("10.0.0.1/32") {
		t.Error(ps, err)
	}
}

func TestPrefixEdges(t *testing.T) {
	bad := netip.Prefix{}
	if Size(bad).Sign() != 0 {
		t.Error("Size invalid")
	}
	if _, err := PrefixFromMask(A("1.1.1.1"), A("::")); !errors.Is(err, ErrFamilyMismatch) {
		t.Error(err)
	}
	if _, err := Supernet(P("10.0.0.0/8"), 9); !errors.Is(err, ErrInvalidPrefix) {
		t.Error(err)
	}
	if _, _, ok := Children(P("10.0.0.1/32")); ok {
		t.Error("children of /32")
	}
	lo, hi, _ := Children(P("2001:db8::/32"))
	if lo != P("2001:db8::/33") || hi != P("2001:db8:8000::/33") {
		t.Error(lo, hi)
	}
	if _, ok := Sibling(P("::/0")); ok {
		t.Error("sibling of /0")
	}
	if s, _ := Sibling(P("10.0.0.0/25")); s != P("10.0.0.128/25") {
		t.Error(s)
	}
	if _, err := CommonPrefix(netip.Addr{}, A("::1")); !errors.Is(err, ErrInvalidAddr) {
		t.Error(err)
	}
	if _, err := CommonPrefix(A("1.1.1.1"), A("::1")); !errors.Is(err, ErrFamilyMismatch) {
		t.Error(err)
	}
	if _, err := CommonAncestor(); !errors.Is(err, ErrInvalidPrefix) {
		t.Error(err)
	}
	if _, err := CommonAncestor(P("10.0.0.0/8"), P("::/0")); !errors.Is(err, ErrFamilyMismatch) {
		t.Error(err)
	}
	if _, err := Offset(P("10.0.0.0/24"), A("10.0.1.1")); !errors.Is(err, ErrNotInPool) {
		t.Error(err)
	}
	if _, err := SubnetCount(P("10.0.0.0/24"), 8); err == nil {
		t.Error("SubnetCount shorter")
	}
	if _, err := SplitN(P("10.0.0.0/24"), 8, 0); err == nil {
		t.Error("SplitN shorter")
	}
	if _, err := SubnetIndex(P("10.0.0.0/24"), 8, A("10.0.0.1")); err == nil {
		t.Error("SubnetIndex shorter")
	}
	if _, err := SubnetIndex(P("10.0.0.0/24"), 26, A("11.0.0.1")); !errors.Is(err, ErrNotInPool) {
		t.Error(err)
	}
	for range Hosts(bad) {
		t.Error("hosts of invalid prefix")
	}
	var n int
	for range Hosts(P("2001:db8::/126")) {
		n++
	}
	if n != 4 {
		t.Error("v6 hosts", n)
	}
	if b, _ := PrefixLenForHosts(1<<16, true); b != 112 {
		t.Error(b)
	}
	if _, err := PrefixLenForHosts(1<<33, false); !errors.Is(err, ErrExhausted) {
		t.Error(err)
	}
	if _, err := PlanSubnets(bad, []int{24}); !errors.Is(err, ErrInvalidPrefix) {
		t.Error(err)
	}
	if _, err := PlanSubnets(P("10.0.0.0/24"), []int{23}); !errors.Is(err, ErrInvalidPrefix) {
		t.Error(err)
	}
	if x, ok := IntersectPrefix(P("10.2.0.0/16"), P("10.0.0.0/8")); !ok || x != P("10.2.0.0/16") {
		t.Error(x)
	}
	if _, ok := IntersectPrefix(P("10.0.0.0/8"), P("11.0.0.0/8")); ok {
		t.Error("disjoint intersect")
	}
}

func TestRangeEdges(t *testing.T) {
	if _, err := NewRange(netip.Addr{}, A("1.1.1.1")); !errors.Is(err, ErrInvalidRange) {
		t.Error(err)
	}
	if RangeOf(netip.Prefix{}).IsValid() {
		t.Error("RangeOf invalid")
	}
	for _, s := range []string{"x-1.1.1.1", "1.1.1.1-x", "x"} {
		if _, err := ParseRange(s); !errors.Is(err, ErrInvalidRange) {
			t.Error(s, err)
		}
	}
	var z Range
	if z.String() != "invalid Range" || z.Size().Sign() != 0 || z.Prefixes() != nil || z.Subtract(z) != nil || z.SplitRange(1) != nil {
		t.Error("zero Range")
	}
	if b, _ := z.MarshalText(); len(b) != 0 {
		t.Error("MarshalText zero")
	}
	if b, _ := z.MarshalBinary(); len(b) != 0 {
		t.Error("MarshalBinary zero")
	}
	r, _ := ParseRange("10.0.0.0-10.0.0.9")
	if err := r.UnmarshalText(nil); err != nil || r.IsValid() {
		t.Error("UnmarshalText empty")
	}
	if err := r.UnmarshalText([]byte("bad")); err == nil {
		t.Error("UnmarshalText bad")
	}
	if err := r.UnmarshalBinary(nil); err != nil || r.IsValid() {
		t.Error("UnmarshalBinary empty")
	}
	if err := r.UnmarshalBinary([]byte{10, 0, 0, 9, 10, 0, 0, 1}); !errors.Is(err, ErrInvalidRange) {
		t.Error("reversed binary", err)
	}
	a, _ := ParseRange("10.0.0.0-10.0.0.9")
	if got := a.Subtract(Range{A("11.0.0.0"), A("11.0.0.1")}); len(got) != 1 || got[0] != a {
		t.Error(got)
	}
	if _, ok := a.Prefix(); ok {
		t.Error("10 addresses are not one prefix")
	}
	if _, ok := a.Intersect(Range{A("11.0.0.0"), A("11.0.0.1")}); ok {
		t.Error("disjoint intersect")
	}
	if _, ok := a.Merge(Range{A("11.0.0.0"), A("11.0.0.1")}); ok {
		t.Error("gap merged")
	}
	if !a.Adjacent(Range{A("9.255.255.255"), A("9.255.255.255")}) {
		t.Error("left adjacency")
	}
	if !a.ContainsRange(Range{A("10.0.0.2"), A("10.0.0.3")}) {
		t.Error("ContainsRange")
	}
	top, _ := ParseRange("255.255.255.0-255.255.255.255")
	if got := top.SplitRange(1 << 20); len(got) != 1 {
		t.Error(got)
	}
	var seen int
	for range a.All() {
		seen++
		break
	}
	if seen != 1 {
		t.Error("early stop")
	}
}

func TestRangeWalk(t *testing.T) {
	r, _ := ParseRange("10.0.0.0/20")
	n := 0
	if err := r.Walk(context.Background(), func(netip.Addr) bool { n++; return n < 5 }); err != nil || n != 5 {
		t.Error(n, err)
	}
	n = 0
	if err := r.Walk(context.Background(), func(netip.Addr) bool { n++; return true }); err != nil || n != 4096 {
		t.Error(n, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Walk(ctx, func(netip.Addr) bool { return true }); !errors.Is(err, context.Canceled) {
		t.Error(err)
	}
}

func TestSetEdges(t *testing.T) {
	var nilSet *IPSet
	if !nilSet.IsEmpty() || nilSet.Contains(A("1.1.1.1")) {
		t.Error("nil set")
	}
	s := NewIPSet([]netip.Addr{A("10.0.0.1")}, []Range{{A("10.0.0.5"), A("10.0.0.6")}}, NewIPSet(P("::1/128")), "ignored")
	if s.String() != "10.0.0.1/32, 10.0.0.5/32, 10.0.0.6/32, ::1/128" {
		t.Error(s)
	}
	var b Builder
	b.AddSet(s)
	b.AddSet(nil)
	b.AddPrefix(netip.Prefix{})
	b.AddRange(Range{})
	b.AddAddr(netip.Addr{})
	b.RemovePrefix(P("10.0.0.0/30"))
	b.RemovePrefix(netip.Prefix{})
	b.RemoveRange(Range{A("10.0.0.5"), A("10.0.0.5")})
	b.RemoveRange(Range{})
	b.RemoveSet(NewIPSet(A("::1")))
	b.RemoveSet(nil)
	b.RemoveAddr(netip.Addr{})
	if got := b.IPSet().String(); got != "10.0.0.6/32" {
		t.Error(got)
	}
	if !s.ContainsPrefix(P("10.0.0.5/32")) || s.ContainsRange(Range{}) {
		t.Error("ContainsPrefix")
	}
	if !s.Overlaps(NewIPSet(A("::1"))) || s.Overlaps(NewIPSet(A("::2"))) {
		t.Error("Overlaps")
	}
	var all []netip.Addr
	for a := range s.All() {
		all = append(all, a)
		if len(all) == 3 {
			break
		}
	}
	if !slices.Equal(all, []netip.Addr{A("10.0.0.1"), A("10.0.0.5"), A("10.0.0.6")}) {
		t.Error(all)
	}
	if !s.Contains(A("::1%eth0")) {
		t.Error("zoned lookup")
	}
	if _, err := ParseIPSet("10.0.0.0/8, bogus"); err == nil {
		t.Error("ParseIPSet bad")
	}
}

func TestTableEdges(t *testing.T) {
	var tb Table[int]
	if tb.Insert(netip.Prefix{}, 1) || tb.Delete(netip.Prefix{}) || tb.Contains(A("1.1.1.1")) {
		t.Error("invalid/empty")
	}
	if _, ok := tb.Get(netip.Prefix{}); ok {
		t.Error("Get invalid")
	}
	if _, _, ok := tb.LookupShortest(A("1.1.1.1")); ok {
		t.Error("LookupShortest empty")
	}
	tb.Insert(P("10.0.0.0/24"), 1)
	tb.Insert(P("10.0.1.0/24"), 2) // creates valueless 10.0.0.0/23 branch node
	tb.Insert(P("10.0.0.0/24"), 3) // replace
	if tb.Len() != 2 {
		t.Error(tb.Len())
	}
	if _, ok := tb.Get(P("10.0.0.0/23")); ok {
		t.Error("branch node reported as stored")
	}
	if _, ok := tb.Get(P("10.0.0.0/25")); ok {
		t.Error("longer than leaf")
	}
	if _, ok := tb.Get(P("10.0.2.0/24")); ok {
		t.Error("absent sibling")
	}
	if tb.Delete(P("10.0.0.0/23")) || tb.Delete(P("11.0.0.0/8")) || tb.Delete(P("10.0.0.0/25")) {
		t.Error("deleted absent prefix")
	}
	tb.Insert(P("10.0.0.0/23"), 9) // fills the branch node
	if tb.Len() != 3 {
		t.Error(tb.Len())
	}
	if !tb.Contains(A("10.0.1.5")) {
		t.Error("Contains")
	}
	tb.Delete(P("10.0.1.0/24")) // leaves a stored node with one child
	tb.Delete(P("10.0.0.0/23")) // now valueless with a single left child: collapses
	if v, _ := tb.Get(P("10.0.0.0/24")); v != 3 || tb.Len() != 1 {
		t.Error("collapse", v, tb.Len())
	}
	tb.Insert(P("10.0.1.0/24"), 4)
	tb.Delete(P("10.0.0.0/24")) // branch collapses onto right child
	if v, _ := tb.Get(P("10.0.1.0/24")); v != 4 {
		t.Error("right collapse", v)
	}
	if got := tb.Matches(netip.Addr{}); got != nil {
		t.Error("Matches invalid")
	}
	tb.Insert(P("::/0"), 0)
	n := 0
	for range tb.All() {
		n++
		break
	}
	if n != 1 {
		t.Error("All early stop")
	}
	var st SyncTable[int]
	st.Insert(P("10.0.0.0/8"), 1)
	if v, ok := st.Get(P("10.0.0.0/8")); !ok || v != 1 || !st.Delete(P("10.0.0.0/8")) {
		t.Error("SyncTable")
	}
}

func TestClassifyEdges(t *testing.T) {
	if !IsUnspecified(A("::ffff:0.0.0.0")) || !IsGlobalUnicast(A("8.8.8.8")) || !IsInterfaceLocal(A("ff01::1")) {
		t.Error("stdlib wrappers")
	}
	if IsIPv4Compatible(A("1.2.3.4")) || IsIPv4Compatible(A("::1:0:0:0:1")) {
		t.Error("IsIPv4Compatible false cases")
	}
	if Family(A("::1")) != 6 {
		t.Error("Family v6")
	}
	if !IsCloudMetadata(A("169.254.169.254")) || IsCloudMetadata(A("8.8.8.8")) || !IsSafeTarget(A("8.8.8.8")) {
		t.Error("metadata")
	}
	if _, ok := EmbeddedIPv4(A("2001:db8::1")); ok {
		t.Error("no embedded v4")
	}
}

func TestACLEdges(t *testing.T) {
	acl := NewACL(LongestPrefix, Deny)
	acl.Add(Rule{Prefix: P("10.0.0.0/8"), Action: Allow, Priority: 5})
	acl.Add(Rule{Prefix: P("10.0.0.0/8"), Action: Deny, Priority: 1})
	acl.Add(Rule{Prefix: P("10.0.0.0/8"), Action: Allow, Priority: 1})
	if acl.Allowed(A("10.1.1.1")) {
		t.Error("equal prefix: lowest priority, then insertion order, should deny")
	}
	if len(acl.Rules()) != 3 || Deny.String() != "deny" || Allow.String() != "allow" {
		t.Error("Rules/String")
	}
}

func TestAllocatorEdges(t *testing.T) {
	if _, err := NewAllocator(netip.Prefix{}); !errors.Is(err, ErrInvalidPrefix) {
		t.Error(err)
	}
	if _, err := NewRangeAllocator(Range{}); !errors.Is(err, ErrInvalidRange) {
		t.Error(err)
	}
	al, _ := NewAllocator(P("10.0.0.0/30"))
	al.AllocateN(2)
	if _, err := al.AllocatePrev(); !errors.Is(err, ErrExhausted) {
		t.Error(err)
	}
	if _, err := al.AllocateRandom(); !errors.Is(err, ErrExhausted) {
		t.Error(err)
	}
	if al.Release(A("10.0.0.3")) {
		t.Error("released never-allocated address")
	}
	if !al.Release(A("10.0.0.2")) {
		t.Error("release")
	}
	if a, _ := al.AllocatePrev(); a != A("10.0.0.2") {
		t.Error(a)
	}
	// Downward scan jumping over a taken run.
	al2, _ := NewAllocator(P("10.0.0.0/29"))
	al2.Reserve(A("10.0.0.6"))
	if a, _ := al2.AllocatePrev(); a != A("10.0.0.5") {
		t.Error(a)
	}
	al2.Reserve(A("10.0.0.1"))
	al2.Claim(A("10.0.0.2"))
	al2.Claim(A("10.0.0.3"))
	al2.Claim(A("10.0.0.4"))
	if _, err := al2.AllocatePrev(); !errors.Is(err, ErrExhausted) {
		t.Error(err)
	}
}

func TestDialerEdges(t *testing.T) {
	ctx := context.Background()
	d := &SafeDialer{}
	if _, err := d.DialContext(ctx, "tcp", "noport"); err == nil {
		t.Error("missing port accepted")
	}
	// Default resolver: localhost resolves to loopback and is blocked.
	if _, err := d.DialContext(ctx, "tcp", "localhost:80"); !errors.Is(err, ErrBlockedAddr) {
		t.Error(err)
	}
	empty := &SafeDialer{Lookup: func(context.Context, string) ([]netip.Addr, error) { return nil, nil }}
	if _, err := empty.DialContext(ctx, "tcp", "x.test:80"); err == nil {
		t.Error("empty answer accepted")
	}
	// Allowed but nothing listening: dial error is returned.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	open := &SafeDialer{Allow: Allowlist(P("127.0.0.0/8"))}
	if _, err := open.DialContext(ctx, "tcp", addr); err == nil || errors.Is(err, ErrBlockedAddr) {
		t.Error(err)
	}
}

func TestDNSEdges(t *testing.T) {
	if _, err := ReverseName(netip.Addr{}); !errors.Is(err, ErrInvalidAddr) {
		t.Error(err)
	}
	for _, bad := range []string{
		"256.2.3.4.in-addr.arpa",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.20.ip6.arpa",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.g.ip6.arpa",
	} {
		if _, err := ParseReverseName(bad); !errors.Is(err, ErrInvalidReverse) {
			t.Error(bad, err)
		}
	}
	if _, err := ReverseZones(netip.Prefix{}); !errors.Is(err, ErrInvalidPrefix) {
		t.Error(err)
	}
	if _, err := RFC2317CNAMEs(P("10.0.0.0/8")); !errors.Is(err, ErrInvalidPrefix) {
		t.Error(err)
	}
}

func TestEndpointEdges(t *testing.T) {
	if _, _, err := SplitHostPort(""); !errors.Is(err, ErrInvalidEndpoint) {
		t.Error(err)
	}
	if _, _, err := SplitHostPort("[::1"); !errors.Is(err, ErrInvalidEndpoint) {
		t.Error(err)
	}
	if _, _, err := SplitHostPort("1.2.3.4:0"); !errors.Is(err, ErrInvalidPort) {
		t.Error(err)
	}
	if _, err := ParseHost(""); err == nil {
		t.Error("empty host")
	}
	a, b := netip.MustParseAddrPort("1.1.1.1:1"), netip.MustParseAddrPort("1.1.1.1:2")
	if CompareEndpoint(a, b) >= 0 {
		t.Error("CompareEndpoint")
	}
	if NormalizeEndpoint(netip.MustParseAddrPort("[::ffff:1.1.1.1]:1")) != a {
		t.Error("NormalizeEndpoint")
	}
}

func TestInspectEdges(t *testing.T) {
	if _, err := InspectAddr(netip.Addr{}); !errors.Is(err, ErrInvalidAddr) {
		t.Error(err)
	}
	if _, err := InspectPrefix(netip.Prefix{}); !errors.Is(err, ErrInvalidPrefix) {
		t.Error(err)
	}
	i, _ := InspectAddr(A("64:ff9b::a00:1"))
	if i.EmbeddedV4 != A("10.0.0.1") || i.String() == "" {
		t.Error(i)
	}
}

func TestMoreEdges(t *testing.T) {
	al, _ := NewAllocator(P("10.0.0.0/30"))
	if _, err := al.AllocateN(3); !errors.Is(err, ErrExhausted) || al.Available().Int64() != 2 {
		t.Error("partial AllocateN not rolled back", err)
	}
	for range (Range{}).All() {
		t.Error("invalid range yielded")
	}
	var tb Table[int]
	tb.Insert(P("10.0.0.0/24"), 1)
	tb.Insert(P("10.0.0.0/16"), 2) // new node lands above an existing longer one
	if _, v, _ := tb.Lookup(A("10.0.5.1")); v != 2 {
		t.Error(v)
	}
	if _, v, _ := tb.Lookup(A("10.0.0.1")); v != 1 {
		t.Error(v)
	}
}

func TestU128Edges(t *testing.T) {
	if _, ok := u128FromBig(nil); ok {
		t.Error("nil big")
	}
	if (u128{1, 0}).bit(63, 128) != 1 {
		t.Error("bit in high word")
	}
}

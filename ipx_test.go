package ipx

import (
	"errors"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"testing"
)

var (
	A = netip.MustParseAddr
	P = netip.MustParsePrefix
)

func TestParse(t *testing.T) {
	for _, s := range []string{"1.2.3.4", "::1", "fe80::1%eth0"} {
		if _, err := ParseAddr(s); err != nil {
			t.Errorf("ParseAddr(%q): %v", s, err)
		}
	}
	for _, s := range []string{"", "1.2.3", "01.2.3.4", " 1.2.3.4", "[::1]", "1.2.3.256"} {
		if _, err := ParseAddr(s); !errors.Is(err, ErrInvalidAddr) {
			t.Errorf("ParseAddr(%q) err = %v", s, err)
		}
	}
	if _, err := ParsePrefix("10.0.0.0/33"); !errors.Is(err, ErrInvalidPrefix) {
		t.Error("want ErrInvalidPrefix for /33")
	}
	if _, err := ParsePrefixStrict("10.0.0.1/24"); !errors.Is(err, ErrHostBitsSet) {
		t.Error("want ErrHostBitsSet")
	}
	if p, _ := ParseNetwork("10.0.0.7"); p != P("10.0.0.7/32") {
		t.Error(p)
	}
	if p, _ := ParseNetwork("10.0.0.7/8"); p != P("10.0.0.0/8") {
		t.Error(p)
	}
	if got := NormalizePrefix(P("::ffff:10.1.0.0/112")); got != P("10.1.0.0/16") {
		t.Error(got)
	}
	if _, err := ParseAddrs([]string{"1.1.1.1", "x", "y"}); err == nil {
		t.Error("want joined error")
	}
}

func TestArithmetic(t *testing.T) {
	if _, err := Next(A("255.255.255.255")); !errors.Is(err, ErrOverflow) {
		t.Error("v4 overflow")
	}
	if _, err := Prev(A("::")); !errors.Is(err, ErrOverflow) {
		t.Error("v6 underflow")
	}
	if _, err := Next(A("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")); !errors.Is(err, ErrOverflow) {
		t.Error("v6 overflow")
	}
	if a, _ := Add(A("10.0.0.255"), 1); a != A("10.0.1.0") {
		t.Error(a)
	}
	if a, _ := Add(A("::1:0:0:0"), -1); a != A("::ffff:ffff:ffff") {
		t.Error(a)
	}
	d, _ := Distance(A("10.0.0.0"), A("10.0.1.0"))
	if d.Int64() != 256 {
		t.Error(d)
	}
	if _, err := Distance(A("1.1.1.1"), A("::1")); !errors.Is(err, ErrFamilyMismatch) {
		t.Error("mismatch")
	}
	if n, _ := IPv4ToUint32(A("::ffff:1.2.3.4")); n != 0x01020304 || Uint32ToIPv4(n) != A("1.2.3.4") {
		t.Error(n)
	}
	b := ToBig(A("::1:0"))
	if a, _ := FromBig(b, true); a != A("::1:0") {
		t.Error(a)
	}
	if _, err := FromBig(big.NewInt(1<<32), false); !errors.Is(err, ErrOverflow) {
		t.Error("FromBig v4 overflow")
	}
	if ToHex(A("192.168.0.1")) != "c0a80001" {
		t.Error(ToHex(A("192.168.0.1")))
	}
	if a, _ := FromHex("0xc0a80001"); a != A("192.168.0.1") {
		t.Error(a)
	}
	if ExpandIPv6(A("2001:db8::1")) != "2001:0db8:0000:0000:0000:0000:0000:0001" {
		t.Error(ExpandIPv6(A("2001:db8::1")))
	}
}

func TestConvert(t *testing.T) {
	a, ok := FromStdIP(net.ParseIP("1.2.3.4")) // 16-byte form
	if !ok || a != A("1.2.3.4") {
		t.Error(a)
	}
	_, n, _ := net.ParseCIDR("10.0.0.0/8")
	if p, ok := FromIPNet(n); !ok || p != P("10.0.0.0/8") {
		t.Error(p)
	}
	if ToIPNet(P("10.1.2.3/16")).String() != "10.1.0.0/16" {
		t.Error(ToIPNet(P("10.1.2.3/16")))
	}
	if m, _ := IPv4ToMapped(A("1.2.3.4")); m != A("::ffff:1.2.3.4") {
		t.Error(m)
	}
}

func TestSortDedup(t *testing.T) {
	in := []netip.Addr{A("::1"), A("10.0.0.2"), A("::ffff:10.0.0.2"), A("10.0.0.1")}
	got := DedupAddrs(in)
	want := []netip.Addr{A("10.0.0.1"), A("10.0.0.2"), A("::1")}
	if !slices.Equal(got, want) {
		t.Error(got)
	}
	if mn, _ := MinAddr(in); mn != A("10.0.0.1") {
		t.Error(mn)
	}
	if mx, _ := MaxAddr(in); mx != A("::ffff:10.0.0.2") {
		t.Error(mx)
	}
}

func TestPrefixMath(t *testing.T) {
	p := P("192.168.1.77/24")
	checks := map[string][2]netip.Addr{
		"first":  {First(p), A("192.168.1.0")},
		"last":   {Last(p), A("192.168.1.255")},
		"fu":     {FirstUsable(p), A("192.168.1.1")},
		"lu":     {LastUsable(p), A("192.168.1.254")},
		"mask":   {Netmask(p), A("255.255.255.0")},
		"wild":   {Hostmask(p), A("0.0.0.255")},
		"fu/31":  {FirstUsable(P("10.0.0.0/31")), A("10.0.0.0")},
		"mask/0": {Netmask(P("0.0.0.0/0")), A("0.0.0.0")},
		"mask6":  {Netmask(P("2001:db8::/64")), A("ffff:ffff:ffff:ffff::")},
		"last6":  {Last(P("::/0")), A("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
	}
	for name, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s: got %s want %s", name, c[0], c[1])
		}
	}
	for _, c := range []struct {
		p           string
		size, hosts int64
	}{{"10.0.0.0/24", 256, 254}, {"10.0.0.0/31", 2, 2}, {"10.0.0.0/32", 1, 1}, {"2001:db8::/127", 2, 2}, {"2001:db8::/128", 1, 1}} {
		if Size(P(c.p)).Int64() != c.size || UsableHosts(P(c.p)).Int64() != c.hosts {
			t.Errorf("%s size/hosts", c.p)
		}
	}
	if Size(P("::/0")).BitLen() != 129 {
		t.Error("::/0 size")
	}
	if _, ok := Broadcast(P("2001:db8::/64")); ok {
		t.Error("v6 broadcast")
	}
	if p, _ := PrefixFromMask(A("10.1.2.3"), A("255.255.0.0")); p != P("10.1.0.0/16") {
		t.Error(p)
	}
	if _, err := PrefixFromMask(A("10.1.2.3"), A("255.0.255.0")); err == nil {
		t.Error("non-contiguous mask accepted")
	}
}

func TestPrefixRelations(t *testing.T) {
	if !ContainsPrefix(P("10.0.0.0/8"), P("10.1.0.0/16")) || ContainsPrefix(P("10.1.0.0/16"), P("10.0.0.0/8")) {
		t.Error("ContainsPrefix")
	}
	if par, _ := Parent(P("10.0.1.0/24")); par != P("10.0.0.0/23") {
		t.Error(par)
	}
	if _, ok := Parent(P("0.0.0.0/0")); ok {
		t.Error("parent of /0")
	}
	lo, hi, _ := Children(P("10.0.0.0/24"))
	if lo != P("10.0.0.0/25") || hi != P("10.0.0.128/25") {
		t.Error(lo, hi)
	}
	if s, _ := Sibling(P("10.0.0.128/25")); s != P("10.0.0.0/25") {
		t.Error(s)
	}
	if !Adjacent(P("10.0.0.0/25"), P("10.0.0.128/25")) || Adjacent(P("10.0.0.0/25"), P("10.0.1.0/25")) {
		t.Error("Adjacent")
	}
	if c, _ := CommonPrefix(A("10.0.0.1"), A("10.0.0.130")); c != P("10.0.0.0/24") {
		t.Error(c)
	}
	if c, _ := CommonAncestor(P("10.0.0.0/24"), P("10.0.3.0/24"), P("10.0.1.0/25")); c != P("10.0.0.0/22") {
		t.Error(c)
	}
	if s, _ := Supernet(P("10.1.2.0/24"), 8); s != P("10.0.0.0/8") {
		t.Error(s)
	}
	if x, ok := IntersectPrefix(P("10.0.0.0/8"), P("10.2.0.0/16")); !ok || x != P("10.2.0.0/16") {
		t.Error(x)
	}
	ps := []netip.Prefix{P("10.0.0.0/24"), P("::/0"), P("10.0.0.0/8"), P("9.0.0.0/8")}
	SortPrefixes(ps)
	if !slices.Equal(ps, []netip.Prefix{P("9.0.0.0/8"), P("10.0.0.0/8"), P("10.0.0.0/24"), P("::/0")}) {
		t.Error(ps)
	}
}

func TestSplitAndSubnets(t *testing.T) {
	got, _ := SplitN(P("192.168.1.0/24"), 26, 0)
	want := []netip.Prefix{P("192.168.1.0/26"), P("192.168.1.64/26"), P("192.168.1.128/26"), P("192.168.1.192/26")}
	if !slices.Equal(got, want) {
		t.Error(got)
	}
	if got, _ := SplitN(P("255.255.255.0/24"), 25, 0); len(got) != 2 {
		t.Error("split at top of space", got)
	}
	if got, _ := SplitN(P("2001:db8::/32"), 64, 3); len(got) != 3 || got[2] != P("2001:db8:0:2::/64") {
		t.Error(got)
	}
	if got, _ := SplitN(P("::/0"), 1, 0); len(got) != 2 {
		t.Error(got)
	}
	if _, err := Split(P("10.0.0.0/24"), 23); err == nil {
		t.Error("split to shorter")
	}
	if n, _ := SubnetCount(P("10.0.0.0/8"), 24); n.Int64() != 65536 {
		t.Error(n)
	}
	if i, _ := SubnetIndex(P("10.0.0.0/24"), 26, A("10.0.0.130")); i.Int64() != 2 {
		t.Error(i)
	}
	if o, _ := Offset(P("10.0.0.0/24"), A("10.0.0.9")); o.Int64() != 9 {
		t.Error(o)
	}
	if a, _ := Nth(P("10.0.0.0/24"), big.NewInt(10)); a != A("10.0.0.10") {
		t.Error(a)
	}
	if _, err := Nth(P("10.0.0.0/24"), big.NewInt(256)); err == nil {
		t.Error("Nth overflow")
	}
	var hosts []netip.Addr
	for h := range Hosts(P("10.0.0.0/30")) {
		hosts = append(hosts, h)
	}
	if !slices.Equal(hosts, []netip.Addr{A("10.0.0.1"), A("10.0.0.2")}) {
		t.Error(hosts)
	}
	if b, _ := PrefixLenForHosts(50, false); b != 26 {
		t.Error(b)
	}
	if b, _ := PrefixLenForHosts(2, false); b != 31 { // RFC 3021 point-to-point
		t.Error(b)
	}
}

func TestPlanSubnets(t *testing.T) {
	got, err := PlanSubnets(P("10.0.0.0/24"), []int{27, 25, 26, 27})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{P("10.0.0.192/27"), P("10.0.0.0/25"), P("10.0.0.128/26"), P("10.0.0.224/27")}
	if !slices.Equal(got, want) {
		t.Error(got)
	}
	if _, err := PlanSubnets(P("10.0.0.0/24"), []int{25, 25, 25}); !errors.Is(err, ErrExhausted) {
		t.Error(err)
	}
}

func TestRange(t *testing.T) {
	r, err := ParseRange("10.0.0.5-10.0.0.20")
	if err != nil {
		t.Fatal(err)
	}
	if r.Size().Int64() != 16 || !r.Contains(A("::ffff:10.0.0.9")) || r.Contains(A("10.0.0.21")) {
		t.Error("size/contains")
	}
	want := []netip.Prefix{P("10.0.0.5/32"), P("10.0.0.6/31"), P("10.0.0.8/29"), P("10.0.0.16/30"), P("10.0.0.20/32")}
	if got := r.Prefixes(); !slices.Equal(got, want) {
		t.Error(got)
	}
	if _, err := ParseRange("10.0.0.9-10.0.0.1"); !errors.Is(err, ErrInvalidRange) {
		t.Error(err)
	}
	if _, err := ParseRange("10.0.0.1-::1"); !errors.Is(err, ErrFamilyMismatch) {
		t.Error(err)
	}
	full, _ := ParseRange("0.0.0.0-255.255.255.255")
	if p, ok := full.Prefix(); !ok || p != P("0.0.0.0/0") {
		t.Error(p)
	}
	full6, _ := ParseRange("::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	if p, ok := full6.Prefix(); !ok || p != P("::/0") {
		t.Error(p)
	}
	a, _ := ParseRange("10.0.0.0/24")
	b, _ := ParseRange("10.0.0.128-10.0.1.10")
	if x, ok := a.Intersect(b); !ok || x.String() != "10.0.0.128-10.0.0.255" {
		t.Error(x)
	}
	if m, ok := a.Merge(b); !ok || m.String() != "10.0.0.0-10.0.1.10" {
		t.Error(m)
	}
	sub := a.Subtract(Range{A("10.0.0.10"), A("10.0.0.20")})
	if len(sub) != 2 || sub[0].String() != "10.0.0.0-10.0.0.9" || sub[1].String() != "10.0.0.21-10.0.0.255" {
		t.Error(sub)
	}
	if len(a.SplitRange(100)) != 3 {
		t.Error(a.SplitRange(100))
	}
	merged := MergeRanges([]Range{b, a, {}, Range{A("10.0.1.11"), A("10.0.1.11")}})
	if len(merged) != 1 || merged[0].String() != "10.0.0.0-10.0.1.11" {
		t.Error(merged)
	}
	var n int
	for range r.All() {
		n++
	}
	if n != 16 {
		t.Error(n)
	}
	var back Range
	txt, _ := r.MarshalText()
	if err := back.UnmarshalText(txt); err != nil || back != r {
		t.Error(back, err)
	}
}

func TestIPSet(t *testing.T) {
	s := NewIPSet(P("10.0.0.0/25"), P("10.0.0.128/25"), A("10.0.1.0"), P("10.0.0.0/26"))
	if got := s.Prefixes(); !slices.Equal(got, []netip.Prefix{P("10.0.0.0/24"), P("10.0.1.0/32")}) {
		t.Error(got)
	}
	if !s.Contains(A("10.0.0.200")) || !s.Contains(A("::ffff:10.0.1.0")) || s.Contains(A("10.0.1.1")) {
		t.Error("Contains")
	}
	o := NewIPSet(P("10.0.0.0/25"))
	if d := s.Difference(o).Prefixes(); !slices.Equal(d, []netip.Prefix{P("10.0.0.128/25"), P("10.0.1.0/32")}) {
		t.Error(d)
	}
	if i := s.Intersect(NewIPSet(P("10.0.0.64/26"), P("::/0"))).Prefixes(); !slices.Equal(i, []netip.Prefix{P("10.0.0.64/26")}) {
		t.Error(i)
	}
	if !s.Union(o).Equal(s) {
		t.Error("union")
	}
	if x := s.SymmetricDifference(NewIPSet(P("10.0.0.0/24"), P("10.0.2.0/24"))).Prefixes(); !slices.Equal(x, []netip.Prefix{P("10.0.1.0/32"), P("10.0.2.0/24")}) {
		t.Error(x)
	}
	c := NewIPSet(P("0.0.0.0/1"), P("::/1")).Complement()
	if got := c.Prefixes(); !slices.Equal(got, []netip.Prefix{P("128.0.0.0/1"), P("8000::/1")}) {
		t.Error(got)
	}
	if !(&IPSet{}).Complement().Complement().IsEmpty() {
		t.Error("double complement")
	}
	if s.Size().Int64() != 257 {
		t.Error(s.Size())
	}
	var b Builder
	b.AddPrefix(P("10.0.0.0/24"))
	b.RemoveAddr(A("10.0.0.0"))
	if got := b.IPSet().Prefixes(); len(got) != 8 || got[0] != P("10.0.0.1/32") {
		t.Error(got)
	}
	ps, err := ParseIPSet("10.0.0.0/25, 10.0.0.128-10.0.0.255 ::1")
	if err != nil || ps.String() != "10.0.0.0/24, ::1/128" {
		t.Error(ps, err)
	}
}

func TestAggregateSubtract(t *testing.T) {
	got := Aggregate([]netip.Prefix{P("10.0.0.128/25"), P("10.0.0.0/25"), P("10.0.0.0/24"), P("10.0.1.0/24")})
	if !slices.Equal(got, []netip.Prefix{P("10.0.0.0/23")}) {
		t.Error(got)
	}
	got = SubtractPrefixes([]netip.Prefix{P("10.0.0.0/24")}, []netip.Prefix{P("10.0.0.0/25")})
	if !slices.Equal(got, []netip.Prefix{P("10.0.0.128/25")}) {
		t.Error(got)
	}
	got = SubtractPrefixes([]netip.Prefix{P("10.0.0.0/24")}, []netip.Prefix{P("10.0.0.7/32")})
	if len(got) != 8 {
		t.Error(got)
	}
	if a := AggregateAddrs([]netip.Addr{A("10.0.0.1"), A("10.0.0.0")}); !slices.Equal(a, []netip.Prefix{P("10.0.0.0/31")}) {
		t.Error(a)
	}
}

func TestTable(t *testing.T) {
	var tb Table[string]
	tb.Insert(P("10.0.0.0/8"), "a")
	tb.Insert(P("10.10.0.0/16"), "b")
	tb.Insert(P("10.10.10.0/24"), "c")
	tb.Insert(P("::/0"), "v6")
	if p, v, ok := tb.Lookup(A("10.10.10.50")); !ok || v != "c" || p != P("10.10.10.0/24") {
		t.Error(p, v)
	}
	if p, v, _ := tb.LookupShortest(A("10.10.10.50")); v != "a" || p != P("10.0.0.0/8") {
		t.Error(p, v)
	}
	if _, v, _ := tb.Lookup(A("::ffff:10.10.1.1")); v != "b" {
		t.Error("mapped lookup", v)
	}
	if _, _, ok := tb.Lookup(A("11.0.0.1")); ok {
		t.Error("miss")
	}
	if got := tb.Matches(A("10.10.10.1")); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Error(got)
	}
	if v, ok := tb.Get(P("10.10.0.0/16")); !ok || v != "b" {
		t.Error(v)
	}
	if !tb.Delete(P("10.10.10.0/24")) || tb.Delete(P("10.10.10.0/24")) || tb.Len() != 3 {
		t.Error("delete")
	}
	if _, v, _ := tb.Lookup(A("10.10.10.50")); v != "b" {
		t.Error(v)
	}
	var order []netip.Prefix
	for p := range tb.All() {
		order = append(order, p)
	}
	if !slices.Equal(order, []netip.Prefix{P("10.0.0.0/8"), P("10.10.0.0/16"), P("::/0")}) {
		t.Error(order)
	}
	tb.Insert(P("1.2.3.4/32"), "host")
	if _, v, _ := tb.Lookup(A("1.2.3.4")); v != "host" {
		t.Error(v)
	}
}

func TestSyncTableRace(t *testing.T) {
	var st SyncTable[int]
	done := make(chan bool)
	go func() {
		for i := range 200 {
			st.Insert(netip.PrefixFrom(Uint32ToIPv4(uint32(i)<<8), 24), i)
		}
		done <- true
	}()
	for range 200 {
		st.Lookup(A("0.0.5.1"))
	}
	<-done
	if st.Len() != 200 || len(st.Snapshot()) != 200 {
		t.Error(st.Len())
	}
}

func TestClassify(t *testing.T) {
	type c struct {
		a    string
		fn   func(netip.Addr) bool
		want bool
	}
	for i, x := range []c{
		{"10.1.1.1", IsPrivate, true},
		{"::ffff:192.168.1.1", IsPrivate, true},
		{"fd00::1", IsPrivate, true},
		{"8.8.8.8", IsPublic, true},
		{"2606:4700::1111", IsPublic, true},
		{"100.64.0.1", IsShared, true},
		{"100.64.0.1", IsPublic, false},
		{"192.0.2.1", IsDocumentation, true},
		{"2001:db8::1", IsDocumentation, true},
		{"3fff::1", IsDocumentation, true},
		{"198.18.0.1", IsBenchmarking, true},
		{"240.0.0.1", IsReserved, true},
		{"255.255.255.255", IsUnicast, false},
		{"::ffff:127.0.0.1", IsLoopback, true},
		{"fe80::1", IsLinkLocal, true},
		{"224.0.0.1", IsMulticast, true},
		{"::ffff:1.2.3.4", IsIPv4, true},
		{"::ffff:1.2.3.4", IsIPv6, false},
		{"::1.2.3.4", IsIPv4Compatible, true},
		{"::1", IsIPv4Compatible, false},
		{"::ffff:1.2.3.4", IsIPv4Mapped, true},
		{"0.1.2.3", IsSpecial, true},
		{"1.1.1.1", IsSpecial, false},
	} {
		if got := x.fn(A(x.a)); got != x.want {
			t.Errorf("#%d %s: got %v", i, x.a, got)
		}
	}
	if b, ok := Special(A("192.168.3.3")); !ok || b.RFC != "RFC 1918" {
		t.Error(b)
	}
	if Categories(A("2001:2::1"))&CatBenchmarking == 0 || Categories(A("2001:2::1"))&CatProtocol == 0 {
		t.Error("nested categories")
	}
	if Family(A("::ffff:1.1.1.1")) != 4 || Family(netip.Addr{}) != 0 {
		t.Error("Family")
	}
}

func TestSecurity(t *testing.T) {
	internal := []string{
		"127.0.0.1", "::1", "10.0.0.1", "169.254.169.254", "::ffff:169.254.169.254",
		"::ffff:127.0.0.1", "::127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::",
		"0.0.0.0", "::", "100.100.100.200", "fd00:ec2::254", "fe80::1", "224.0.0.1",
		"192.0.2.1",
	}
	for _, s := range internal {
		if !IsInternal(A(s)) {
			t.Errorf("%s should be internal", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "2606:4700::1111", "64:ff9b::808:808"} {
		if IsInternal(A(s)) {
			t.Errorf("%s should be public", s)
		}
	}
	if !IsInternal(netip.Addr{}) {
		t.Error("invalid must be internal")
	}
	if !IsCloudMetadata(A("64:ff9b::a9fe:a9fe")) {
		t.Error("NAT64 metadata")
	}
	if v4, ok := EmbeddedIPv4(A("2002:c0a8:101::")); !ok || v4 != A("192.168.1.1") {
		t.Error(v4)
	}
}

func TestACL(t *testing.T) {
	acl := NewACL(LongestPrefix, Deny)
	acl.Add(Rule{Prefix: P("10.0.0.0/8"), Action: Allow})
	acl.Add(Rule{Prefix: P("10.66.0.0/16"), Action: Deny, Group: "bad"})
	if !acl.Allowed(A("10.1.1.1")) || acl.Allowed(A("10.66.1.1")) || acl.Allowed(A("8.8.8.8")) {
		t.Error("LPM")
	}
	if !acl.Allowed(A("::ffff:10.1.1.1")) || acl.Allowed(A("::ffff:10.66.1.1")) {
		t.Error("mapped bypass")
	}
	if acl.RemoveGroup("bad") != 1 || !acl.Allowed(A("10.66.1.1")) {
		t.Error("RemoveGroup")
	}
	fm := NewACL(FirstMatch, Allow)
	fm.Add(Rule{Prefix: P("10.0.0.0/8"), Action: Deny, Priority: 1})
	fm.Add(Rule{Prefix: P("10.1.0.0/16"), Action: Allow, Priority: 2})
	if fm.Allowed(A("10.1.1.1")) {
		t.Error("first match should deny")
	}
	if Allowlist(P("1.1.1.0/24")).Allowed(A("1.1.2.1")) || !Denylist(P("1.1.1.0/24")).Allowed(A("1.1.2.1")) {
		t.Error("allow/deny lists")
	}
	if acl.Allowed(netip.Addr{}) || Denylist().Allowed(netip.Addr{}) {
		t.Error("invalid must deny")
	}
	if err := acl.Add(Rule{}); !errors.Is(err, ErrInvalidPrefix) {
		t.Error(err)
	}
}

func TestAllocator(t *testing.T) {
	al, err := NewAllocator(P("10.0.0.0/29"), P("10.0.0.6/32"))
	if err != nil {
		t.Fatal(err)
	}
	if al.Available().Int64() != 5 {
		t.Error(al.Available())
	}
	if err := al.Reserve(A("10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	a, _ := al.Allocate()
	if a != A("10.0.0.2") {
		t.Error(a)
	}
	if err := al.Claim(A("10.0.0.2")); !errors.Is(err, ErrInUse) {
		t.Error(err)
	}
	if err := al.Claim(A("10.0.0.7")); !errors.Is(err, ErrNotInPool) {
		t.Error("broadcast claim", err)
	}
	if b, _ := al.AllocatePrev(); b != A("10.0.0.5") {
		t.Error(b)
	}
	rest, err := al.AllocateN(2)
	if err != nil || !slices.Equal(rest, []netip.Addr{A("10.0.0.3"), A("10.0.0.4")}) {
		t.Error(rest, err)
	}
	if _, err := al.Allocate(); !errors.Is(err, ErrExhausted) {
		t.Error(err)
	}
	if _, err := al.AllocateN(1); !errors.Is(err, ErrExhausted) {
		t.Error(err)
	}
	if !al.Release(A("10.0.0.3")) || !al.IsFree(A("10.0.0.3")) {
		t.Error("release")
	}
	if r, _ := al.AllocateRandom(); r != A("10.0.0.3") {
		t.Error(r)
	}
	if len(al.Allocated()) != 4 {
		t.Error(al.Allocated())
	}
	big6, _ := NewAllocator(P("2001:db8::/64"))
	r1, err := big6.AllocateRandom()
	if err != nil || !P("2001:db8::/64").Contains(r1) {
		t.Error(r1, err)
	}
	if _, err := NewAllocator(P("10.0.0.0/32")); err != nil {
		t.Error("/32 has one usable host:", err)
	}
}

func TestDNS(t *testing.T) {
	if n, _ := ReverseName(A("8.8.4.4")); n != "4.4.8.8.in-addr.arpa." {
		t.Error(n)
	}
	n6, _ := ReverseName(A("2001:db8::1"))
	if n6 != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa." {
		t.Error(n6)
	}
	for _, a := range []string{"8.8.4.4", "2001:db8::1", "::", "ffff::abcd"} {
		name, _ := ReverseName(A(a))
		if back, err := ParseReverseName(name); err != nil || back != A(a) {
			t.Error(a, back, err)
		}
	}
	for _, bad := range []string{"1.2.3.in-addr.arpa", "01.2.3.4.in-addr.arpa", "x.ip6.arpa", "example.com"} {
		if _, err := ParseReverseName(bad); !errors.Is(err, ErrInvalidReverse) {
			t.Error(bad, err)
		}
	}
	z, _ := ReverseZones(P("10.0.0.0/23"))
	if !slices.Equal(z, []string{"0.0.10.in-addr.arpa.", "1.0.10.in-addr.arpa."}) {
		t.Error(z)
	}
	z6, _ := ReverseZones(P("2001:db8::/32"))
	if !slices.Equal(z6, []string{"8.b.d.0.1.0.0.2.ip6.arpa."}) {
		t.Error(z6)
	}
}

func TestEndpoint(t *testing.T) {
	ap, err := ParseEndpoint("[::ffff:1.2.3.4]:80")
	if err != nil || ap.String() != "1.2.3.4:80" {
		t.Error(ap, err)
	}
	if _, err := ParseEndpoint("1.2.3.4:99999"); !errors.Is(err, ErrInvalidEndpoint) {
		t.Error(err)
	}
	for _, bad := range []string{"0", "080", "65536", "-1", "+1", ""} {
		if _, err := ParsePort(bad); !errors.Is(err, ErrInvalidPort) {
			t.Error(bad)
		}
	}
	if FormatEndpoint(A("::1"), 443) != "[::1]:443" {
		t.Error(FormatEndpoint(A("::1"), 443))
	}
	cases := map[string]string{"1.2.3.4": "1.2.3.4", "1.2.3.4:8080": "1.2.3.4", "::1": "::1", "[::1]": "::1", "[::1]:80": "::1"}
	for in, want := range cases {
		if a, err := ParseHost(in); err != nil || a != A(want) {
			t.Error(in, a, err)
		}
	}
	if _, err := ParseHost("example.com:80"); err == nil {
		t.Error("hostname accepted")
	}
}

func TestInspect(t *testing.T) {
	i, _ := InspectAddr(A("::ffff:10.0.0.1"))
	if i.Addr != A("10.0.0.1") || i.Version != 4 || !i.Private || i.Public || i.Special != "Private-Use" {
		t.Errorf("%+v", i)
	}
	pi, _ := InspectPrefix(P("192.168.1.9/24"))
	if pi.Prefix != P("192.168.1.0/24") || pi.Broadcast != A("192.168.1.255") || pi.UsableHosts.Int64() != 254 {
		t.Errorf("%+v", pi)
	}
	if pi.String() == "" || i.String() == "" {
		t.Error("empty String")
	}
}

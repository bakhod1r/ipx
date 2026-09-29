package ipx

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
)

func TestFindOverlaps(t *testing.T) {
	ps := []netip.Prefix{P("10.0.0.0/8"), P("192.168.0.0/16"), P("10.1.0.0/16"), P("10.1.2.0/24"), P("172.16.0.0/12"), P("10.1.0.0/16")}
	got := FindOverlaps(ps)
	want := []Overlap{
		{P("10.0.0.0/8"), P("10.1.0.0/16")},
		{P("10.0.0.0/8"), P("10.1.0.0/16")},
		{P("10.0.0.0/8"), P("10.1.2.0/24")},
		{P("10.1.0.0/16"), P("10.1.0.0/16")},
		{P("10.1.0.0/16"), P("10.1.2.0/24")},
		{P("10.1.0.0/16"), P("10.1.2.0/24")},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %v", got)
	}
	if FindOverlaps([]netip.Prefix{P("10.0.0.0/25"), P("10.0.0.128/25"), P("::/0")}) != nil {
		t.Error("disjoint reported")
	}
}

func TestBuildTree(t *testing.T) {
	roots := BuildTree([]netip.Prefix{P("10.1.2.0/24"), P("10.0.0.0/8"), P("10.1.0.0/16"), P("10.2.0.0/16"), P("192.168.0.0/16"), P("10.1.0.0/16")})
	if len(roots) != 2 || roots[0].Prefix != P("10.0.0.0/8") || roots[1].Prefix != P("192.168.0.0/16") {
		t.Fatalf("roots %v", roots)
	}
	kids := roots[0].Children
	if len(kids) != 2 || kids[0].Prefix != P("10.1.0.0/16") || kids[1].Prefix != P("10.2.0.0/16") {
		t.Fatalf("kids %v", kids)
	}
	if len(kids[0].Children) != 1 || kids[0].Children[0].Prefix != P("10.1.2.0/24") {
		t.Fatalf("grandkids %v", kids[0].Children)
	}
}

func TestRFC2317(t *testing.T) {
	z, err := RFC2317Zone(P("192.0.2.64/26"))
	if err != nil || z != "64-127.2.0.192.in-addr.arpa." {
		t.Fatal(z, err)
	}
	cn, _ := RFC2317CNAMEs(P("192.0.2.64/30"))
	want := []CNAME{
		{"64.2.0.192.in-addr.arpa.", "64.64-67.2.0.192.in-addr.arpa."},
		{"65.2.0.192.in-addr.arpa.", "65.64-67.2.0.192.in-addr.arpa."},
		{"66.2.0.192.in-addr.arpa.", "66.64-67.2.0.192.in-addr.arpa."},
		{"67.2.0.192.in-addr.arpa.", "67.64-67.2.0.192.in-addr.arpa."},
	}
	if !slices.Equal(cn, want) {
		t.Error(cn)
	}
	for _, bad := range []string{"192.0.2.0/24", "10.0.0.0/8", "2001:db8::/120"} {
		if _, err := RFC2317Zone(P(bad)); !errors.Is(err, ErrInvalidPrefix) {
			t.Error(bad, err)
		}
	}
}

func TestBatch(t *testing.T) {
	s := NewIPSet(P("10.0.0.0/8"))
	addrs := []netip.Addr{A("10.1.1.1"), A("8.8.8.8"), A("::ffff:10.0.0.1"), {}}
	if got := s.ContainsBatch(addrs); !slices.Equal(got, []bool{true, false, true, false}) {
		t.Error(got)
	}
	var tb Table[string]
	tb.Insert(P("10.0.0.0/8"), "a")
	tb.Insert(P("10.1.0.0/16"), "b")
	res := tb.LookupBatch(addrs)
	if len(res) != 4 || res[0].Value != "b" || res[1].OK || res[2].Value != "a" || res[2].Prefix != P("10.0.0.0/8") {
		t.Errorf("%+v", res)
	}
}

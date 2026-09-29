// Package bench compares ipx with go4.org/netipx. It is a separate module so
// the core library stays dependency-free. Run: cd bench && go test -bench .
package bench

import (
	"net/netip"
	"testing"

	"github.com/bakhod1r/ipx"
	"go4.org/netipx"
)

func prefixes(n int) []netip.Prefix {
	out := make([]netip.Prefix, n)
	for i := range out {
		out[i] = netip.PrefixFrom(ipx.Uint32ToIPv4(uint32(i)<<13), 20)
	}
	return out
}

var probe = netip.MustParseAddr("0.100.5.1")

func BenchmarkBuild_ipx(b *testing.B) {
	ps := prefixes(10000)
	for b.Loop() {
		ipx.NewIPSet(ps)
	}
}

func BenchmarkBuild_netipx(b *testing.B) {
	ps := prefixes(10000)
	for b.Loop() {
		var sb netipx.IPSetBuilder
		for _, p := range ps {
			sb.AddPrefix(p)
		}
		sb.IPSet()
	}
}

func BenchmarkContains_ipx(b *testing.B) {
	s := ipx.NewIPSet(prefixes(10000))
	b.ReportAllocs()
	for b.Loop() {
		s.Contains(probe)
	}
}

func BenchmarkContains_netipx(b *testing.B) {
	var sb netipx.IPSetBuilder
	for _, p := range prefixes(10000) {
		sb.AddPrefix(p)
	}
	s, _ := sb.IPSet()
	b.ReportAllocs()
	for b.Loop() {
		s.Contains(probe)
	}
}

func BenchmarkRangePrefixes_ipx(b *testing.B) {
	r, _ := ipx.ParseRange("10.0.0.5-10.200.3.77")
	b.ReportAllocs()
	for b.Loop() {
		r.Prefixes()
	}
}

func BenchmarkRangePrefixes_netipx(b *testing.B) {
	r := netipx.IPRangeFrom(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.200.3.77"))
	b.ReportAllocs()
	for b.Loop() {
		r.Prefixes()
	}
}

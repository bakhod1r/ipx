package ipx

import (
	"net/netip"
	"testing"
)

func BenchmarkTableLookup(b *testing.B) {
	var t Table[int]
	for i := range 10000 {
		t.Insert(netip.PrefixFrom(Uint32ToIPv4(uint32(i)<<12), 20), i)
	}
	a := A("0.100.5.1")
	b.ReportAllocs()
	for b.Loop() {
		t.Lookup(a)
	}
}

func BenchmarkIPSetContains(b *testing.B) {
	ps := make([]netip.Prefix, 0, 10000)
	for i := range 10000 {
		ps = append(ps, netip.PrefixFrom(Uint32ToIPv4(uint32(i)<<13), 20))
	}
	s := NewIPSet(ps)
	a := A("0.100.5.1")
	b.ReportAllocs()
	for b.Loop() {
		s.Contains(a)
	}
}

func BenchmarkIsInternal(b *testing.B) {
	a := A("8.8.8.8")
	b.ReportAllocs()
	for b.Loop() {
		IsInternal(a)
	}
}

package ipx

import (
	"math/big"
	"net/netip"
	"testing"
)

// Range.Prefixes must tile the range exactly: contiguous, aligned, in order.
func FuzzRangePrefixes(f *testing.F) {
	f.Add([]byte{10, 0, 0, 5}, []byte{10, 0, 0, 20})
	f.Add([]byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})
	f.Add(make([]byte, 16), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, x, y []byte) {
		a, ok1 := netip.AddrFromSlice(x)
		b, ok2 := netip.AddrFromSlice(y)
		if !ok1 || !ok2 || a.Is4() != b.Is4() {
			return
		}
		if a.Compare(b) > 0 {
			a, b = b, a
		}
		r, err := NewRange(a, b)
		if err != nil {
			return
		}
		ps := r.Prefixes()
		if len(ps) > 2*r.From().BitLen() {
			t.Fatalf("too many prefixes: %d", len(ps))
		}
		want := r.From()
		total := new(big.Int)
		for _, p := range ps {
			if p.Masked() != p || p.Addr() != want {
				t.Fatalf("gap or misaligned at %s (want start %s)", p, want)
			}
			total.Add(total, Size(p))
			want = Last(p).Next()
		}
		if Last(ps[len(ps)-1]) != r.To() || total.Cmp(r.Size()) != 0 {
			t.Fatalf("does not end at %s", r.To())
		}
	})
}

func FuzzParseNoPanic(f *testing.F) {
	for _, s := range []string{"1.2.3.4", "::1", "10.0.0.0/8", "1.1.1.1-2.2.2.2", "[::1]:80", "4.3.2.1.in-addr.arpa."} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ParseAddr(s)
		ParseNetwork(s)
		ParseRange(s)
		ParseEndpoint(s)
		ParseHost(s)
		ParseIPSet(s)
		if a, err := ParseReverseName(s); err == nil {
			name, _ := ReverseName(a)
			if back, err := ParseReverseName(name); err != nil || back != a {
				t.Fatalf("reverse round-trip %q", s)
			}
		}
	})
}

// Set algebra identities on random small prefixes.
func FuzzSetAlgebra(f *testing.F) {
	f.Add(uint32(0x0a000000), uint8(24), uint32(0x0a000080), uint8(25))
	f.Fuzz(func(t *testing.T, x uint32, xb uint8, y uint32, yb uint8) {
		pa := netip.PrefixFrom(Uint32ToIPv4(x), int(xb%33))
		pb := netip.PrefixFrom(Uint32ToIPv4(y), int(yb%33))
		a, b := NewIPSet(pa), NewIPSet(pb)
		u, i := a.Union(b), a.Intersect(b)
		// |A∪B| = |A| + |B| - |A∩B|
		lhs := u.Size()
		rhs := new(big.Int).Add(a.Size(), b.Size())
		rhs.Sub(rhs, i.Size())
		if lhs.Cmp(rhs) != 0 {
			t.Fatalf("inclusion-exclusion failed for %s %s", pa, pb)
		}
		if !a.Difference(b).Union(i).Equal(a) {
			t.Fatalf("(A\\B)∪(A∩B) != A for %s %s", pa, pb)
		}
		if !NewIPSet(u.Prefixes()).Equal(u) {
			t.Fatal("Prefixes round-trip")
		}
	})
}

package ipx

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
)

func TestIsInternalZeroAlloc(t *testing.T) {
	for _, s := range []string{"8.8.8.8", "::ffff:10.0.0.1", "64:ff9b::808:808"} {
		a := A(s)
		if n := testing.AllocsPerRun(100, func() { IsInternal(a) }); n != 0 {
			t.Errorf("%s: %v allocs", s, n)
		}
	}
}

func TestContainsRangeManyRanges(t *testing.T) {
	var b Builder
	for i := range 1000 {
		b.AddAddr(Uint32ToIPv4(uint32(i * 2)))
	}
	s := b.IPSet()
	if !s.ContainsRange(Range{A("0.0.7.206"), A("0.0.7.206")}) || s.ContainsRange(Range{A("0.0.0.0"), A("0.0.0.2")}) {
		t.Error("ContainsRange")
	}
	if n := testing.AllocsPerRun(100, func() { s.ContainsRange(Range{A("0.0.7.206"), A("0.0.7.206")}) }); n != 0 {
		t.Error("allocs", n)
	}
}

func TestIPSetText(t *testing.T) {
	s := NewIPSet(P("10.0.0.0/24"), A("::1"))
	js, err := json.Marshal(s)
	if err != nil || string(js) != `"10.0.0.0/24, ::1/128"` {
		t.Fatal(string(js), err)
	}
	var back IPSet
	if err := json.Unmarshal(js, &back); err != nil || !back.Equal(s) {
		t.Error(back.String(), err)
	}
	if err := back.UnmarshalText([]byte("nope")); err == nil {
		t.Error("bad text accepted")
	}
	var empty IPSet
	if err := empty.UnmarshalText(nil); err != nil || !empty.IsEmpty() {
		t.Error(err)
	}
}

func TestRangeBinary(t *testing.T) {
	for _, s := range []string{"10.0.0.1-10.0.0.9", "::1-::ff"} {
		r, _ := ParseRange(s)
		b, err := r.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var back Range
		if err := back.UnmarshalBinary(b); err != nil || back != r {
			t.Error(s, back, err)
		}
	}
	var r Range
	if err := r.UnmarshalBinary([]byte{1, 2, 3}); !errors.Is(err, ErrInvalidRange) {
		t.Error(err)
	}
}

func TestSafeDialer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	lookup := func(ctx context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "evil.test":
			return []netip.Addr{A("8.8.8.8"), A("127.0.0.1")}, nil // one bad answer poisons all
		case "good.test":
			return []netip.Addr{A("127.0.0.1")}, nil
		}
		return nil, errors.New("nxdomain")
	}
	d := &SafeDialer{Lookup: lookup}
	ctx := context.Background()
	for _, target := range []string{"evil.test:80", "127.0.0.1:80", "[::ffff:127.0.0.1]:80", "169.254.169.254:80"} {
		if _, err := d.DialContext(ctx, "tcp", target); !errors.Is(err, ErrBlockedAddr) {
			t.Errorf("%s: %v", target, err)
		}
	}
	if _, err := d.DialContext(ctx, "tcp", "nope.test:80"); err == nil || errors.Is(err, ErrBlockedAddr) {
		t.Error("lookup error should surface", err)
	}
	// Allow overrides for tests: permit loopback explicitly.
	d.Allow = Allowlist(P("127.0.0.0/8"))
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort("good.test", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func (t *Table[V]) nodeCount() int {
	var count func(n *node[V]) int
	count = func(n *node[V]) int {
		if n == nil {
			return 0
		}
		return 1 + count(n.child[0]) + count(n.child[1])
	}
	return count(t.v4) + count(t.v6)
}

func TestTableCompressed(t *testing.T) {
	var tb Table[int]
	tb.Insert(P("2001:db8::1/128"), 1)
	tb.Insert(P("2001:db8::2/128"), 2)
	if n := tb.nodeCount(); n > 3 {
		t.Errorf("uncompressed: %d nodes for 2 host routes", n)
	}
	tb.Delete(P("2001:db8::1/128"))
	if n := tb.nodeCount(); n != 1 {
		t.Errorf("not collapsed after delete: %d nodes", n)
	}
	if _, v, ok := tb.Lookup(A("2001:db8::2")); !ok || v != 2 {
		t.Error(v)
	}
	tb.Delete(P("2001:db8::2/128"))
	if tb.nodeCount() != 0 || tb.Len() != 0 {
		t.Error("not empty")
	}
}

// Compressed trie must agree with a naive linear scan.
func FuzzTableVsLinear(f *testing.F) {
	f.Add([]byte{10, 0, 0, 0, 8, 10, 10, 0, 0, 16, 10, 10, 10, 0, 24}, uint32(0x0a0a0a32))
	f.Fuzz(func(t *testing.T, raw []byte, probe uint32) {
		var tb Table[int]
		live := map[netip.Prefix]bool{}
		var order []netip.Prefix
		for i := 0; i+5 <= len(raw); i += 5 {
			if raw[i+4]&0x80 != 0 && len(order) > 0 {
				tb.Delete(order[0])
				delete(live, order[0])
				order = order[1:]
				continue
			}
			p := netip.PrefixFrom(netip.AddrFrom4([4]byte(raw[i:i+4])), int(raw[i+4]%33)).Masked()
			tb.Insert(p, p.Bits())
			live[p] = true
			order = append(order, p)
		}
		if tb.Len() != len(live) {
			t.Fatalf("Len %d want %d", tb.Len(), len(live))
		}
		a := Uint32ToIPv4(probe)
		want := -1
		for p := range live {
			if p.Contains(a) && p.Bits() > want {
				want = p.Bits()
			}
		}
		p, v, ok := tb.Lookup(a)
		if want < 0 {
			if ok {
				t.Fatalf("unexpected match %s", p)
			}
			return
		}
		if !ok || v != want || p.Bits() != want {
			t.Fatalf("got %s/%d want /%d", p, v, want)
		}
		for p := range live {
			if _, ok := tb.Get(p); !ok {
				t.Fatalf("Get lost %s", p)
			}
		}
	})
}

// Near-full pool: a single free slot far behind the cursor must be found
// without walking the pool. Compare a /24 with a 1024x larger /14: an O(n)
// scan would slow down ~1000x, an O(log n) one barely at all. A ratio is
// used instead of an absolute time so slow CI runners (-race) don't flake.
func TestAllocatorNearFullFast(t *testing.T) {
	cost := func(p netip.Prefix) float64 {
		al, _ := NewAllocator(p)
		for {
			if _, err := al.Allocate(); err != nil {
				break
			}
		}
		hole := First(p).Next()
		return float64(testing.Benchmark(func(b *testing.B) {
			for b.Loop() {
				al.Release(hole)
				if a, err := al.Allocate(); err != nil || a != hole {
					b.Fatal(a, err)
				}
			}
		}).NsPerOp())
	}
	small, large := cost(P("10.0.0.0/24")), cost(P("10.0.0.0/14"))
	if ratio := large / small; ratio > 50 {
		t.Errorf("near-full scan scales with pool size: /24 %.0fns, /14 %.0fns (x%.0f)", small, large, ratio)
	}
}

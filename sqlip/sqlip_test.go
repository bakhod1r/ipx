package sqlip

import (
	"database/sql/driver"
	"net/netip"
	"testing"
)

func TestAddrScan(t *testing.T) {
	cases := []struct {
		in   any
		want string // "" = NULL
	}{
		{"10.0.0.1", "10.0.0.1"},
		{[]byte("2001:db8::1"), "2001:db8::1"},
		{"10.0.0.1/32", "10.0.0.1"},                      // postgres inet host form
		{"::ffff:10.0.0.1", "10.0.0.1"},                  // normalized
		{[]byte("2001:db8::1:2:34"), "2001:db8::1:2:34"}, // 16 bytes of text, not binary
		{nil, ""},
	}
	for _, c := range cases {
		var a Addr
		if err := a.Scan(c.in); err != nil {
			t.Fatalf("%v: %v", c.in, err)
		}
		if got := a.String(); c.want == "" && a.IsValid() || c.want != "" && got != c.want {
			t.Errorf("%v: got %q", c.in, got)
		}
	}
	for _, bad := range []any{"x", "10.0.0.0/24", []byte{10, 0, 0, 1}, 42} {
		var a Addr
		if err := a.Scan(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestAddrValue(t *testing.T) {
	v, _ := Addr{netip.MustParseAddr("10.0.0.1")}.Value()
	if v != "10.0.0.1" {
		t.Error(v)
	}
	if v, _ := (Addr{}).Value(); v != nil {
		t.Error("zero should be NULL")
	}
	b, _ := BinaryAddr{netip.MustParseAddr("10.0.0.1")}.Value()
	if string(b.([]byte)) != string([]byte{10, 0, 0, 1}) {
		t.Error(b)
	}
	if v, _ := (BinaryAddr{}).Value(); v != nil {
		t.Error("zero binary should be NULL")
	}
	var ba BinaryAddr
	if err := ba.Scan([]byte{10, 0, 0, 2}); err != nil || ba.Addr != netip.MustParseAddr("10.0.0.2") {
		t.Error(ba, err)
	}
	v6 := netip.MustParseAddr("2001:db8::1:2:34")
	if err := ba.Scan(v6.AsSlice()); err != nil || ba.Addr != v6 {
		t.Error(ba, err)
	}
	if err := ba.Scan(netip.MustParseAddr("::ffff:1.2.3.4").AsSlice()); err != nil || ba.Addr != netip.MustParseAddr("1.2.3.4") {
		t.Error("mapped binary not normalized", ba)
	}
	if err := ba.Scan(nil); err != nil || ba.IsValid() {
		t.Error("NULL")
	}
	for _, bad := range []any{[]byte{1, 2, 3}, "10.0.0.1"} {
		if err := ba.Scan(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	var _ driver.Valuer = Addr{}
}

func TestPrefix(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{"10.0.0.0/8", "10.0.0.0/8"},
		{[]byte("10.1.2.3/8"), "10.0.0.0/8"}, // inet with host bits: masked
		{"10.0.0.1", "10.0.0.1/32"},
		{"2001:db8::/32", "2001:db8::/32"},
	}
	for _, c := range cases {
		var p Prefix
		if err := p.Scan(c.in); err != nil || p.String() != c.want {
			t.Errorf("%v: %v %v", c.in, p, err)
		}
	}
	var p Prefix
	if err := p.Scan(nil); err != nil || p.IsValid() {
		t.Error("NULL")
	}
	for _, bad := range []any{"x", 1.5} {
		if err := p.Scan(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if v, _ := (Prefix{netip.MustParsePrefix("10.0.0.0/8")}).Value(); v != "10.0.0.0/8" {
		t.Error(v)
	}
	if v, _ := (Prefix{}).Value(); v != nil {
		t.Error("zero prefix should be NULL")
	}
}

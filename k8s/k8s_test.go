package k8s

import (
	"errors"
	"net/netip"
	"testing"
)

var P = netip.MustParsePrefix

func TestValidate(t *testing.T) {
	ok := Networks{
		Pods:     []netip.Prefix{P("10.244.0.0/16")},
		Services: []netip.Prefix{P("10.96.0.0/12")},
		Nodes:    []netip.Prefix{P("192.168.1.0/24")},
	}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := ok
	bad.Services = []netip.Prefix{P("10.244.128.0/20")}
	err := bad.Validate()
	if !errors.Is(err, ErrOverlap) {
		t.Fatal(err)
	}
	if msg := err.Error(); msg == "" {
		t.Error("empty message")
	}
	if err := (Networks{Services: []netip.Prefix{P("10.0.0.0/8")}}).Validate(); !errors.Is(err, ErrServiceCIDRTooLarge) {
		t.Error(err)
	}
	if err := (Networks{Pods: []netip.Prefix{{}}}).Validate(); err == nil {
		t.Error("invalid prefix accepted")
	}
}

func TestServiceIPs(t *testing.T) {
	svc := P("10.96.0.0/12")
	if a, _ := APIServerIP(svc); a != netip.MustParseAddr("10.96.0.1") {
		t.Error(a)
	}
	if a, _ := DNSServiceIP(svc); a != netip.MustParseAddr("10.96.0.10") {
		t.Error(a)
	}
	if a, _ := ServiceIP(svc, 300); a != netip.MustParseAddr("10.96.1.44") {
		t.Error(a)
	}
	if _, err := ServiceIP(P("10.96.0.0/30"), 4); err == nil {
		t.Error("out of range")
	}
}

func TestNodeCIDRs(t *testing.T) {
	cidrs, err := NodeCIDRs(P("10.244.0.0/16"), 24, 3)
	if err != nil || len(cidrs) != 3 || cidrs[2] != P("10.244.2.0/24") {
		t.Fatal(cidrs, err)
	}
	if n, _ := MaxNodes(P("10.244.0.0/16"), 24); n.Int64() != 256 {
		t.Error(n)
	}
	if _, err := NodeCIDRs(P("10.244.0.0/16"), 24, 257); err == nil {
		t.Error("too many nodes accepted")
	}
	if n, _ := MaxPodsPerNode(24); n != 254 {
		t.Error(n)
	}
}

func TestErrors(t *testing.T) {
	if _, err := ServiceIP(netip.Prefix{}, 1); err == nil {
		t.Error("invalid svc")
	}
	if _, err := NodeCIDRs(P("10.244.0.0/16"), 8, 1); err == nil {
		t.Error("mask shorter than cluster")
	}
	for _, m := range []int{-1, 33} {
		if _, err := MaxPodsPerNode(m); err == nil {
			t.Error(m)
		}
	}
}

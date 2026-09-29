package geoip

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func buildDB(t *testing.T) []byte {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "Test", RecordSize: 24, IPVersion: 6})
	if err != nil {
		t.Fatal(err)
	}
	add := func(cidr string, v mmdbtype.Map) {
		_, n, _ := net.ParseCIDR(cidr)
		if err := tree.Insert(n, v); err != nil {
			t.Fatal(err)
		}
	}
	add("81.2.69.0/24", mmdbtype.Map{
		"country":                        mmdbtype.Map{"iso_code": mmdbtype.String("GB"), "names": mmdbtype.Map{"en": mmdbtype.String("United Kingdom")}},
		"autonomous_system_number":       mmdbtype.Uint32(20712),
		"autonomous_system_organization": mmdbtype.String("Andrews & Arnold"),
	})
	add("2001:218::/32", mmdbtype.Map{
		"country": mmdbtype.Map{"iso_code": mmdbtype.String("JP"), "names": mmdbtype.Map{"en": mmdbtype.String("Japan")}},
	})
	add("1.0.0.0/24", mmdbtype.Map{"autonomous_system_number": mmdbtype.Uint32(13335)})
	var buf bytes.Buffer
	if _, err := tree.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestLookups(t *testing.T) {
	r, err := OpenBytes(buildDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	c, err := r.Country(netip.MustParseAddr("81.2.69.160"))
	if err != nil || c.ISOCode != "GB" || c.Name != "United Kingdom" {
		t.Error(c, err)
	}
	// IPv4-mapped input resolves like IPv4.
	if c, _ := r.Country(netip.MustParseAddr("::ffff:81.2.69.1")); c.ISOCode != "GB" {
		t.Error("mapped", c)
	}
	if c, _ := r.Country(netip.MustParseAddr("2001:218::1")); c.ISOCode != "JP" {
		t.Error(c)
	}
	asn, err := r.ASN(netip.MustParseAddr("81.2.69.1"))
	if err != nil || asn.Number != 20712 || asn.Organization != "Andrews & Arnold" {
		t.Error(asn, err)
	}
	if _, err := r.Country(netip.MustParseAddr("8.8.8.8")); !errors.Is(err, ErrNotFound) {
		t.Error(err)
	}
	if _, err := r.ASN(netip.MustParseAddr("8.8.8.8")); !errors.Is(err, ErrNotFound) {
		t.Error(err)
	}
	if _, err := r.ASN(netip.MustParseAddr("2001:218::1")); !errors.Is(err, ErrNotFound) {
		t.Error("record without ASN", err)
	}
	if _, err := r.Country(netip.MustParseAddr("1.0.0.1")); !errors.Is(err, ErrNotFound) {
		t.Error("record without country", err)
	}
	if _, err := r.Country(netip.Addr{}); err == nil {
		t.Error("invalid address accepted")
	}
	var raw map[string]any
	p, err := r.Lookup(netip.MustParseAddr("81.2.69.1"), &raw)
	if err != nil || p != netip.MustParsePrefix("81.2.69.0/24") || raw["country"] == nil {
		t.Error(p, raw, err)
	}
	var bad struct {
		Country int `maxminddb:"country"`
	}
	if _, err := r.Lookup(netip.MustParseAddr("81.2.69.1"), &bad); err == nil {
		t.Error("type mismatch not reported")
	}
}

func TestOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.mmdb")
	if err := os.WriteFile(path, buildDB(t), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if _, err := Open(filepath.Join(t.TempDir(), "missing.mmdb")); err == nil {
		t.Error("missing file opened")
	}
	if _, err := OpenBytes([]byte("not an mmdb")); err == nil {
		t.Error("garbage opened")
	}
}

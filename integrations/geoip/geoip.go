// Package geoip reads MaxMind DB (.mmdb) files — GeoLite2/GeoIP2 Country,
// City and ASN, or any MMDB — with ipx normalization applied first, so
// IPv4-mapped IPv6 input resolves like plain IPv4.
//
// Databases are not bundled: GeoLite2 requires a free MaxMind account and
// its own license. Download them yourself and pass the path to Open.
package geoip

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/bakhod1r/ipx"
	"github.com/oschwald/maxminddb-golang/v2"
)

// ErrNotFound means the database has no record for the address.
var ErrNotFound = errors.New("geoip: address not found")

// Reader wraps an open MMDB. Safe for concurrent lookups.
type Reader struct{ db *maxminddb.Reader }

// Open memory-maps an .mmdb file.
func Open(path string) (*Reader, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: %w", err)
	}
	return &Reader{db}, nil
}

// OpenBytes reads a database already in memory.
func OpenBytes(b []byte) (*Reader, error) {
	db, err := maxminddb.OpenBytes(b)
	if err != nil {
		return nil, fmt.Errorf("geoip: %w", err)
	}
	return &Reader{db}, nil
}

// Close releases the database.
func (r *Reader) Close() error { return r.db.Close() }

// Lookup decodes the record for a into v and returns the matched network.
func (r *Reader) Lookup(a netip.Addr, v any) (netip.Prefix, error) {
	if !a.IsValid() {
		return netip.Prefix{}, ipx.ErrInvalidAddr
	}
	res := r.db.Lookup(ipx.Normalize(a))
	if !res.Found() {
		return netip.Prefix{}, fmt.Errorf("%w: %s", ErrNotFound, a)
	}
	if err := res.Decode(v); err != nil {
		return netip.Prefix{}, fmt.Errorf("geoip: decode %s: %w", a, err)
	}
	return res.Prefix(), nil
}

// Country is the country part of a GeoLite2/GeoIP2 Country or City record.
type Country struct {
	ISOCode string
	Name    string // English name
}

// Country looks up the country of a.
func (r *Reader) Country(a netip.Addr) (Country, error) {
	var rec struct {
		Country struct {
			ISOCode string            `maxminddb:"iso_code"`
			Names   map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
	}
	if _, err := r.Lookup(a, &rec); err != nil {
		return Country{}, err
	}
	if rec.Country.ISOCode == "" {
		return Country{}, fmt.Errorf("%w: %s has no country", ErrNotFound, a)
	}
	return Country{rec.Country.ISOCode, rec.Country.Names["en"]}, nil
}

// ASN is a GeoLite2-ASN record.
type ASN struct {
	Number       uint32
	Organization string
}

// ASN looks up the autonomous system of a.
func (r *Reader) ASN(a netip.Addr) (ASN, error) {
	var rec struct {
		Number uint32 `maxminddb:"autonomous_system_number"`
		Org    string `maxminddb:"autonomous_system_organization"`
	}
	if _, err := r.Lookup(a, &rec); err != nil {
		return ASN{}, err
	}
	if rec.Number == 0 {
		return ASN{}, fmt.Errorf("%w: %s has no ASN", ErrNotFound, a)
	}
	return ASN{rec.Number, rec.Org}, nil
}

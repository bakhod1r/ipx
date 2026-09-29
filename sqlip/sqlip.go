// Package sqlip provides database/sql Scanner/Valuer types for IP data.
// Standard library only — works with any driver (pgx stdlib, lib/pq,
// go-sql-driver/mysql, sqlite).
//
//   - Addr:       PostgreSQL inet (host), or any text column.
//   - Prefix:     PostgreSQL cidr/inet (network), or any text column.
//   - BinaryAddr: MySQL VARBINARY(16) / INET6_ATON form (4 or 16 bytes).
//
// The zero value of each type maps to SQL NULL. Scanned addresses are
// normalized (IPv4-mapped IPv6 unmapped).
package sqlip

import (
	"database/sql/driver"
	"fmt"
	"net/netip"
	"strings"

	"github.com/bakhod1r/ipx"
)

// Addr is a nullable IP address stored as text.
type Addr struct{ netip.Addr }

// Scan accepts text only ("10.0.0.1", Postgres inet "10.0.0.1/32"), as
// string or []byte. Raw binary columns need BinaryAddr: 16 bytes of text
// such as "2001:db8::1:2:34" would otherwise be indistinguishable.
func (a *Addr) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*a = Addr{}
		return nil
	case string:
		return a.scanText(v)
	case []byte:
		return a.scanText(string(v))
	}
	return fmt.Errorf("sqlip: cannot scan %T into Addr", src)
}

func (a *Addr) scanText(s string) error {
	if host, bits, ok := strings.Cut(s, "/"); ok {
		p, err := ipx.ParsePrefix(s)
		if err != nil || p.Bits() != p.Addr().BitLen() {
			return fmt.Errorf("sqlip: %q is a network, not a host (%s bits)", s, bits)
		}
		s = host
	}
	x, err := ipx.ParseAddr(s)
	if err != nil {
		return err
	}
	a.Addr = ipx.Normalize(x)
	return nil
}

// Value returns the text form, or nil for the zero Addr.
func (a Addr) Value() (driver.Value, error) {
	if !a.IsValid() {
		return nil, nil
	}
	return a.String(), nil
}

// BinaryAddr is a nullable IP address stored as 4 (IPv4) or 16 (IPv6) bytes.
type BinaryAddr struct{ netip.Addr }

// Scan accepts NULL or exactly 4 or 16 raw bytes.
func (b *BinaryAddr) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*b = BinaryAddr{}
		return nil
	case []byte:
		if x, ok := netip.AddrFromSlice(v); ok {
			b.Addr = ipx.Normalize(x)
			return nil
		}
		return fmt.Errorf("sqlip: binary address must be 4 or 16 bytes, got %d", len(v))
	}
	return fmt.Errorf("sqlip: cannot scan %T into BinaryAddr", src)
}

// Value returns the raw bytes, or nil for the zero BinaryAddr.
func (b BinaryAddr) Value() (driver.Value, error) {
	if !b.IsValid() {
		return nil, nil
	}
	return b.AsSlice(), nil
}

// Prefix is a nullable network stored as text. Host bits are masked on scan,
// so Postgres inet values like 10.1.2.3/8 become 10.0.0.0/8.
type Prefix struct{ netip.Prefix }

// Scan accepts CIDR text or a bare address (becoming /32 or /128).
func (p *Prefix) Scan(src any) error {
	var s string
	switch v := src.(type) {
	case nil:
		*p = Prefix{}
		return nil
	case string:
		s = v
	case []byte:
		s = string(v)
	default:
		return fmt.Errorf("sqlip: cannot scan %T into Prefix", src)
	}
	x, err := ipx.ParseNetwork(s)
	if err != nil {
		return err
	}
	p.Prefix = ipx.NormalizePrefix(x)
	return nil
}

// Value returns the CIDR text, or nil for the zero Prefix.
func (p Prefix) Value() (driver.Value, error) {
	if !p.IsValid() {
		return nil, nil
	}
	return p.String(), nil
}

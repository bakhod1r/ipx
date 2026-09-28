// Package ipx is a dependency-free IP networking toolkit built on net/netip.
//
// It covers parsing and validation, classification against the IANA
// special-purpose registries, 128-bit address arithmetic, CIDR math
// (split, aggregate, subtract, supernet), address ranges, immutable IP sets
// with set algebra, a longest-prefix-match table, ACLs, an address
// allocator, reverse DNS names and SSRF-oriented security checks.
//
// Design rules:
//
//   - Every operation on user input returns an error or a bool; nothing panics.
//   - IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are unmapped before
//     classification, set membership and ACL matching, so an attacker cannot
//     bypass an IPv4 rule by writing the address in IPv6 form.
//   - Values (Range, IPSet) are immutable and safe for concurrent reads.
//     Mutable structures (Table, ACL, Allocator) document their own locking.
package ipx

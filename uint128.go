package ipx

import (
	"encoding/binary"
	"math/big"
	"math/bits"
	"net/netip"
)

// u128 is an unsigned 128-bit integer used for address arithmetic.
// IPv4 addresses occupy the low 32 bits.
type u128 struct{ hi, lo uint64 }

var u128Max = u128{^uint64(0), ^uint64(0)}

func toU128(a netip.Addr) u128 {
	if a.Is4() {
		b := a.As4()
		return u128{0, uint64(binary.BigEndian.Uint32(b[:]))}
	}
	b := a.As16()
	return u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

func fromU128(u u128, is4 bool) netip.Addr {
	if is4 {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(u.lo))
		return netip.AddrFrom4(b)
	}
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], u.hi)
	binary.BigEndian.PutUint64(b[8:], u.lo)
	return netip.AddrFrom16(b)
}

func (u u128) add(v u128) (u128, bool) {
	lo, c := bits.Add64(u.lo, v.lo, 0)
	hi, c := bits.Add64(u.hi, v.hi, c)
	return u128{hi, lo}, c != 0
}

func (u u128) sub(v u128) (u128, bool) {
	lo, b := bits.Sub64(u.lo, v.lo, 0)
	hi, b := bits.Sub64(u.hi, v.hi, b)
	return u128{hi, lo}, b != 0
}

func (u u128) cmp(v u128) int {
	switch {
	case u.hi < v.hi:
		return -1
	case u.hi > v.hi:
		return 1
	case u.lo < v.lo:
		return -1
	case u.lo > v.lo:
		return 1
	}
	return 0
}

// trailingZeros counts trailing zero bits, capped at width.
func (u u128) trailingZeros(width int) int {
	if u.lo != 0 {
		return min(bits.TrailingZeros64(u.lo), width)
	}
	if u.hi != 0 {
		return min(64+bits.TrailingZeros64(u.hi), width)
	}
	return width
}

// sub1 returns u-v (caller guarantees u ≥ v).
func (u u128) sub1(v u128) u128 { d, _ := u.sub(v); return d }

// log2Count returns floor(log2(u+1)): the largest k with 2^k ≤ u+1.
func (u u128) log2Count() int {
	n, c := u.add(u128{0, 1})
	if c {
		return 128
	}
	if n.hi != 0 {
		return 127 - bits.LeadingZeros64(n.hi)
	}
	return 63 - bits.LeadingZeros64(n.lo)
}

func (u u128) and(v u128) u128 { return u128{u.hi & v.hi, u.lo & v.lo} }
func (u u128) or(v u128) u128  { return u128{u.hi | v.hi, u.lo | v.lo} }
func (u u128) not() u128       { return u128{^u.hi, ^u.lo} }

// bit returns bit i counted from the most significant bit of a width-bit number.
func (u u128) bit(i, width int) uint {
	pos := width - 1 - i
	if pos >= 64 {
		return uint(u.hi>>(pos-64)) & 1
	}
	return uint(u.lo>>pos) & 1
}

// setBit sets bit i (from MSB of a width-bit number) to 1.
func (u u128) setBit(i, width int) u128 {
	pos := width - 1 - i
	if pos >= 64 {
		u.hi |= 1 << (pos - 64)
	} else {
		u.lo |= 1 << pos
	}
	return u
}

// lowOnes returns a value with the n low bits set.
func lowOnes(n int) u128 {
	switch {
	case n <= 0:
		return u128{}
	case n >= 128:
		return u128Max
	case n >= 64:
		return u128{1<<(n-64) - 1, ^uint64(0)}
	}
	return u128{0, 1<<n - 1}
}

// hostMask returns the host-bit mask of a /bits prefix in a width-bit space.
func hostMask(bits, width int) u128 { return lowOnes(width - bits) }

func (u u128) big() *big.Int {
	b := new(big.Int).SetUint64(u.hi)
	b.Lsh(b, 64)
	return b.Or(b, new(big.Int).SetUint64(u.lo))
}

// u128FromBig converts x to u128; ok is false if x is negative or ≥ 2^128.
func u128FromBig(x *big.Int) (u128, bool) {
	if x == nil || x.Sign() < 0 || x.BitLen() > 128 {
		return u128{}, false
	}
	lo := new(big.Int).And(x, new(big.Int).SetUint64(^uint64(0)))
	hi := new(big.Int).Rsh(x, 64)
	return u128{hi.Uint64(), lo.Uint64()}, true
}

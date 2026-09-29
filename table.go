package ipx

import (
	"iter"
	"math/bits"
	"net/netip"
	"sync"
)

// Table is a binary prefix trie mapping prefixes to values, with
// longest-prefix-match lookup (a routing table). The zero value is ready to
// use. Table is not safe for concurrent mutation; use SyncTable for that.
//
// Prefixes are normalized (masked, IPv4-mapped unmapped) on insert and
// addresses on lookup.
type Table[V any] struct {
	v4, v6 *node[V]
	n      int
}

// node is a path-compressed trie node: it stands for prefix key/bits and
// only exists where a value is stored or two branches diverge.
type node[V any] struct {
	key   u128 // masked to bits
	bits  int
	child [2]*node[V]
	val   V
	set   bool
}

func (t *Table[V]) root(is4 bool) **node[V] {
	if is4 {
		return &t.v4
	}
	return &t.v6
}

// Len returns the number of stored prefixes.
func (t *Table[V]) Len() int { return t.n }

// commonBits returns the length of the common leading bits of a and b,
// capped at limit, in a width-bit space.
func commonBits(a, b u128, width, limit int) int {
	x := u128{a.hi ^ b.hi, a.lo ^ b.lo}
	var lz int
	if x.hi != 0 {
		lz = bits.LeadingZeros64(x.hi)
	} else {
		lz = 64 + bits.LeadingZeros64(x.lo)
	}
	return min(lz-(128-width), limit)
}

func keyOf(p netip.Prefix) (u128, int, int, bool) {
	p = NormalizePrefix(p)
	if !p.IsValid() {
		return u128{}, 0, 0, false
	}
	return toU128(p.Addr()), p.Bits(), p.Addr().BitLen(), true
}

// Insert stores v at p, replacing any existing value. Invalid p is ignored
// and reported as false.
func (t *Table[V]) Insert(p netip.Prefix, v V) bool {
	key, plen, w, ok := keyOf(p)
	if !ok {
		return false
	}
	link := t.root(w == 32)
	for {
		n := *link
		if n == nil {
			*link = &node[V]{key: key, bits: plen, val: v, set: true}
			t.n++
			return true
		}
		c := commonBits(n.key, key, w, min(n.bits, plen))
		if c == n.bits {
			if plen == n.bits {
				if !n.set {
					t.n++
				}
				n.val, n.set = v, true
				return true
			}
			link = &n.child[key.bit(n.bits, w)]
			continue
		}
		// Diverge above n: insert a node at depth c.
		mid := &node[V]{key: key.and(hostMask(c, w).not()), bits: c}
		mid.child[n.key.bit(c, w)] = n
		if c == plen {
			mid.val, mid.set = v, true
		} else {
			mid.child[key.bit(c, w)] = &node[V]{key: key, bits: plen, val: v, set: true}
		}
		*link = mid
		t.n++
		return true
	}
}

// Delete removes p; false if it was absent.
func (t *Table[V]) Delete(p netip.Prefix) bool {
	key, plen, w, ok := keyOf(p)
	if !ok {
		return false
	}
	var path []**node[V]
	link := t.root(w == 32)
	for *link != nil {
		n := *link
		if n.bits > plen || commonBits(n.key, key, w, n.bits) < n.bits {
			return false
		}
		path = append(path, link)
		if n.bits == plen {
			break
		}
		link = &n.child[key.bit(n.bits, w)]
	}
	if *link == nil || (*link).bits != plen || !(*link).set {
		return false
	}
	var zero V
	(*link).val, (*link).set = zero, false
	t.n--
	// Collapse from the bottom: drop valueless nodes with <2 children.
	for i := len(path) - 1; i >= 0; i-- {
		n := *path[i]
		if n.set || (n.child[0] != nil && n.child[1] != nil) {
			break
		}
		if n.child[0] != nil {
			*path[i] = n.child[0]
		} else {
			*path[i] = n.child[1]
		}
	}
	return true
}

// Get returns the value stored at exactly p.
func (t *Table[V]) Get(p netip.Prefix) (V, bool) {
	var zero V
	key, plen, w, ok := keyOf(p)
	if !ok {
		return zero, false
	}
	n := *t.root(w == 32)
	for n != nil && n.bits <= plen && commonBits(n.key, key, w, n.bits) == n.bits {
		if n.bits == plen {
			if n.set {
				return n.val, true
			}
			return zero, false
		}
		n = n.child[key.bit(n.bits, w)]
	}
	return zero, false
}

// walk visits every stored prefix containing a, shortest first.
func (t *Table[V]) walk(a netip.Addr, fn func(bits int, v V) bool) {
	a = Normalize(a)
	if !a.IsValid() {
		return
	}
	w := a.BitLen()
	u := toU128(a)
	n := *t.root(a.Is4())
	for n != nil && u.and(lowOnes(w-n.bits).not()) == n.key {
		if n.set && !fn(n.bits, n.val) {
			return
		}
		if n.bits == w {
			return
		}
		n = n.child[u.bit(n.bits, w)]
	}
}

// Lookup returns the longest stored prefix containing a and its value.
func (t *Table[V]) Lookup(a netip.Addr) (netip.Prefix, V, bool) {
	var best *node[V]
	a = Normalize(a)
	if a.IsValid() {
		w := a.BitLen()
		u := toU128(a)
		for n := *t.root(a.Is4()); n != nil && u.and(lowOnes(w-n.bits).not()) == n.key; {
			if n.set {
				best = n
			}
			if n.bits == w {
				break
			}
			n = n.child[u.bit(n.bits, w)]
		}
	}
	if best == nil {
		var zero V
		return netip.Prefix{}, zero, false
	}
	return netip.PrefixFrom(fromU128(best.key, a.Is4()), best.bits), best.val, true
}

// LookupShortest returns the shortest stored prefix containing a.
func (t *Table[V]) LookupShortest(a netip.Addr) (netip.Prefix, V, bool) {
	var (
		best  V
		bits  = -1
		naddr = Normalize(a)
	)
	t.walk(naddr, func(b int, v V) bool { bits, best = b, v; return false })
	if bits < 0 {
		return netip.Prefix{}, best, false
	}
	return netip.PrefixFrom(naddr, bits).Masked(), best, true
}

// Contains reports whether any stored prefix contains a.
func (t *Table[V]) Contains(a netip.Addr) bool { _, _, ok := t.LookupShortest(a); return ok }

// Matches returns the values of every stored prefix containing a,
// shortest prefix first.
func (t *Table[V]) Matches(a netip.Addr) []V {
	var out []V
	t.walk(a, func(_ int, v V) bool { out = append(out, v); return true })
	return out
}

// All yields every stored prefix and value: IPv4 first, then IPv6, each in
// address order with shorter prefixes before their children.
func (t *Table[V]) All() iter.Seq2[netip.Prefix, V] {
	return func(yield func(netip.Prefix, V) bool) {
		if dfs(t.v4, true, yield) {
			dfs(t.v6, false, yield)
		}
	}
}

func dfs[V any](n *node[V], is4 bool, yield func(netip.Prefix, V) bool) bool {
	if n == nil {
		return true
	}
	if n.set && !yield(netip.PrefixFrom(fromU128(n.key, is4), n.bits), n.val) {
		return false
	}
	return dfs(n.child[0], is4, yield) && dfs(n.child[1], is4, yield)
}

// SyncTable is a Table guarded by a RWMutex: many concurrent readers, one
// writer. The zero value is ready to use.
type SyncTable[V any] struct {
	mu sync.RWMutex
	t  Table[V]
}

func (s *SyncTable[V]) Insert(p netip.Prefix, v V) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.t.Insert(p, v)
}

func (s *SyncTable[V]) Delete(p netip.Prefix) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.t.Delete(p)
}

func (s *SyncTable[V]) Get(p netip.Prefix) (V, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.t.Get(p)
}

func (s *SyncTable[V]) Lookup(a netip.Addr) (netip.Prefix, V, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.t.Lookup(a)
}

func (s *SyncTable[V]) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.t.Len()
}

// Snapshot returns a copy of all entries.
func (s *SyncTable[V]) Snapshot() map[netip.Prefix]V {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := make(map[netip.Prefix]V, s.t.Len())
	for p, v := range s.t.All() {
		m[p] = v
	}
	return m
}

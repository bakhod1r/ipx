package ipx

import (
	"iter"
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

type node[V any] struct {
	child [2]*node[V]
	val   V
	set   bool
}

func (t *Table[V]) root(is4 bool, create bool) **node[V] {
	r := &t.v6
	if is4 {
		r = &t.v4
	}
	if *r == nil && create {
		*r = &node[V]{}
	}
	return r
}

// Len returns the number of stored prefixes.
func (t *Table[V]) Len() int { return t.n }

// Insert stores v at p, replacing any existing value. Invalid p is ignored
// and reported as false.
func (t *Table[V]) Insert(p netip.Prefix, v V) bool {
	p = NormalizePrefix(p)
	if !p.IsValid() {
		return false
	}
	a, w := p.Addr(), p.Addr().BitLen()
	u := toU128(a)
	n := *t.root(a.Is4(), true)
	for i := 0; i < p.Bits(); i++ {
		b := u.bit(i, w)
		if n.child[b] == nil {
			n.child[b] = &node[V]{}
		}
		n = n.child[b]
	}
	if !n.set {
		t.n++
	}
	n.val, n.set = v, true
	return true
}

// Delete removes p; false if it was absent.
func (t *Table[V]) Delete(p netip.Prefix) bool {
	p = NormalizePrefix(p)
	if !p.IsValid() {
		return false
	}
	a, w := p.Addr(), p.Addr().BitLen()
	u := toU128(a)
	root := t.root(a.Is4(), false)
	if *root == nil {
		return false
	}
	path := []*node[V]{*root}
	n := *root
	for i := 0; i < p.Bits(); i++ {
		n = n.child[u.bit(i, w)]
		if n == nil {
			return false
		}
		path = append(path, n)
	}
	if !n.set {
		return false
	}
	var zero V
	n.val, n.set = zero, false
	t.n--
	// Prune empty leaves.
	for i := len(path) - 1; i > 0; i-- {
		cur := path[i]
		if cur.set || cur.child[0] != nil || cur.child[1] != nil {
			break
		}
		path[i-1].child[u.bit(i-1, w)] = nil
	}
	return true
}

// Get returns the value stored at exactly p.
func (t *Table[V]) Get(p netip.Prefix) (V, bool) {
	var zero V
	p = NormalizePrefix(p)
	if !p.IsValid() {
		return zero, false
	}
	a, w := p.Addr(), p.Addr().BitLen()
	u := toU128(a)
	n := *t.root(a.Is4(), false)
	for i := 0; n != nil && i < p.Bits(); i++ {
		n = n.child[u.bit(i, w)]
	}
	if n == nil || !n.set {
		return zero, false
	}
	return n.val, true
}

// walk visits every stored prefix containing a, shortest first.
func (t *Table[V]) walk(a netip.Addr, fn func(bits int, v V) bool) {
	a = Normalize(a)
	if !a.IsValid() {
		return
	}
	w := a.BitLen()
	u := toU128(a)
	n := *t.root(a.Is4(), false)
	for i := 0; n != nil; i++ {
		if n.set && !fn(i, n.val) {
			return
		}
		if i == w {
			return
		}
		n = n.child[u.bit(i, w)]
	}
}

// Lookup returns the longest stored prefix containing a and its value.
func (t *Table[V]) Lookup(a netip.Addr) (netip.Prefix, V, bool) {
	var (
		best  V
		bits  = -1
		naddr = Normalize(a)
	)
	t.walk(naddr, func(b int, v V) bool { bits, best = b, v; return true })
	if bits < 0 {
		return netip.Prefix{}, best, false
	}
	return netip.PrefixFrom(naddr, bits).Masked(), best, true
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
		if !dfs(t.v4, u128{}, 0, true, yield) {
			return
		}
		dfs(t.v6, u128{}, 0, false, yield)
	}
}

func dfs[V any](n *node[V], u u128, depth int, is4 bool, yield func(netip.Prefix, V) bool) bool {
	if n == nil {
		return true
	}
	w := 128
	if is4 {
		w = 32
	}
	if n.set && !yield(netip.PrefixFrom(fromU128(u, is4), depth), n.val) {
		return false
	}
	if !dfs(n.child[0], u, depth+1, is4, yield) {
		return false
	}
	if n.child[1] != nil {
		return dfs(n.child[1], u.setBit(depth, w), depth+1, is4, yield)
	}
	return true
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

package ipx

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/netip"
	"slices"
	"sync"
)

// Allocator hands out addresses from a pool. Safe for concurrent use.
//
// The pool is a prefix (usable hosts only) or a Range, minus exclusions.
// State is in memory; persist Allocated() yourself if needed.
type Allocator struct {
	mu        sync.Mutex
	pool      Range
	exclude   *IPSet
	taken     []Range // sorted, merged: exclusions + used + reserved
	used      map[netip.Addr]struct{}
	reserved  map[netip.Addr]struct{}
	cursor    netip.Addr
	available *big.Int
}

// NewAllocator creates a pool of p's usable hosts (IPv4 network and
// broadcast excluded for prefixes shorter than /31).
func NewAllocator(p netip.Prefix, exclude ...netip.Prefix) (*Allocator, error) {
	if !p.IsValid() {
		return nil, ErrInvalidPrefix
	}
	p = NormalizePrefix(p)
	f, l := usableBounds(p)
	r, err := NewRange(f, l)
	if err != nil {
		return nil, fmt.Errorf("%w: %s has no usable hosts", ErrExhausted, p)
	}
	return NewRangeAllocator(r, exclude...)
}

// NewRangeAllocator creates a pool over r.
func NewRangeAllocator(r Range, exclude ...netip.Prefix) (*Allocator, error) {
	if !r.IsValid() {
		return nil, ErrInvalidRange
	}
	ex := NewIPSet(exclude).Intersect(NewIPSet(r))
	return &Allocator{
		pool:      r,
		exclude:   ex,
		taken:     ex.Ranges(),
		used:      map[netip.Addr]struct{}{},
		reserved:  map[netip.Addr]struct{}{},
		cursor:    r.from,
		available: new(big.Int).Sub(r.Size(), ex.Size()),
	}, nil
}

// takenIndex returns the index of the taken range containing a, or -1.
func (al *Allocator) takenIndex(a netip.Addr) int {
	i, found := slices.BinarySearchFunc(al.taken, a, func(r Range, a netip.Addr) int {
		if r.to.Compare(a) < 0 {
			return -1
		}
		if r.from.Compare(a) > 0 {
			return 1
		}
		return 0
	})
	if !found {
		return -1
	}
	return i
}

func (al *Allocator) free(a netip.Addr) bool { return al.takenIndex(a) < 0 }

// markTaken inserts a single free address into taken, merging neighbors.
func (al *Allocator) markTaken(a netip.Addr) {
	r := Range{a, a}
	i, _ := slices.BinarySearchFunc(al.taken, a, func(x Range, a netip.Addr) int { return x.from.Compare(a) })
	al.taken = slices.Insert(al.taken, i, r)
	if i+1 < len(al.taken) {
		if m, ok := al.taken[i].Merge(al.taken[i+1]); ok {
			al.taken[i] = m
			al.taken = slices.Delete(al.taken, i+1, i+2)
		}
	}
	if i > 0 {
		if m, ok := al.taken[i-1].Merge(al.taken[i]); ok {
			al.taken[i-1] = m
			al.taken = slices.Delete(al.taken, i, i+1)
		}
	}
}

// unmarkTaken removes a from taken, splitting its range.
func (al *Allocator) unmarkTaken(a netip.Addr) {
	i := al.takenIndex(a)
	if i < 0 {
		return
	}
	parts := al.taken[i].Subtract(Range{a, a})
	al.taken = slices.Replace(al.taken, i, i+1, parts...)
}

// Available returns how many addresses can still be allocated.
func (al *Allocator) Available() *big.Int {
	al.mu.Lock()
	defer al.mu.Unlock()
	return new(big.Int).Set(al.available)
}

// IsFree reports whether a is in the pool and unallocated.
func (al *Allocator) IsFree(a netip.Addr) bool {
	a = Normalize(a)
	al.mu.Lock()
	defer al.mu.Unlock()
	return al.pool.Contains(a) && al.free(a)
}

// Allocate returns the next free address after the last one handed out,
// wrapping around. Returns ErrExhausted when the pool is full.
func (al *Allocator) Allocate() (netip.Addr, error) {
	al.mu.Lock()
	defer al.mu.Unlock()
	a, err := al.scan(al.cursor, 1)
	if err != nil {
		return a, err
	}
	al.take(a)
	if n, err := Next(a); err == nil && al.pool.Contains(n) {
		al.cursor = n
	} else {
		al.cursor = al.pool.from
	}
	return a, nil
}

// AllocatePrev returns the highest free address, scanning downward.
func (al *Allocator) AllocatePrev() (netip.Addr, error) {
	al.mu.Lock()
	defer al.mu.Unlock()
	a, err := al.scan(al.pool.to, -1)
	if err != nil {
		return a, err
	}
	al.take(a)
	return a, nil
}

// AllocateN allocates n addresses sequentially; on failure nothing is kept.
func (al *Allocator) AllocateN(n int) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, n)
	for range n {
		a, err := al.Allocate()
		if err != nil {
			for _, x := range out {
				al.Release(x)
			}
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// AllocateRandom picks a uniformly random start point and returns the first
// free address from there. Useful to avoid predictable addresses in IPv6.
func (al *Allocator) AllocateRandom() (netip.Addr, error) {
	al.mu.Lock()
	defer al.mu.Unlock()
	size := al.pool.Size()
	off, err := rand.Int(rand.Reader, size)
	if err != nil {
		return netip.Addr{}, err
	}
	start, _ := AddBig(al.pool.from, off)
	a, err := al.scan(start, 1)
	if err != nil {
		return a, err
	}
	al.take(a)
	return a, nil
}

// scan finds the first free address from start in dir (±1), wrapping once.
// O(log n) in the number of taken runs. Caller holds mu.
func (al *Allocator) scan(start netip.Addr, dir int) (netip.Addr, error) {
	if al.available.Sign() == 0 {
		return netip.Addr{}, ErrExhausted
	}
	a := start
	for range 2 { // at most one wrap
		i := al.takenIndex(a)
		if i < 0 {
			return a, nil
		}
		var next netip.Addr
		if dir > 0 {
			next = al.taken[i].to.Next()
		} else {
			next = al.taken[i].from.Prev()
		}
		if next.IsValid() && al.pool.Contains(next) {
			return next, nil // taken is merged, so the neighbor is free
		}
		if dir > 0 {
			a = al.pool.from
		} else {
			a = al.pool.to
		}
	}
	return netip.Addr{}, ErrExhausted
}

func (al *Allocator) take(a netip.Addr) {
	al.used[a] = struct{}{}
	al.markTaken(a)
	al.available.Sub(al.available, big.NewInt(1))
}

// Claim allocates a specific address.
func (al *Allocator) Claim(a netip.Addr) error { return al.mark(a, al.used) }

// Reserve marks a so it is never handed out (gateway, DNS, …).
func (al *Allocator) Reserve(a netip.Addr) error { return al.mark(a, al.reserved) }

func (al *Allocator) mark(a netip.Addr, m map[netip.Addr]struct{}) error {
	a = Normalize(a)
	al.mu.Lock()
	defer al.mu.Unlock()
	if !al.pool.Contains(a) {
		return fmt.Errorf("%w: %s", ErrNotInPool, a)
	}
	if !al.free(a) {
		return fmt.Errorf("%w: %s", ErrInUse, a)
	}
	m[a] = struct{}{}
	al.markTaken(a)
	al.available.Sub(al.available, big.NewInt(1))
	return nil
}

// Release returns an allocated or reserved address to the pool.
func (al *Allocator) Release(a netip.Addr) bool {
	a = Normalize(a)
	al.mu.Lock()
	defer al.mu.Unlock()
	for _, m := range []map[netip.Addr]struct{}{al.used, al.reserved} {
		if _, ok := m[a]; ok {
			delete(m, a)
			al.unmarkTaken(a)
			al.available.Add(al.available, big.NewInt(1))
			return true
		}
	}
	return false
}

// Allocated returns the currently allocated addresses, sorted.
func (al *Allocator) Allocated() []netip.Addr {
	al.mu.Lock()
	defer al.mu.Unlock()
	out := make([]netip.Addr, 0, len(al.used))
	for a := range al.used {
		out = append(out, a)
	}
	SortAddrs(out)
	return out
}

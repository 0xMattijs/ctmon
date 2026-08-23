// Package bounded provides a concurrent map that forgets everything at once
// when it fills up.
package bounded

import "sync"

// Map holds at most max entries. Reaching the ceiling drops the whole table
// and starts a new one.
//
// Throwing everything away is the point, not a shortcut around writing an LRU.
// Every table built on this one sheds work rather than deciding anything: a
// duplicate-hostname filter in front of a store that deduplicates for real, a
// DNS cache in front of a resolver that can be asked again, a per-address rate
// limiter whose budgets are a courtesy. Forgetting an entry early costs the
// work it would have saved — one lookup, one duplicate probe, one bucket
// refunded — and never a wrong answer. An LRU would buy accuracy none of them
// need, and charge a list update on every hit to do it.
//
// What that costs has to be paid at the ceiling, so size it well above what a
// busy moment holds: the loss lands all at once, not entry by entry.
//
// A Map is safe for concurrent use. A nil *Map is not: use New.
type Map[K comparable, V any] struct {
	mu  sync.Mutex
	max int
	m   map[K]V
}

// New returns a Map holding at most max entries.
//
// The table starts at a quarter of max. It grows into the rest on its own, and
// starting it full-size would commit the whole footprint to a Map that may
// never fill.
func New[K comparable, V any](max int) *Map[K, V] {
	return &Map[K, V]{max: max, m: make(map[K]V, max/4)}
}

// Get returns the value stored for k.
func (b *Map[K, V]) Get(k K) (V, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.m[k]
	return v, ok
}

// Put stores v under k, emptying the table first if it is full.
func (b *Map[K, V]) Put(k K, v V) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.evictIfFull()
	b.m[k] = v
}

// GetOrPut returns the value stored for k, calling make to build one when
// there is none. It reports whether the value was already there.
//
// make runs under the lock, so it must not be slow or reach back into the
// Map. It is for building the value itself — a fresh limiter, an empty
// marker — and not for the work that value goes on to do, which belongs after
// GetOrPut returns.
func (b *Map[K, V]) GetOrPut(k K, make func() V) (V, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if v, ok := b.m[k]; ok {
		return v, true
	}
	b.evictIfFull()
	v := make()
	b.m[k] = v
	return v, false
}

// Len reports how many entries are held.
func (b *Map[K, V]) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.m)
}

// evictIfFull empties the table when it has reached its ceiling. The caller
// holds the lock.
func (b *Map[K, V]) evictIfFull() {
	if len(b.m) >= b.max {
		b.m = make(map[K]V, b.max/4)
	}
}

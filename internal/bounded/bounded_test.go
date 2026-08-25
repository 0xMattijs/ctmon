package bounded

import (
	"strconv"
	"sync"
	"testing"
)

func TestGetPut(t *testing.T) {
	m := New[string, int](10)
	if _, ok := m.Get("a"); ok {
		t.Fatal("empty map returned a value")
	}
	m.Put("a", 1)
	if v, ok := m.Get("a"); !ok || v != 1 {
		t.Fatalf("Get(a) = %v, %v; want 1, true", v, ok)
	}
	m.Put("a", 2)
	if v, _ := m.Get("a"); v != 2 {
		t.Fatalf("Put did not overwrite: got %v", v)
	}
	if m.Len() != 1 {
		t.Fatalf("Len = %d, want 1", m.Len())
	}
}

func TestGetOrPut(t *testing.T) {
	m := New[string, int](10)
	calls := 0
	v, existed := m.GetOrPut("a", func() int { calls++; return 7 })
	if v != 7 || existed {
		t.Fatalf("first GetOrPut = %v, %v; want 7, false", v, existed)
	}
	v, existed = m.GetOrPut("a", func() int { calls++; return 9 })
	if v != 7 || !existed {
		t.Fatalf("second GetOrPut = %v, %v; want 7, true", v, existed)
	}
	if calls != 1 {
		t.Fatalf("make called %d times, want 1", calls)
	}
}

// The ceiling is the whole point, so check that reaching it empties the table
// rather than letting it grow without end.
func TestEvictsAtCeiling(t *testing.T) {
	const max = 8
	m := New[int, int](max)
	for i := range max * 4 {
		m.Put(i, i)
		if m.Len() > max {
			t.Fatalf("after %d puts Len = %d, over the ceiling of %d", i+1, m.Len(), max)
		}
	}
	// The last entry written survives the most recent eviction.
	if _, ok := m.Get(max*4 - 1); !ok {
		t.Fatal("the entry written last is missing")
	}
}

func TestGetOrPutEvicts(t *testing.T) {
	const max = 8
	m := New[int, int](max)
	for i := range max * 4 {
		m.GetOrPut(i, func() int { return i })
		if m.Len() > max {
			t.Fatalf("after %d calls Len = %d, over the ceiling of %d", i+1, m.Len(), max)
		}
	}
}

// Concurrent use is the reason the lock is in here rather than at each call
// site. Run under -race.
func TestConcurrent(t *testing.T) {
	m := New[string, int](64)
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 500 {
				k := strconv.Itoa((w*500 + i) % 200)
				m.Put(k, i)
				m.Get(k)
				m.GetOrPut(k, func() int { return i })
				m.Len()
			}
		}()
	}
	wg.Wait()
	if m.Len() > 64 {
		t.Fatalf("Len = %d, over the ceiling", m.Len())
	}
}

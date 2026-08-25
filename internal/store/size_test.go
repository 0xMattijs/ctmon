package store

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// fragmented writes a database, empties it again, and returns its path along
// with the allocation high-water mark tx.Size() reports. Every page the keys
// held is on the freelist by the end: allocated, below the high-water mark,
// and holding nothing.
func fragmented(t *testing.T) (path string, high int64) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "free.db")
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}()
	db.NoSync = true

	const keys = 20000
	value := make([]byte, 128)
	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte("filler"))
		if err != nil {
			return err
		}
		for i := 0; i < keys; i++ {
			if err := b.Put([]byte(fmt.Sprintf("%08d", i)), value); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("fill: %v", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		return tx.DeleteBucket([]byte("filler"))
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	// A write transaction is what hands pending pages back to the freelist.
	// Both counts are subtracted, so this only makes the test read the number
	// the way a long-running store would.
	if err := db.Update(func(*bolt.Tx) error { return nil }); err != nil {
		t.Fatalf("settle: %v", err)
	}

	_ = db.View(func(tx *bolt.Tx) error {
		high = tx.Size()
		return nil
	})
	if used := usedBytes(db); used >= high/2 {
		t.Fatalf("used %d of a %d high-water mark, want the freed pages left out", used, high)
	}
	return path, high
}

// usedBytes must leave the freelist out. Counting it was what made a
// compaction report claim the leaves were fuller than they were.
func TestUsedBytesLeavesOutTheFreelist(t *testing.T) {
	path, high := fragmented(t)

	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db.Close()
	if used := usedBytes(db); used >= high/2 {
		t.Errorf("used = %d, high-water mark = %d, want the freed pages left out", used, high)
	}
}

// The same measured through a read-only handle, which is how compact, migrate,
// and stats see the file they report on. bolt loads the freelist for those
// only when asked; without that the free pages are invisible and the number
// falls back to the high-water mark.
func TestUsedBytesAtSeesTheFreelist(t *testing.T) {
	path, high := fragmented(t)

	switch used := usedBytesAt(path); {
	case used == high:
		t.Errorf("used = %d, the whole high-water mark: the freelist was not loaded", used)
	case used >= high/2:
		t.Errorf("used = %d, high-water mark = %d, want the freed pages left out", used, high)
	case used <= 0:
		t.Errorf("used = %d, want the pages the meta and root still hold", used)
	}
}

// Stats reports the size the file occupies, not bolt's high-water mark. The
// two differ on any database: bolt maps the file in steps and grows it past
// what it has allocated.
func TestStatsReportsTheFileSize(t *testing.T) {
	s := open(t)
	for i := 0; i < 100; i++ {
		host := fmt.Sprintf("host%d.example.com", i)
		err := s.Update(host, func(r *Record, existed bool) bool {
			r.FirstSeen, r.LastSeen = time.Now().UTC(), time.Now().UTC()
			r.SeenCount = 1
			return true
		})
		if err != nil {
			t.Fatalf("update %s: %v", host, err)
		}
	}

	st, err := s.Stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	info, err := os.Stat(s.path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Bytes != info.Size() {
		t.Errorf("Bytes = %d, file is %d", st.Bytes, info.Size())
	}
	if st.Used <= 0 || st.Used > st.Bytes {
		t.Errorf("Used = %d, want between 0 and the %d byte file", st.Used, st.Bytes)
	}
}

// scrambled writes a store and then zeroes everything after the meta pages,
// leaving the length alone. The freelist bolt is told to read is inside the
// file and is not a freelist, which is the damage a recover can do something
// about; truncating instead would put pages outside the mapping, and reading
// one of those is a SIGBUS that takes the process with it either way.
func scrambled(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scrambled.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s.db.NoSync = true
	s.db.MaxBatchDelay = 0
	for i := 0; i < 2000; i++ {
		host := fmt.Sprintf("host%d.example.com", i)
		err := s.Update(host, func(r *Record, existed bool) bool {
			r.FirstSeen, r.LastSeen = time.Now().UTC(), time.Now().UTC()
			r.SeenCount = 1
			return true
		})
		if err != nil {
			t.Fatalf("update %s: %v", host, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Past the two meta pages, so bolt still finds the file and still
	// believes what it says about where the freelist is.
	from := int64(2 * os.Getpagesize())
	if _, err := f.WriteAt(make([]byte, info.Size()-from), from); err != nil {
		t.Fatalf("scramble: %v", err)
	}
	return path
}

// Loading the freelist at open moves a failure that used to surface on a
// later read into the open itself, and bolt reports that one by panicking. A
// command asked to report on a damaged file has to say so instead.
func TestOpenReadOnlyReportsAnUnreadableFreelist(t *testing.T) {
	path := scrambled(t)

	s, err := OpenReadOnly(path)
	if err == nil {
		s.Close()
		t.Fatalf("OpenReadOnly succeeded on a database with no readable freelist")
	}
	t.Logf("error: %v", err)
}

// usedBytesAt only ever feeds a progress report, and promises 0 for a file it
// cannot read rather than taking the command down with it.
func TestUsedBytesAtReportsZeroForAnUnreadableFreelist(t *testing.T) {
	if n := usedBytesAt(scrambled(t)); n != 0 {
		t.Errorf("usedBytesAt = %d, want 0", n)
	}
}

// Stats measures through the same handle a compaction closes and replaces, so
// the measurement has to take the lock the swap holds. Without it, a stats
// call running alongside compactLoop races on the handle and, landing
// mid-swap, measures a closed database as zero. Hold the lock and watch the
// call wait for it.
func TestUsedBytesWaitsForTheHandleLock(t *testing.T) {
	s := open(t)
	err := s.Update("only.example.com", func(r *Record, existed bool) bool {
		r.FirstSeen, r.LastSeen = time.Now().UTC(), time.Now().UTC()
		r.SeenCount = 1
		return true
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	s.mu.Lock()
	measured := make(chan int64, 1)
	go func() { measured <- s.usedBytes() }()

	select {
	case n := <-measured:
		s.mu.Unlock()
		t.Fatalf("usedBytes returned %d while the handle was locked", n)
	case <-time.After(50 * time.Millisecond):
	}
	s.mu.Unlock()

	if n := <-measured; n <= 0 {
		t.Errorf("usedBytes = %d once the lock was free, want the pages it holds", n)
	}
}

// The path a store was opened from can be replaced, or taken away, while the
// handle goes on reading the file it holds. A size is not worth failing the
// whole report over, and zero is not an answer.
func TestStatsFallsBackWhenThePathIsGone(t *testing.T) {
	s := open(t)
	err := s.Update("only.example.com", func(r *Record, existed bool) bool {
		r.FirstSeen, r.LastSeen = time.Now().UTC(), time.Now().UTC()
		r.SeenCount = 1
		return true
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := os.Remove(s.path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	st, err := s.Stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if st.Bytes <= 0 || st.Bytes < st.Used {
		t.Errorf("Bytes = %d with %d in use, want the high-water mark", st.Bytes, st.Used)
	}
}

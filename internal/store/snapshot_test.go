package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// put writes one minimal record.
func put(t *testing.T, s *Store, host string) {
	t.Helper()
	now := time.Now()
	err := s.Update(host, func(r *Record, existed bool) bool {
		r.FirstSeen, r.LastSeen, r.SeenCount = now, now, 1
		r.Source = "https://ct.example/log"
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotIsReadableAndComplete(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	want := map[string]bool{}
	for i := 0; i < 500; i++ {
		host := fmt.Sprintf("h%03d.example.com", i)
		put(t, s, host)
		want[host] = true
	}
	if err := s.SetLogPos("https://ct.example/log", 4242); err != nil {
		t.Fatal(err)
	}

	snap := filepath.Join(dir, "live.db.snap")
	n, err := s.Snapshot(snap)
	if err != nil {
		t.Fatal(err)
	}
	if n <= 0 {
		t.Errorf("snapshot reported %d bytes", n)
	}

	// The live store must still be usable, and the snapshot must open as an
	// ordinary database in a second handle while the first is still up.
	put(t, s, "after.example.com")

	got, err := Open(snap)
	if err != nil {
		t.Fatalf("snapshot does not open: %v", err)
	}
	defer got.Close()

	seen := map[string]bool{}
	if err := got.ForEach(func(r *Record) error {
		seen[r.Host] = true
		return nil
	}); err != nil {
		t.Fatalf("walking the snapshot: %v", err)
	}
	for host := range want {
		if !seen[host] {
			t.Fatalf("%s missing from the snapshot", host)
		}
	}
	if seen["after.example.com"] {
		t.Error("snapshot contains a record written after it was taken")
	}
	// Interned dictionaries and log positions have to survive, or the copy
	// decodes to records with empty sources.
	if pos, ok, err := got.LogPos("https://ct.example/log"); err != nil || !ok || pos != 4242 {
		t.Errorf("log position in snapshot = %d, %v, %v; want 4242", pos, ok, err)
	}
	var rec *Record
	if rec, err = got.Get("h001.example.com"); err != nil || rec == nil {
		t.Fatalf("Get from snapshot: %v, %v", rec, err)
	}
	if rec.Source != "https://ct.example/log" {
		t.Errorf("source = %q, want the interned value", rec.Source)
	}
}

// The point of the feature is snapshotting a store that is being written, so
// that is what the test does.
func TestSnapshotUnderConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for i := 0; i < 200; i++ {
		put(t, s, fmt.Sprintf("seed%03d.example.com", i))
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				host := fmt.Sprintf("w%d-%05d.example.com", w, i)
				_ = s.Update(host, func(r *Record, existed bool) bool {
					r.FirstSeen, r.LastSeen, r.SeenCount = time.Now(), time.Now(), 1
					r.Source = fmt.Sprintf("https://ct.example/log%d", w)
					return true
				})
			}
		}(w)
	}

	snap := filepath.Join(dir, "live.db.snap")
	for i := 0; i < 5; i++ {
		if _, err := s.Snapshot(snap); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("snapshot %d failed: %v", i, err)
		}
		// Every snapshot must be a whole database, not a torn one.
		got, err := Open(snap)
		if err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("snapshot %d does not open: %v", i, err)
		}
		n := 0
		err = got.ForEach(func(r *Record) error {
			n++
			if n > 1_000_000 {
				return fmt.Errorf("walk is not terminating; the tree is torn")
			}
			return nil
		})
		got.Close()
		if err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("snapshot %d: %v", i, err)
		}
		if n < 200 {
			close(stop)
			wg.Wait()
			t.Fatalf("snapshot %d holds %d records, want at least the 200 seeded", i, n)
		}
	}
	close(stop)
	wg.Wait()
}

func TestSnapshotLeavesNoPartialFile(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	put(t, s, "example.com")

	snap := filepath.Join(dir, "live.db.snap")
	if _, err := s.Snapshot(snap); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(snap + ".writing"); !os.IsNotExist(err) {
		t.Error("the .writing scratch file was left behind")
	}

	// A path that cannot be created must fail without leaving anything.
	if _, err := s.Snapshot(filepath.Join(dir, "no-such-dir", "x.snap")); err == nil {
		t.Error("Snapshot accepted an uncreatable path")
	}
}

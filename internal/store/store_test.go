package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// digest returns a real sha256 hex digest, the only thing the store accepts
// in a hash field.
func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestUpdateAndGet(t *testing.T) {
	s := open(t)

	if rec, err := s.Get("example.com"); err != nil || rec != nil {
		t.Fatalf("Get on empty store = %v, %v; want nil, nil", rec, err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	err := s.Update("example.com", func(r *Record, existed bool) bool {
		if existed {
			t.Error("record should not exist yet")
		}
		r.CertName = "*.example.com"
		r.FromWildcard = true
		r.FirstSeen = now
		r.BodyHash = digest("abc")
		return true
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	rec, err := s.Get("example.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if rec.Host != "example.com" || rec.CertName != "*.example.com" || !rec.FromWildcard {
		t.Errorf("record round-tripped wrong: %+v", rec)
	}
	if !rec.FirstSeen.Equal(now) {
		t.Errorf("FirstSeen = %v, want %v", rec.FirstSeen, now)
	}

	// A second update sees the existing record.
	err = s.Update("example.com", func(r *Record, existed bool) bool {
		if !existed {
			t.Error("record should exist by now")
		}
		r.PrevHash, r.BodyHash = r.BodyHash, digest("def")
		return true
	})
	if err != nil {
		t.Fatalf("second update: %v", err)
	}
	rec, _ = s.Get("example.com")
	if rec.BodyHash != digest("def") || rec.PrevHash != digest("abc") {
		t.Errorf("hashes = %s/%s, want the def/abc digests", rec.BodyHash, rec.PrevHash)
	}
}

func TestUpdateSkipsWriteWhenUnchanged(t *testing.T) {
	s := open(t)
	if err := s.Update("skip.example", func(r *Record, existed bool) bool { return false }); err != nil {
		t.Fatalf("update: %v", err)
	}
	rec, err := s.Get("skip.example")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if rec != nil {
		t.Errorf("record was written despite fn returning false: %+v", rec)
	}
}

func TestLogPositions(t *testing.T) {
	s := open(t)
	const uri = "https://ct.example/logs/x"

	if _, ok, err := s.LogPos(uri); err != nil || ok {
		t.Fatalf("LogPos on empty store = ok %v, err %v; want false, nil", ok, err)
	}
	if err := s.SetLogPos(uri, 42); err != nil {
		t.Fatalf("set: %v", err)
	}
	pos, ok, err := s.LogPos(uri)
	if err != nil || !ok || pos != 42 {
		t.Fatalf("LogPos = %d, %v, %v; want 42, true, nil", pos, ok, err)
	}
}

func TestStats(t *testing.T) {
	s := open(t)
	mk := func(host string, wild, probed bool, hash, prev, perr string) {
		t.Helper()
		err := s.Update(host, func(r *Record, _ bool) bool {
			r.FromWildcard, r.Probed = wild, probed
			r.BodyHash, r.PrevHash, r.ProbeError = hash, prev, perr
			return true
		})
		if err != nil {
			t.Fatalf("update %s: %v", host, err)
		}
	}
	mk("a.test", false, true, digest("h1"), "", "")
	mk("b.test", true, true, digest("h2"), digest("h1"), "")
	mk("c.test", true, true, "", "", "dial failed")
	mk("d.test", false, false, "", "", "")
	if err := s.SetLogPos("https://ct.example/logs/x", 7); err != nil {
		t.Fatal(err)
	}

	st, err := s.Stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	want := Stats{Domains: 4, Probed: 3, WithHash: 2, Wildcards: 2, Errors: 1, Changed: 1}
	if st.Domains != want.Domains || st.Probed != want.Probed || st.WithHash != want.WithHash ||
		st.Wildcards != want.Wildcards || st.Errors != want.Errors || st.Changed != want.Changed {
		t.Errorf("stats = %+v, want %+v", st, want)
	}
	if st.Logs["https://ct.example/logs/x"] != 7 {
		t.Errorf("log positions = %v", st.Logs)
	}
}

func TestForEachIsSorted(t *testing.T) {
	s := open(t)
	for _, h := range []string{"c.test", "a.test", "b.test"} {
		if err := s.Update(h, func(r *Record, _ bool) bool { return true }); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	if err := s.ForEach(func(r *Record) error {
		got = append(got, r.Host)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != "a.test" || got[1] != "b.test" || got[2] != "c.test" {
		t.Errorf("ForEach order = %v", got)
	}
}

func TestCompactShrinksAndKeepsEverything(t *testing.T) {
	s := open(t)

	// Slack needs enough records to span many pages. Neither bolt's fsyncs
	// nor the 10 ms it waits to gather a batch are what this test is about.
	s.db.NoSync = true
	s.db.MaxBatchDelay = 0

	const records = 3000
	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < records; i++ {
		host := fmt.Sprintf("host%d.example%d.com", i, i%97)
		err := s.Update(host, func(r *Record, existed bool) bool {
			r.FirstSeen, r.LastSeen = now, now
			r.SeenCount = 1
			r.Source = "https://ct.example.com/logs/x/"
			r.Issuer = "Example CA"
			r.BodyHash = digest(host)
			return true
		})
		if err != nil {
			t.Fatalf("update %s: %v", host, err)
		}
	}
	if err := s.SetLogPos("https://ct.example.com/logs/x/", 42); err != nil {
		t.Fatalf("set log pos: %v", err)
	}
	before := s.usedBytes()

	res, err := s.Compact()
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	if res.NewUsed >= res.OldUsed {
		t.Errorf("used %d -> %d, want smaller", res.OldUsed, res.NewUsed)
	}
	if got := s.usedBytes(); got != res.NewUsed || got >= before {
		t.Errorf("used after compaction = %d, want %d and below %d", got, res.NewUsed, before)
	}

	// Everything the compacted file holds must still decode, including the
	// interned source and issuer, which are only ids in the record itself.
	n := 0
	err = s.ForEach(func(r *Record) error {
		n++
		if r.Source != "https://ct.example.com/logs/x/" || r.Issuer != "Example CA" {
			return fmt.Errorf("%s: interned fields lost: %q %q", r.Host, r.Source, r.Issuer)
		}
		if r.BodyHash != digest(r.Host) {
			return fmt.Errorf("%s: hash = %s", r.Host, r.BodyHash)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != records {
		t.Errorf("records after compaction = %d, want %d", n, records)
	}
	if pos, ok, _ := s.LogPos("https://ct.example.com/logs/x/"); !ok || pos != 42 {
		t.Errorf("log pos = %d, %v; want 42, true", pos, ok)
	}

	// The handle was swapped, so writes have to keep working through it.
	if err := s.Update("after.example.com", func(r *Record, existed bool) bool {
		if existed {
			t.Error("record should not exist yet")
		}
		r.FirstSeen = now
		return true
	}); err != nil {
		t.Fatalf("update after compaction: %v", err)
	}
	if rec, err := s.Get("after.example.com"); err != nil || rec == nil {
		t.Fatalf("get after compaction = %v, %v", rec, err)
	}
}

func TestCompactUnderConcurrentUse(t *testing.T) {
	s := open(t)

	now := time.Now().UTC().Truncate(time.Second)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				host := fmt.Sprintf("h%d-%d.example.com", w, i)
				if err := s.Update(host, func(r *Record, existed bool) bool {
					r.FirstSeen = now
					return true
				}); err != nil {
					t.Errorf("update %s: %v", host, err)
					return
				}
				if _, err := s.Get(host); err != nil {
					t.Errorf("get %s: %v", host, err)
					return
				}
			}
		}(w)
	}

	for i := 0; i < 3; i++ {
		if _, err := s.Compact(); err != nil {
			t.Fatalf("compact %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
}

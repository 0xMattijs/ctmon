package store

import (
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// withError writes a record carrying a probe error from source and issuer.
func withError(t *testing.T, s *Store, host, source, issuer, probeErr string, when time.Time) {
	t.Helper()
	err := s.Update(host, func(r *Record, existed bool) bool {
		r.FirstSeen, r.LastSeen = when, when
		r.Source, r.Issuer = source, issuer
		r.Probed, r.ProbedAt, r.ProbeError = true, when, probeErr
		return true
	})
	if err != nil {
		t.Fatalf("update %s: %v", host, err)
	}
}

// dictLen reports how many entries a dictionary bucket holds on disk, which is
// the number the in-memory tables are supposed to agree with.
func dictLen(t *testing.T, s *Store, d *dict) int {
	t.Helper()
	n := 0
	err := s.view(func(tx *bolt.Tx) error {
		b := tx.Bucket(d.bucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, _ []byte) error {
			if len(k) == 4 {
				n++
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("count %s: %v", d.bucket, err)
	}
	return n
}

func TestSweepDropsWhatNoRecordUses(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	old := now.Add(-100 * 24 * time.Hour)

	withError(t, s, "gone.example.com", "ctlog-a", "CA One", "dial tcp 10.0.0.1:443: refused", old)
	withError(t, s, "stays.example.com", "ctlog-b", "CA Two", "lookup stays.example.com: no such host", now)

	if got := dictLen(t, s, s.errors); got != 2 {
		t.Fatalf("error shapes = %d; want 2", got)
	}

	// Delete the first record, which is the only user of ctlog-a, CA One and
	// its error shape.
	if _, err := s.Prune(PruneOptions{Match: Unseen(now.Add(-90 * 24 * time.Hour))}); err != nil {
		t.Fatal(err)
	}

	res, err := s.SweepDicts()
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.Sources != 1 || res.Issuers != 1 || res.Errors != 1 {
		t.Errorf("sweep = %+v; want one of each", res)
	}
	if res.Bytes <= 0 {
		t.Errorf("sweep reported %d bytes; want the entries it dropped", res.Bytes)
	}
	for _, c := range []struct {
		name string
		d    *dict
	}{{"sources", s.sources}, {"issuers", s.issuers}, {"errors", s.errors}} {
		if got := dictLen(t, s, c.d); got != 1 {
			t.Errorf("%s left %d entries on disk; want 1", c.name, got)
		}
		if got := c.d.len(); got != 1 {
			t.Errorf("%s in-memory table has %d entries; want 1", c.name, got)
		}
	}
}

// The record that survives has to still read correctly afterwards — the ids it
// holds must not have moved.
func TestSweepLeavesSurvivorsReadable(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	old := now.Add(-100 * 24 * time.Hour)

	for i, host := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		when := now
		if i == 0 {
			when = old
		}
		withError(t, s, host, "src-"+host, "issuer-"+host, "lookup "+host+": no such host", when)
	}
	if _, err := s.Prune(PruneOptions{Match: Unseen(now.Add(-90 * 24 * time.Hour))}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SweepDicts(); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	for _, host := range []string{"b.example.com", "c.example.com"} {
		rec, err := s.Get(host)
		if err != nil {
			t.Fatalf("get %s: %v", host, err)
		}
		if rec == nil {
			t.Fatalf("%s went missing", host)
		}
		if rec.Source != "src-"+host || rec.Issuer != "issuer-"+host {
			t.Errorf("%s reads back as %+v; ids moved under it", host, rec)
		}
		if want := "lookup " + host + ": no such host"; rec.ProbeError != want {
			t.Errorf("%s error = %q; want %q", host, rec.ProbeError, want)
		}
	}
}

// A name forgotten from the file must be forgotten in memory too. Left marked
// durable, it would be handed back by intern without being written, and the
// next open would find a record pointing at an entry that is not there.
func TestSweepRewritesAForgottenNameOnReuse(t *testing.T) {
	dir := t.TempDir() + "/reuse.db"
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	old := now.Add(-100 * 24 * time.Hour)

	withError(t, s, "gone.example.com", "lonely-source", "Lonely CA", "lookup x: no such host", old)
	withError(t, s, "keep.example.com", "other-source", "Other CA", "read body: unexpected EOF", now)
	if _, err := s.Prune(PruneOptions{Match: Unseen(now.Add(-90 * 24 * time.Hour))}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SweepDicts(); err != nil {
		t.Fatal(err)
	}

	// The same vocabulary arrives again on a new record.
	withError(t, s, "new.example.com", "lonely-source", "Lonely CA", "lookup x: no such host", now)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopened from the file alone: if the entries were not rewritten, this
	// record reads back with empty fields.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	rec, err := s2.Get("new.example.com")
	if err != nil || rec == nil {
		t.Fatalf("get: %v, %v", rec, err)
	}
	if rec.Source != "lonely-source" || rec.Issuer != "Lonely CA" {
		t.Errorf("record reads back as source=%q issuer=%q; the forgotten entries were not rewritten",
			rec.Source, rec.Issuer)
	}
	if rec.ProbeError != "lookup x: no such host" {
		t.Errorf("error reads back as %q; the forgotten entry was not rewritten", rec.ProbeError)
	}
}

func TestSweepOnAnUntouchedStoreDropsNothing(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	withError(t, s, "a.example.com", "src", "CA", "lookup a.example.com: no such host", now)

	res, err := s.SweepDicts()
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.Total() != 0 {
		t.Errorf("sweep of an untouched store = %+v; want nothing dropped", res)
	}
}

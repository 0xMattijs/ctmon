package store

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func hosts(items []Pending) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.Host
	}
	return out
}

// Order is by how long a host has waited, not by what it is called. The scan
// this replaced went in reversed-hostname order, which is why a live store had
// .ai at 97% probed and .com at 3%.
func TestPendingComesOutOldestFirst(t *testing.T) {
	db := openTemp(t)
	now := time.Now().UTC()
	for i, h := range []string{"aaa.test", "mmm.test", "zzz.test"} {
		// Queued in reverse age order: zzz has waited longest.
		if err := db.Enqueue(h, now.Add(-time.Duration(i+1)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}

	got, err := db.PendingLease(now, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"zzz.test", "mmm.test", "aaa.test"}
	if fmt.Sprint(hosts(got)) != fmt.Sprint(want) {
		t.Errorf("leased %v, want %v", hosts(got), want)
	}
}

func TestPendingHoldsBackWhatIsNotDue(t *testing.T) {
	db := openTemp(t)
	now := time.Now().UTC()
	if err := db.Enqueue("soon.test", now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := db.Enqueue("later.test", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	got, err := db.PendingLease(now, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Host != "soon.test" {
		t.Errorf("leased %v, want only the host that is due", hosts(got))
	}
}

func TestPendingRespectsLimit(t *testing.T) {
	db := openTemp(t)
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		if err := db.Enqueue(fmt.Sprintf("h%d.test", i), now.Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.PendingLease(now, 2, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("leased %d hosts, want the 2-host limit", len(got))
	}
}

// A leased host is out of circulation until the lease runs out, so two sweeps
// in a row do not hand the same work to two probers.
func TestLeaseHidesAHostThenGivesItBack(t *testing.T) {
	db := openTemp(t)
	now := time.Now().UTC()
	if err := db.Enqueue("host.test", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	first, err := db.PendingLease(now, 10, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 {
		t.Fatalf("leased %d hosts, want 1", len(first))
	}

	again, err := db.PendingLease(now.Add(time.Minute), 10, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Errorf("leased %v while the lease was still held", hosts(again))
	}

	// This is the crash case: nobody called PendingDone, and the host comes
	// back rather than being lost.
	expired, err := db.PendingLease(now.Add(6*time.Minute), 10, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0].Host != "host.test" {
		t.Errorf("leased %v after the lease expired, want [host.test]", hosts(expired))
	}
}

func TestPendingDoneDropsTheEntry(t *testing.T) {
	db := openTemp(t)
	now := time.Now().UTC()
	if err := db.Enqueue("host.test", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	leased, err := db.PendingLease(now, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PendingDone(leased[0].Key); err != nil {
		t.Fatal(err)
	}

	n, oldest, err := db.PendingStats()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("queue holds %d entries after the work was finished, want 0", n)
	}
	if !oldest.IsZero() {
		t.Errorf("oldest = %v on an empty queue, want the zero time", oldest)
	}
	// Releasing a key twice is what happens when a lease expires and someone
	// else finishes the work. It is not an error.
	if err := db.PendingDone(leased[0].Key); err != nil {
		t.Errorf("second release: %v", err)
	}
}

func TestUpdateWithQueueWritesBothOrNeither(t *testing.T) {
	db := openTemp(t)
	due := time.Now().UTC().Add(-time.Minute)

	err := db.UpdateWithQueue("kept.test", func(r *Record, _ bool) (bool, time.Time) {
		r.CertName = "kept.test"
		return true, due
	})
	if err != nil {
		t.Fatal(err)
	}
	// A write that asks for nothing queues nothing.
	err = db.UpdateWithQueue("quiet.test", func(r *Record, _ bool) (bool, time.Time) {
		return true, time.Time{}
	})
	if err != nil {
		t.Fatal(err)
	}
	// An abandoned write leaves no queue entry behind either.
	err = db.UpdateWithQueue("dropped.test", func(r *Record, _ bool) (bool, time.Time) {
		return false, due
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := db.PendingLease(time.Now().UTC(), 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Host != "kept.test" {
		t.Errorf("queued %v, want only [kept.test]", hosts(got))
	}
	if rec, err := db.Get("dropped.test"); err != nil || rec != nil {
		t.Errorf("dropped.test = %v, %v; want no record", rec, err)
	}
}

// Seeding is what makes a database written before the queue usable: without
// it every host already in the store would sit unprobed forever.
func TestSeedPendingFillsTheQueueOnce(t *testing.T) {
	db := openTemp(t)
	seen := time.Now().UTC().Add(-time.Hour)
	for _, h := range []string{"a.test", "b.test"} {
		err := db.Update(h, func(r *Record, _ bool) bool {
			r.FirstSeen = seen
			return true
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	err := db.Update("done.test", func(r *Record, _ bool) bool {
		r.FirstSeen, r.Probed = seen, true
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	due := func(r *Record) (time.Time, bool) {
		if r.Probed {
			return time.Time{}, false
		}
		return r.FirstSeen, true
	}
	queued, ran, err := db.SeedPending(due, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ran || queued != 2 {
		t.Errorf("seed queued %d hosts (ran=%v), want 2", queued, ran)
	}

	// Running again does nothing: the queue is now the record of what is
	// owed, and re-seeding would duplicate every entry still in it.
	queued, ran, err = db.SeedPending(due, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ran || queued != 0 {
		t.Errorf("second seed queued %d hosts (ran=%v), want none", queued, ran)
	}
}

// The seed walks in chunks, so it has to pick up in the right place each time.
func TestSeedPendingSpansChunks(t *testing.T) {
	db := openTemp(t)
	defer func(orig int) { seedChunk = orig }(seedChunk)
	seedChunk = 10

	const n = 37
	for i := 0; i < n; i++ {
		host := fmt.Sprintf("h%06d.test", i)
		if err := db.Update(host, func(r *Record, _ bool) bool { return true }); err != nil {
			t.Fatal(err)
		}
	}

	queued, _, err := db.SeedPending(
		func(r *Record) (time.Time, bool) { return r.FirstSeen, true }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if queued != n {
		t.Errorf("seed queued %d of %d hosts", queued, n)
	}
	if got, _, err := db.PendingStats(); err != nil || got != n {
		t.Errorf("queue holds %d entries (err %v), want %d", got, err, n)
	}
}

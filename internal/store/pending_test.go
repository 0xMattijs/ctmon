package store

import (
	"errors"
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
	queued, ran, err := db.SeedPending("gen1", due, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ran || queued != 2 {
		t.Errorf("seed queued %d hosts (ran=%v), want 2", queued, ran)
	}

	// Running again does nothing: the queue is now the record of what is
	// owed, and re-seeding would duplicate every entry still in it.
	queued, ran, err = db.SeedPending("gen1", due, nil)
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

	queued, _, err := db.SeedPending("gen1",
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

// Changing the re-probe policy changes which records belong in the queue, so
// the store has to be seeded again. Without this, turning --reprobe on never
// reaches the records that were already there when it was off.
func TestSeedRunsAgainWhenThePolicyChanges(t *testing.T) {
	db := openTemp(t)
	probed := time.Now().UTC().Add(-time.Hour)
	err := db.Update("done.test", func(r *Record, _ bool) bool {
		r.Probed, r.ProbedAt, r.FirstSeen = true, probed, probed
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	// No re-probing: a host already probed wants nothing.
	noReprobe := func(r *Record) (time.Time, bool) {
		if r.Probed {
			return time.Time{}, false
		}
		return r.FirstSeen, true
	}
	if queued, _, err := db.SeedPending("reprobe=0", noReprobe, nil); err != nil || queued != 0 {
		t.Fatalf("seed queued %d (err %v), want none", queued, err)
	}

	// Turn re-probing on, and the same record is now owed one.
	withReprobe := func(r *Record) (time.Time, bool) {
		if r.Probed {
			return r.ProbedAt.Add(time.Minute), true
		}
		return r.FirstSeen, true
	}
	queued, ran, err := db.SeedPending("reprobe=1m", withReprobe, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ran || queued != 1 {
		t.Errorf("seed queued %d (ran=%v), want the probed host re-queued", queued, ran)
	}
	// And it does not run a third time for the same policy.
	if _, ran, err := db.SeedPending("reprobe=1m", withReprobe, nil); err != nil || ran {
		t.Errorf("seed ran again for an unchanged policy (err %v)", err)
	}
}

// An interrupted seed picks up where it stopped. Walking from the top again
// would queue every host the first attempt had already queued.
func TestSeedResumesFromWhereItStopped(t *testing.T) {
	db := openTemp(t)
	defer func(orig int) { seedChunk = orig }(seedChunk)
	seedChunk = 10

	const n = 30
	for i := 0; i < n; i++ {
		host := fmt.Sprintf("h%03d.test", i)
		if err := db.Update(host, func(r *Record, _ bool) bool { return true }); err != nil {
			t.Fatal(err)
		}
	}

	// Stop part way through, the way a killed process does: the chunks
	// already committed stay, and so does the cursor.
	func() {
		defer func() { _ = recover() }()
		chunks := 0
		db.SeedPending("gen1",
			func(r *Record) (time.Time, bool) { return r.FirstSeen, true },
			func(int, int) {
				if chunks++; chunks >= 2 {
					panic(errors.New("killed"))
				}
			})
	}()

	// Resuming must not re-queue what the first pass already did.
	before, _, err := db.PendingStats()
	if err != nil {
		t.Fatal(err)
	}
	queued, ran, err := db.SeedPending("gen1",
		func(r *Record) (time.Time, bool) { return r.FirstSeen, true }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ran {
		t.Fatal("seed did not resume")
	}
	total, _, err := db.PendingStats()
	if err != nil {
		t.Fatal(err)
	}
	if total != n {
		t.Errorf("queue holds %d entries after resuming (%d before, %d added), want %d with no duplicates",
			total, before, queued, n)
	}
}

// A run with the sweep off records hosts nothing queues: one shed because
// every worker was busy is written unprobed with no entry pointing at it. The
// generation names the re-probe policy alone, so without a marker of its own
// that run's discoveries would be skipped by the next swept run's seed and
// wait for a certificate to name them again.
func TestSeedRunsAgainAfterAnUnqueuedRun(t *testing.T) {
	db := openTemp(t)
	seen := time.Now().UTC().Add(-time.Hour)
	write := func(host string, probed bool) {
		t.Helper()
		err := db.Update(host, func(r *Record, _ bool) bool {
			r.FirstSeen, r.Probed, r.ProbedAt = seen, probed, seen
			return true
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	due := func(r *Record) (time.Time, bool) {
		if r.Probed {
			return time.Time{}, false
		}
		return r.FirstSeen, true
	}

	write("done.test", true)
	if _, ran, err := db.SeedPending("gen1", due, nil); err != nil || !ran {
		t.Fatalf("first seed did not run (ran=%v, err %v)", ran, err)
	}

	// The run with the sweep off: a record, no queue entry, and the marker
	// that says so.
	write("shed.test", false)
	if err := db.MarkUnqueued(); err != nil {
		t.Fatal(err)
	}
	if unqueued, err := db.Unqueued(); err != nil || !unqueued {
		t.Fatalf("marker not set (unqueued=%v, err %v)", unqueued, err)
	}

	// Same policy as the first seed, so only the marker can bring the walk
	// back.
	queued, ran, err := db.SeedPending("gen1", due, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ran || queued != 1 {
		t.Errorf("seed queued %d hosts (ran=%v), want the shed host queued", queued, ran)
	}
	got, err := db.PendingLease(time.Now().UTC(), 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Host != "shed.test" {
		t.Errorf("queued %v, want only [shed.test]", hosts(got))
	}

	// And the walk it asked for clears it, so the next start is cheap again.
	if unqueued, err := db.Unqueued(); err != nil || unqueued {
		t.Errorf("marker survived the seed (unqueued=%v, err %v)", unqueued, err)
	}
	if _, ran, err := db.SeedPending("gen1", due, nil); err != nil || ran {
		t.Errorf("seed ran again with nothing asking for it (err %v)", err)
	}
}

// seedTestHosts writes n unprobed records that sort in the order they are
// numbered, and returns the due function a seed of them wants.
func seedTestHosts(t *testing.T, db *Store, n int, seen time.Time) func(*Record) (time.Time, bool) {
	t.Helper()
	for i := 0; i < n; i++ {
		host := fmt.Sprintf("h%03d.example", i)
		err := db.Update(host, func(r *Record, _ bool) bool {
			r.FirstSeen = seen
			return true
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// Due at FirstSeen, so queueing the same host twice writes the same key
	// and a second walk over a record cannot duplicate its entry.
	return func(r *Record) (time.Time, bool) { return r.FirstSeen, true }
}

// interruptSeed runs a seed that dies after the given number of chunks, the
// way a killed process does: the chunks already committed stay, and so does
// the cursor.
func interruptSeed(db *Store, generation string, due func(*Record) (time.Time, bool), chunks int) {
	defer func() { _ = recover() }()
	n := 0
	db.SeedPending(generation, due, func(int, int) {
		if n++; n >= chunks {
			panic(errors.New("killed"))
		}
	})
}

// A walk that makes up for an unqueued run has to start from the top. The
// records it is looking for were written after an interrupted ordinary seed
// had passed their place in the keyspace, so resuming that seed's cursor would
// step over them — and the seed clears the marker on its way out, so they
// would never be looked for again.
func TestSeedForUnqueuedRunIgnoresAnOlderCursor(t *testing.T) {
	db := openTemp(t)
	defer func(orig int) { seedChunk = orig }(seedChunk)
	seedChunk = 10

	seen := time.Now().UTC().Add(-time.Hour)
	due := seedTestHosts(t, db, 30, seen)
	interruptSeed(db, "gen1", due, 2)

	// The run with the sweep off: a record the interrupted walk is already
	// past, and no queue entry for it.
	err := db.Update("aaa.example", func(r *Record, _ bool) bool {
		r.FirstSeen = seen
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.MarkUnqueued(); err != nil {
		t.Fatal(err)
	}

	if _, ran, err := db.SeedPending("gen1", due, nil); err != nil || !ran {
		t.Fatalf("seed did not run (ran=%v, err %v)", ran, err)
	}
	got, err := db.PendingLease(time.Now().UTC(), 100, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	queued := make(map[string]bool, len(got))
	for _, p := range got {
		queued[p.Host] = true
	}
	if !queued["aaa.example"] {
		t.Errorf("queued %d hosts, none of them aaa.example: the walk resumed instead of restarting", len(got))
	}
	if len(queued) != 31 {
		t.Errorf("queue holds %d hosts, want all 31 with no duplicates", len(queued))
	}
}

// Restarting is only owed to a cursor from a different walk. A forced walk
// interrupted part way through resumes its own, so a store that takes half a
// minute to seed does not pay it again from the top.
func TestSeedForUnqueuedRunResumesItsOwnWalk(t *testing.T) {
	db := openTemp(t)
	defer func(orig int) { seedChunk = orig }(seedChunk)
	seedChunk = 10

	due := seedTestHosts(t, db, 30, time.Now().UTC().Add(-time.Hour))
	if err := db.MarkUnqueued(); err != nil {
		t.Fatal(err)
	}
	interruptSeed(db, "gen1", due, 2)

	scanned := 0
	_, ran, err := db.SeedPending("gen1", due, func(s, _ int) { scanned = s })
	if err != nil || !ran {
		t.Fatalf("seed did not run (ran=%v, err %v)", ran, err)
	}
	if scanned > 10 {
		t.Errorf("resumed seed scanned %d records, want only the 10 the first attempt had not reached", scanned)
	}
}

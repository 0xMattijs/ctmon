package store

import (
	"fmt"
	"slices"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// seen writes a record for host that a certificate first named at first and
// last named at last.
func seen(t *testing.T, s *Store, host string, first, last time.Time) {
	t.Helper()
	err := s.Update(host, func(r *Record, existed bool) bool {
		r.FirstSeen, r.LastSeen = first, last
		r.SeenCount++
		return true
	})
	if err != nil {
		t.Fatalf("update %s: %v", host, err)
	}
}

// probed writes a record first seen at first, with fn filling in the probe
// result.
func probed(t *testing.T, s *Store, host string, first time.Time, fn func(*Record)) {
	t.Helper()
	seen(t, s, host, first, first)
	if err := s.Update(host, func(r *Record, existed bool) bool {
		fn(r)
		return true
	}); err != nil {
		t.Fatalf("probe %s: %v", host, err)
	}
}

// mustGet reads one record and fails on an error, so a test can say what it
// means about the record itself.
func mustGet(t *testing.T, s *Store, host string) *Record {
	t.Helper()
	rec, err := s.Get(host)
	if err != nil {
		t.Fatalf("get %s: %v", host, err)
	}
	return rec
}

// storedHosts returns every host in the store, in key order.
func storedHosts(t *testing.T, s *Store) []string {
	t.Helper()
	var out []string
	if err := s.ForEach(func(r *Record) error {
		out = append(out, r.Host)
		return nil
	}); err != nil {
		t.Fatalf("foreach: %v", err)
	}
	return out
}

// queuedHosts returns every host with a queue entry, in due order.
func queuedHosts(t *testing.T, s *Store) []string {
	t.Helper()
	var out []string
	err := s.view(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPending).ForEach(func(k, _ []byte) error {
			if len(k) > pendingLeaseKey {
				out = append(out, string(k[pendingLeaseKey:]))
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("walk pending: %v", err)
	}
	return out
}

// hostN names the nth record of a bulk test, zero-padded so that the order
// they are written in is the order they are stored in.
func hostN(i int) string { return fmt.Sprintf("h%03d.example.com", i) }

func TestPruneUnseen(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	old, recent := now.Add(-100*24*time.Hour), now.Add(-time.Hour)

	seen(t, s, "stale.example.com", old, old)
	seen(t, s, "renewed.example.com", old, recent) // first seen long ago, still issued for
	seen(t, s, "fresh.example.com", recent, recent)

	cutoff := now.Add(-90 * 24 * time.Hour)
	opts := PruneOptions{Match: Unseen(cutoff), DryRun: true}

	res, err := s.Prune(opts)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if res.Scanned != 3 || res.Deleted != 1 {
		t.Errorf("dry run = %+v; want 3 scanned, 1 deleted", res)
	}
	if got := len(storedHosts(t, s)); got != 3 {
		t.Errorf("a dry run deleted something: %d records left, want 3", got)
	}

	opts.DryRun = false
	if res, err = s.Prune(opts); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Scanned != 3 || res.Deleted != 1 {
		t.Errorf("prune = %+v; want 3 scanned, 1 deleted", res)
	}
	want := []string{"fresh.example.com", "renewed.example.com"}
	if got := storedHosts(t, s); !slices.Equal(got, want) {
		t.Errorf("left %v; want %v", got, want)
	}
}

func TestPruneFailed(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	old := now.Add(-60 * 24 * time.Hour)

	// Probed, still failing, never returned a body: the case prune is for.
	probed(t, s, "dead.example.com", old, func(r *Record) {
		r.Probed, r.ProbedAt, r.ProbeError = true, old, "no such host"
	})
	// Answered once and has started failing since. Its hash is the thing
	// worth keeping.
	probed(t, s, "was-up.example.com", old, func(r *Record) {
		r.Probed, r.ProbedAt = true, old
		r.ProbeError, r.BodyHash = "connection refused", digest("hi")
	})
	// Failing, but only discovered this morning.
	probed(t, s, "new.example.com", now.Add(-time.Hour), func(r *Record) {
		r.Probed, r.ProbedAt, r.ProbeError = true, now.Add(-time.Hour), "no such host"
	})
	// Discovered long ago but only now reaching the front of the queue, and
	// its very first probe has just failed. The backlog delay is what aged it
	// past the cutoff, not the host, so it is not a host that has been failing
	// for 30 days.
	probed(t, s, "just-tried.example.com", old, func(r *Record) {
		r.Probed, r.ProbedAt, r.ProbeError = true, now.Add(-time.Hour), "no such host"
	})
	// Never probed at all, just waiting its turn.
	seen(t, s, "queued.example.com", old, old)

	res, err := s.Prune(PruneOptions{Match: Failed(now.Add(-30 * 24 * time.Hour))})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Deleted != 1 {
		t.Fatalf("deleted %d; want 1", res.Deleted)
	}
	if mustGet(t, s, "dead.example.com") != nil {
		t.Error("dead.example.com survived")
	}
	for _, host := range []string{
		"was-up.example.com", "new.example.com", "queued.example.com",
		"just-tried.example.com",
	} {
		if mustGet(t, s, host) == nil {
			t.Errorf("%s was deleted and should not have been", host)
		}
	}
}

func TestPruneUnder(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	for _, host := range []string{
		"workers.dev",
		"a.workers.dev",
		"deep.b.workers.dev",
		"workers.dev.example.com", // a different domain that only looks like one
		"workers-two.dev",         // sorts between the parent and its children
		"example.com",
	} {
		seen(t, s, host, now, now)
	}

	res, err := s.Prune(PruneOptions{Under: "workers.dev"})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Scanned != 3 || res.Deleted != 3 {
		t.Errorf("prune = %+v; want 3 scanned, 3 deleted", res)
	}
	want := []string{"example.com", "workers.dev.example.com", "workers-two.dev"}
	if got := storedHosts(t, s); !slices.Equal(got, want) {
		t.Errorf("left %v; want %v", got, want)
	}
}

func TestPruneUnderAndFilterCombine(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	old := now.Add(-100 * 24 * time.Hour)
	seen(t, s, "old.workers.dev", old, old)
	seen(t, s, "new.workers.dev", now, now)
	seen(t, s, "old.example.com", old, old)

	res, err := s.Prune(PruneOptions{
		Under: "workers.dev",
		Match: Unseen(now.Add(-90 * 24 * time.Hour)),
	})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Scanned != 2 || res.Deleted != 1 {
		t.Errorf("prune = %+v; want 2 scanned, 1 deleted", res)
	}
	want := []string{"old.example.com", "new.workers.dev"}
	if got := storedHosts(t, s); !slices.Equal(got, want) {
		t.Errorf("left %v; want %v", got, want)
	}
}

// A record and its queue entries go together. The sweep already drops an entry
// whose record has gone, so leaving them would work; it would also leave a
// pruned store dragging the queue behind it.
func TestPruneDropsQueueEntries(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	old := now.Add(-100 * 24 * time.Hour)

	seen(t, s, "stale.example.com", old, old)
	seen(t, s, "fresh.example.com", now, now)
	// Two entries for the doomed host, which is what a name seen twice before
	// its first probe leaves behind.
	for _, due := range []time.Time{old, old.Add(time.Hour)} {
		if err := s.Enqueue("stale.example.com", due); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	if err := s.Enqueue("fresh.example.com", now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	res, err := s.Prune(PruneOptions{Match: Unseen(now.Add(-90 * 24 * time.Hour))})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Deleted != 1 || res.Pending != 2 {
		t.Errorf("prune = %+v; want 1 record and 2 queue entries", res)
	}
	if got := queuedHosts(t, s); !slices.Equal(got, []string{"fresh.example.com"}) {
		t.Errorf("queue holds %v; want only fresh.example.com", got)
	}
}

// A dry run leaves the queue alone, and says so by reporting no entries rather
// than by guessing at how many there would be.
func TestPruneDryRunLeavesQueue(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	seen(t, s, "stale.example.com", now.Add(-100*24*time.Hour), now.Add(-100*24*time.Hour))
	if err := s.Enqueue("stale.example.com", now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	res, err := s.Prune(PruneOptions{Match: Unseen(now.Add(-90 * 24 * time.Hour)), DryRun: true})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Deleted != 1 || res.Pending != 0 {
		t.Errorf("prune = %+v; want 1 would-be deletion and 0 queue entries", res)
	}
	if got := queuedHosts(t, s); len(got) != 1 {
		t.Errorf("a dry run touched the queue: %v", got)
	}
}

// The walk commits in chunks, so it has to resume from a key it may itself
// have deleted. Every third record goes, across several chunks, which puts a
// deleted key at the chunk boundary and a surviving one there too.
func TestPruneSpansChunks(t *testing.T) {
	s := open(t)
	defer func(n int) { pruneChunk = n }(pruneChunk)
	pruneChunk = 7

	const total = 50
	now := time.Now().UTC().Truncate(time.Second)
	old := now.Add(-100 * 24 * time.Hour)
	var want []string
	for i := range total {
		host := hostN(i)
		when := now
		if i%3 == 0 {
			when = old
		} else {
			want = append(want, host)
		}
		seen(t, s, host, when, when)
		if err := s.Enqueue(host, when); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	res, err := s.Prune(PruneOptions{Match: Unseen(now.Add(-90 * 24 * time.Hour))})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Scanned != total {
		t.Errorf("scanned %d; want %d", res.Scanned, total)
	}
	if res.Deleted != total-len(want) || res.Pending != total-len(want) {
		t.Errorf("prune = %+v; want %d records and the same number of queue entries",
			res, total-len(want))
	}
	got := storedHosts(t, s)
	if len(got) != len(want) {
		t.Fatalf("left %d records; want %d", len(got), len(want))
	}
	left := map[string]bool{}
	for _, h := range got {
		left[h] = true
	}
	for _, h := range want {
		if !left[h] {
			t.Errorf("%s was deleted and should not have been", h)
		}
	}
	if n := len(queuedHosts(t, s)); n != len(want) {
		t.Errorf("queue holds %d entries; want %d", n, len(want))
	}
}

// A nil Match takes everything in scope. It is the only way to say "all of
// it", and the command refuses to say it without a scope.
func TestPruneNilMatchTakesScope(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	seen(t, s, "a.workers.dev", now, now)
	seen(t, s, "b.workers.dev", now, now)
	seen(t, s, "example.com", now, now)

	res, err := s.Prune(PruneOptions{Under: "workers.dev"})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Deleted != 2 {
		t.Errorf("deleted %d; want 2", res.Deleted)
	}
	if got := storedHosts(t, s); !slices.Equal(got, []string{"example.com"}) {
		t.Errorf("left %v; want only example.com", got)
	}
}

func TestPruneEmptyStore(t *testing.T) {
	s := open(t)
	res, err := s.Prune(PruneOptions{Match: Unseen(time.Now())})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res != (PruneResult{}) {
		t.Errorf("prune of an empty store = %+v; want zero", res)
	}
}

// Queue entries orphaned by something other than this prune go too. The pass
// cannot tell them apart from the ones it just orphaned, and there is no
// reason it should.
func TestPruneClearsOrphanedQueueEntries(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	seen(t, s, "stale.example.com", now.Add(-100*24*time.Hour), now.Add(-100*24*time.Hour))
	if err := s.Enqueue("gone.example.com", now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	res, err := s.Prune(PruneOptions{Match: Unseen(now.Add(-90 * 24 * time.Hour))})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Deleted != 1 || res.Pending != 1 {
		t.Errorf("prune = %+v; want 1 record and 1 orphaned queue entry", res)
	}
	if got := queuedHosts(t, s); len(got) != 0 {
		t.Errorf("queue holds %v; want nothing", got)
	}
}

// A parent made only of separators names no domain, and the scope it collapses
// to is the whole store. Prune refuses rather than treating "delete everything"
// as what was asked for.
func TestPruneRefusesAScopeThatCollapses(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, under := range []string{".", "..", "...", "  ", " . "} {
		s := open(t)
		seen(t, s, "a.example.com", now, now)
		seen(t, s, "b.other.org", now, now)

		if _, err := s.Prune(PruneOptions{Under: under}); err == nil {
			t.Errorf("Prune(Under: %q) = nil; want a refusal", under)
		}
		if got := len(storedHosts(t, s)); got != 2 {
			t.Errorf("Prune(Under: %q) deleted records: %d left, want 2", under, got)
		}
	}
	// An empty Under is not a collapse; it is the caller saying "the whole
	// store", which is a thing they are allowed to say.
	s := open(t)
	seen(t, s, "a.example.com", now, now)
	if _, err := s.Prune(PruneOptions{Under: "", Match: Unseen(now.Add(-time.Hour))}); err != nil {
		t.Errorf("Prune over the whole store: %v", err)
	}
}

// A prune interrupted between the record walk and the queue pass leaves
// orphaned entries. Running it again has to finish the job, which it cannot do
// if it gives up on finding no records left to delete.
func TestPruneReconcilesQueueWithNothingLeftToDelete(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	seen(t, s, "live.example.com", now, now)
	if err := s.Enqueue("live.example.com", now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	// What an interrupted prune leaves: records gone, entries still pointing
	// at them.
	for _, host := range []string{"gone.example.com", "also-gone.example.com"} {
		if err := s.Enqueue(host, now); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	res, err := s.Prune(PruneOptions{Match: Unseen(now.Add(-90 * 24 * time.Hour))})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Deleted != 0 {
		t.Errorf("deleted %d records; want 0", res.Deleted)
	}
	if res.Pending != 2 {
		t.Errorf("dropped %d queue entries; want the 2 orphans", res.Pending)
	}
	if got := queuedHosts(t, s); !slices.Equal(got, []string{"live.example.com"}) {
		t.Errorf("queue holds %v; want only live.example.com", got)
	}
}

// A dry run still leaves the queue alone, even now that the real pass runs
// unconditionally.
func TestPruneDryRunSkipsReconciliation(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := s.Enqueue("gone.example.com", now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	res, err := s.Prune(PruneOptions{Match: Unseen(now), DryRun: true})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Pending != 0 {
		t.Errorf("dry run reported %d queue entries; want 0", res.Pending)
	}
	if got := len(queuedHosts(t, s)); got != 1 {
		t.Errorf("dry run dropped queue entries: %d left, want 1", got)
	}
}

// A scope that names no domain must not widen the read path either. Before
// this was shared, ForEachUnder collapsed "." to the empty prefix and walked
// the whole store.
func TestForEachUnderRefusesAScopeThatCollapses(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	seen(t, s, "a.example.com", now, now)
	seen(t, s, "b.other.org", now, now)

	for _, under := range []string{".", "..", " . ", "  "} {
		n := 0
		err := s.ForEachUnder(under, func(*Record) error { n++; return nil })
		if err == nil {
			t.Errorf("ForEachUnder(%q) = nil after visiting %d records; want a refusal", under, n)
		}
		if n != 0 {
			t.Errorf("ForEachUnder(%q) visited %d records before refusing", under, n)
		}
	}
	// An empty parent still means the whole store, which is a thing a caller
	// is allowed to ask for.
	n := 0
	if err := s.ForEachUnder("", func(*Record) error { n++; return nil }); err != nil {
		t.Errorf("ForEachUnder(\"\"): %v", err)
	}
	if n != 2 {
		t.Errorf("ForEachUnder(\"\") visited %d records; want 2", n)
	}
}

func TestAllRequiresEveryMatch(t *testing.T) {
	yes := func(*Record) bool { return true }
	no := func(*Record) bool { return false }
	tests := []struct {
		name  string
		match []func(*Record) bool
		want  bool
	}{
		{"none given", nil, true},
		{"one, true", []func(*Record) bool{yes}, true},
		{"one, false", []func(*Record) bool{no}, false},
		{"both true", []func(*Record) bool{yes, yes}, true},
		{"one false", []func(*Record) bool{yes, no}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := All(tt.match...)(&Record{}); got != tt.want {
				t.Errorf("All(%s) = %v; want %v", tt.name, got, tt.want)
			}
		})
	}
}

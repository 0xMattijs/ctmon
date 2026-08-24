package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mvo/ct/internal/store"
)

func TestDaysFlag(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
		err  bool
	}{
		{raw: "90d", want: 90 * 24 * time.Hour},
		{raw: "1d12h", want: 36 * time.Hour},
		// Everything time.ParseDuration takes still works, so nobody has to
		// learn that this flag is special.
		{raw: "36h", want: 36 * time.Hour},
		{raw: "90m", want: 90 * time.Minute},
		{raw: "1h30m", want: 90 * time.Minute},
		// A retention window of zero or less names a rule nobody can mean,
		// and the layer above reads an unset window as "no rule given" — so
		// one that parsed and then vanished would leave the other rules to
		// delete strictly more than was asked for.
		{raw: "-30d", err: true},
		{raw: "0d", err: true},
		{raw: "0", err: true},
		{raw: "0s", err: true},
		{raw: "1d-25h", err: true},
		{raw: "", err: true},
		{raw: "d", err: true},
		{raw: "1.5d", err: true},
		{raw: "90", err: true},
		{raw: "90days", err: true},
		{raw: "1d2x", err: true},
		// A day count large enough to overflow int64 nanoseconds would wrap
		// into a cutoff in the future, which matches every record in the
		// store rather than none.
		{raw: "999999999d", err: true},
		{raw: "-999999999d", err: true},
		{raw: "100001d", err: true},
		{raw: "100000d", want: 100000 * 24 * time.Hour},
		{raw: "99999d2562047h", err: true},
	}
	for _, c := range cases {
		var d days
		switch err := d.Set(c.raw); {
		case c.err && err == nil:
			t.Errorf("Set(%q) = %v; want an error", c.raw, time.Duration(d))
		case !c.err && err != nil:
			t.Errorf("Set(%q): %v", c.raw, err)
		case !c.err && time.Duration(d) != c.want:
			t.Errorf("Set(%q) = %v; want %v", c.raw, time.Duration(d), c.want)
		}
	}
}

// A whole number of days reads back as days, because that is how it was
// typed and the flag's default is printed in -h.
func TestDaysString(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "0s"},
		{90 * 24 * time.Hour, "90d"},
		{36 * time.Hour, "36h0m0s"},
	}
	for _, c := range cases {
		d := days(c.in)
		if got := d.String(); got != c.want {
			t.Errorf("days(%v).String() = %q; want %q", c.in, got, c.want)
		}
	}
}

// An overflowed window is the dangerous kind of wrong: it does not match
// nothing, it matches everything.
func TestDaysOverflowCannotMatchEverything(t *testing.T) {
	var d days
	if err := d.Set("999999999d"); err == nil {
		t.Fatalf("Set(999999999d) = %v; want a refusal", time.Duration(d))
	}
	// The guard is what keeps that from becoming a rule at all, so the rule
	// builder never sees it. Check the arithmetic it protects, so a later
	// change to maxDays cannot quietly reintroduce the wrap.
	if got := time.Duration(maxDays) * 24 * time.Hour; got <= 0 {
		t.Errorf("maxDays days = %v; want a positive duration", got)
	}
}

// Pruning with no rule at all would empty the store, and there is no way to
// mean that by accident.
func TestPruneOptionsNeedsARule(t *testing.T) {
	if _, err := pruneOptions("", 0, 0); err == nil {
		t.Fatal("pruneOptions with no rule = nil error; want a refusal")
	}
	for _, c := range []struct {
		name           string
		under          string
		unseen, failed time.Duration
	}{
		{name: "under", under: "workers.dev"},
		{name: "unseen", unseen: 90 * 24 * time.Hour},
		{name: "failed", failed: 30 * 24 * time.Hour},
	} {
		if _, err := pruneOptions(c.under, c.unseen, c.failed); err != nil {
			t.Errorf("pruneOptions(%s): %v", c.name, err)
		}
	}
}

// Two retention flags mean both, not either. Guessing the other way deletes
// records neither rule asked for.
func TestPruneOptionsCombineWithAnd(t *testing.T) {
	opts, err := pruneOptions("", 90*24*time.Hour, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	old, recent := now.Add(-100*24*time.Hour), now.Add(-time.Hour)

	cases := []struct {
		name string
		rec  store.Record
		want bool
	}{
		{
			name: "unseen and failed",
			rec:  store.Record{LastSeen: old, FirstSeen: old, Probed: true, ProbeError: "no such host"},
			want: true,
		},
		{
			name: "unseen but answered",
			rec:  store.Record{LastSeen: old, FirstSeen: old, Probed: true, BodyHash: strings.Repeat("a", 64)},
		},
		{
			name: "failed but still being issued for",
			rec:  store.Record{LastSeen: recent, FirstSeen: old, Probed: true, ProbeError: "no such host"},
		},
	}
	for _, c := range cases {
		if got := opts.Match(&c.rec); got != c.want {
			t.Errorf("%s: matched = %v; want %v", c.name, got, c.want)
		}
	}
}

// The scope is passed through untouched: the store, not the command, decides
// what "under" means.
func TestPruneOptionsCarriesScope(t *testing.T) {
	opts, err := pruneOptions("Workers.Dev.", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Under != "Workers.Dev." {
		t.Errorf("Under = %q; want the flag verbatim", opts.Under)
	}
}

// A snapshot is what an operator has in hand while a run holds the database,
// so it is the path they are likeliest to reach for. Deleting from it changes
// nothing they want.
func TestPruneRefusesASnapshot(t *testing.T) {
	err := refuseSnapshot("ct.db.snap")
	if err == nil {
		t.Fatal("refuseSnapshot(ct.db.snap) = nil; want a refusal")
	}
	if !strings.Contains(err.Error(), "ct.db instead") {
		t.Errorf("refusal does not say what to prune instead: %v", err)
	}
	if err := refuseSnapshot("ct.db"); err != nil {
		t.Errorf("refuseSnapshot(ct.db) = %v; want nil", err)
	}
}

// A mistyped --db must not be answered with "nothing matched". store.Open
// would create the database to say it.
func TestPruneRefusesAPathWithNoDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "typo.db")
	err := pruneCmd([]string{"--db", path, "--unseen-for", "90d"})
	if !errors.Is(err, store.ErrNoDatabase) {
		t.Fatalf("prune on a missing path = %v; want ErrNoDatabase", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("prune created the database it was asked about")
	}
}

// A --db that names an empty file is a typo too. store.Open would initialize
// it into a fresh database and then report that nothing matched.
func TestPruneRefusesAnEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := pruneCmd([]string{"--db", path, "--unseen-for", "90d"}); !errors.Is(err, store.ErrNoDatabase) {
		t.Fatalf("prune on an empty file = %v; want ErrNoDatabase", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() != 0 {
		t.Errorf("prune wrote to the file it refused: %v, %v", fi, err)
	}
}

// "--under ." names no domain, and the scope it would collapse to is the whole
// store — so the flag an operator typed to make the prune narrow would be the
// one that made it delete everything.
func TestPruneRefusesAScopeThatNamesNoDomain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ct.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, host := range []string{"a.example.com", "b.other.org", "c.net"} {
		if err := db.Update(host, func(r *store.Record, existed bool) bool {
			r.FirstSeen, r.LastSeen = now, now
			return true
		}); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	for _, under := range []string{".", "..", "...", " . "} {
		if err := pruneCmd([]string{"--db", path, "--under", under, "--apply"}); err == nil {
			t.Errorf("prune --under %q = nil; want a refusal", under)
		}
	}

	db, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st, err := db.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Domains != 3 {
		t.Errorf("%d records left; want all 3", st.Domains)
	}
}

// Prune writes, so a run holding the database blocks it outright and the
// snapshot route readErr offers is no help.
func TestPruneReportsALockedDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ct.db")
	held, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	err = pruneCmd([]string{"--db", path, "--under", "example.com"})
	if !errors.Is(err, store.ErrLocked) {
		t.Fatalf("prune against a held database = %v; want ErrLocked", err)
	}
	if !strings.Contains(err.Error(), "stop the run first") {
		t.Errorf("error does not say what to do: %v", err)
	}
}

// Without --apply nothing goes, whatever the rule would have matched.
func TestPruneCountsWithoutApply(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ct.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-100 * 24 * time.Hour)
	if err := db.Update("stale.example.com", func(r *store.Record, existed bool) bool {
		r.FirstSeen, r.LastSeen = old, old
		return true
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	if err := pruneCmd([]string{"--db", path, "--unseen-for", "90d"}); err != nil {
		t.Fatalf("prune: %v", err)
	}
	db, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if rec, err := db.Get("stale.example.com"); err != nil || rec == nil {
		t.Fatalf("counting deleted the record: %v, %v", rec, err)
	}
}

// --apply deletes, and --compact gives the pages back afterwards.
func TestPruneApplies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ct.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	old := now.Add(-100 * 24 * time.Hour)
	for host, when := range map[string]time.Time{
		"stale.example.com": old,
		"fresh.example.com": now,
	} {
		if err := db.Update(host, func(r *store.Record, existed bool) bool {
			r.FirstSeen, r.LastSeen = when, when
			return true
		}); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	if err := pruneCmd([]string{"--db", path, "--unseen-for", "90d", "--apply", "--compact"}); err != nil {
		t.Fatalf("prune: %v", err)
	}

	db, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if rec, err := db.Get("stale.example.com"); err != nil || rec != nil {
		t.Errorf("stale.example.com survived: %v, %v", rec, err)
	}
	if rec, err := db.Get("fresh.example.com"); err != nil || rec == nil {
		t.Errorf("fresh.example.com went: %v, %v", rec, err)
	}
}

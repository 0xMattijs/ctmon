package source

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// discardLog is a logger for tests that only care about behavior.
func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// fakeLog is a CT log that answers get-sth and get-entries. maxServed caps how
// many entries it will return before failing, which is how a degraded log
// behaves from a client's side.
type fakeLog struct {
	mu        sync.Mutex
	treeSize  uint64
	maxServed int   // 0 means serve whatever is asked
	asked     []int // entry counts requested, in order
	heads     int   // get-sth calls, which is how a follower shows it is alive
}

func (f *fakeLog) serve(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ct/v1/get-sth", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.heads++
		json.NewEncoder(w).Encode(map[string]any{
			"tree_size":           f.treeSize,
			"timestamp":           int64(1787000000000),
			"sha256_root_hash":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"tree_head_signature": base64.StdEncoding.EncodeToString(make([]byte, 4)),
		})
	})
	mux.HandleFunc("/ct/v1/get-entries", func(w http.ResponseWriter, r *http.Request) {
		start, _ := strconv.Atoi(r.URL.Query().Get("start"))
		end, _ := strconv.Atoi(r.URL.Query().Get("end"))
		want := end - start + 1

		f.mu.Lock()
		f.asked = append(f.asked, want)
		maxServed := f.maxServed
		f.mu.Unlock()

		if maxServed > 0 && want > maxServed {
			// The real failure is a timeout; a refusal exercises the same
			// path without making the test wait.
			http.Error(w, "too many entries", http.StatusRequestTimeout)
			return
		}
		entries := make([]map[string]string, want)
		for i := range entries {
			// Unparsable leaves are fine: the follow loop counts them and
			// moves on, which is all this fixture needs it to do.
			entries[i] = map[string]string{"leaf_input": "AAAA", "extra_data": ""}
		}
		json.NewEncoder(w).Encode(map[string]any{"entries": entries})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func (f *fakeLog) requests() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.asked...)
}

func (f *fakeLog) sths() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.heads
}

// memPositions is an in-memory Positions.
type memPositions struct {
	mu  sync.Mutex
	pos map[string]uint64
}

func newPositions() *memPositions { return &memPositions{pos: map[string]uint64{}} }

func (m *memPositions) LogPos(uri string) (uint64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.pos[uri]
	return p, ok, nil
}

func (m *memPositions) SetLogPos(uri string, pos uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pos[uri] = pos
	return nil
}

func (m *memPositions) get(uri string) uint64 {
	p, _, _ := m.LogPos(uri)
	return p
}

func TestBatchShrinksUntilTheLogCanAnswer(t *testing.T) {
	log := &fakeLog{treeSize: 10000, maxServed: 32}
	uri := log.serve(t)

	pos := newPositions()
	pos.SetLogPos(uri, 0)
	c := &CTLog{
		URIs: []string{uri}, Positions: pos, BatchSize: 256,
		PollInterval: time.Millisecond, RequestsPerSecond: 1000, Log: discardLog(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st := &logState{batch: c.batchCeiling(), max: c.batchCeiling()}

	// Each follow returns on the first refusal, so the caller's loop is what
	// eventually finds a size the log will serve.
	out := make(chan Cert, 1024)
	go func() {
		for range out {
		}
	}()
	for i := 0; i < 6 && pos.get(uri) == 0; i++ {
		c.follow(ctx, uri, out, st)
	}

	if pos.get(uri) == 0 {
		t.Fatalf("no progress after shrinking; batch = %d, asked %v", st.batch, log.requests())
	}
	if st.batch > 32 {
		t.Errorf("batch = %d, want <= 32 (what the log serves)", st.batch)
	}
	asked := log.requests()
	if asked[0] != 256 {
		t.Errorf("first request asked for %d, want the configured 256", asked[0])
	}
	for _, n := range asked {
		if n < minBatchSize {
			t.Errorf("asked for %d entries, below the floor of %d", n, minBatchSize)
		}
	}
}

func TestBatchGrowsBackToTheCeiling(t *testing.T) {
	st := &logState{batch: 256, max: 256}
	st.shrink()
	st.shrink()
	if st.batch != 64 {
		t.Fatalf("batch after two shrinks = %d, want 64", st.batch)
	}
	for i := 0; i < 100; i++ {
		st.grow()
	}
	if st.batch != 256 {
		t.Errorf("batch after growing = %d, want the ceiling 256", st.batch)
	}
	for i := 0; i < 10; i++ {
		st.shrink()
	}
	if st.batch != minBatchSize {
		t.Errorf("batch after many shrinks = %d, want the floor %d", st.batch, minBatchSize)
	}
}

func TestMaxLagSkipsToTheTip(t *testing.T) {
	log := &fakeLog{treeSize: 5_000_000}
	uri := log.serve(t)

	pos := newPositions()
	pos.SetLogPos(uri, 1000) // known log, hopelessly behind
	c := &CTLog{
		URIs: []string{uri}, Positions: pos, MaxLag: 10000,
		PollInterval: time.Hour, RequestsPerSecond: 1000, Log: discardLog(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out := make(chan Cert, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		st := &logState{batch: c.batchCeiling(), max: c.batchCeiling()}
		c.follow(ctx, uri, out, st)
	}()

	deadline := time.After(5 * time.Second)
	for pos.get(uri) != log.treeSize {
		select {
		case <-deadline:
			t.Fatalf("position = %d, want the tip %d", pos.get(uri), log.treeSize)
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done

	if got := log.requests(); len(got) != 0 {
		t.Errorf("fetched %d batches, want none: the backlog should be skipped, not read", len(got))
	}
}

func TestMaxLagLeavesFirstSightAlone(t *testing.T) {
	log := &fakeLog{treeSize: 5_000_000}
	uri := log.serve(t)

	pos := newPositions() // no stored position: this is first sight
	c := &CTLog{
		URIs: []string{uri}, Positions: pos, MaxLag: 10000, FromStart: true,
		BatchSize: 16, PollInterval: time.Hour, RequestsPerSecond: 1000, Log: discardLog(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out := make(chan Cert, 1024)
	go func() {
		for range out {
		}
	}()
	go func() {
		st := &logState{batch: c.batchCeiling(), max: c.batchCeiling()}
		c.follow(ctx, uri, out, st)
	}()

	// --from-start asked for the whole log, so the gap must be read, not
	// skipped: the position climbs from zero rather than jumping to the tip.
	deadline := time.After(5 * time.Second)
	for {
		p := pos.get(uri)
		if p > 0 && p < 100000 {
			break
		}
		if p >= log.treeSize {
			t.Fatal("skipped to the tip on first sight, defeating --from-start")
		}
		select {
		case <-deadline:
			t.Fatalf("position = %d, want a climb from zero", p)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestRetryResetsAfterAHealthyRun(t *testing.T) {
	rt := retry{base: time.Second, max: 30 * time.Second}

	// A feed that keeps dropping straight away escalates.
	for _, want := range []time.Duration{1, 2, 4, 8} {
		if got := rt.after(time.Millisecond); got != want*time.Second {
			t.Fatalf("delay = %v, want %v", got, want*time.Second)
		}
	}

	// A run that lasted pays the short pause itself, not the one the bad
	// patch before it earned. Computing the delay before resetting the
	// counter is the mistake this pins down.
	if got := rt.after(healthyRun); got != time.Second {
		t.Errorf("delay after a healthy run = %v, want 1s", got)
	}

	// And escalation resumes from the bottom.
	if got := rt.after(time.Millisecond); got != 2*time.Second {
		t.Errorf("delay after the reset = %v, want 2s", got)
	}
}

func TestRetryCapsTheDelay(t *testing.T) {
	rt := retry{base: time.Second, max: 4 * time.Second}
	var last time.Duration
	for i := 0; i < 20; i++ {
		last = rt.after(0)
	}
	if last != 4*time.Second {
		t.Errorf("delay = %v, want the 4s cap", last)
	}
}

// waitFor polls cond until it holds, and fails the test if it never does.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for !cond() {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		case <-time.After(2 * time.Millisecond):
		}
	}
}

func (m *memPositions) seen(uri string) bool {
	_, ok, _ := m.LogPos(uri)
	return ok
}

// listOf is a log list a test can rewrite while the feed is running, which is
// what a shard rollover looks like from the monitor's side.
type listOf struct {
	mu   sync.Mutex
	uris []string
	err  error
}

func (l *listOf) set(uris ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.uris = uris
}

func (l *listOf) discover(context.Context) ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.uris...), l.err
}

// runFeed starts c and stops it when the test ends.
func runFeed(t *testing.T, c *CTLog) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan Cert, 64)
	go func() {
		for range out {
		}
	}()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, out) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Run did not return after cancellation")
		}
	})
}

// refreshing is a CTLog wired to list, polling fast enough for a test to watch.
func refreshing(uris []string, pos Positions, list *listOf) *CTLog {
	return &CTLog{
		URIs:              uris,
		Positions:         pos,
		PollInterval:      5 * time.Millisecond,
		RequestsPerSecond: 1000,
		RefreshInterval:   10 * time.Millisecond,
		Discover:          list.discover,
		Log:               discardLog(),
	}
}

func TestRefreshFollowsALogTheListAdds(t *testing.T) {
	started, added := &fakeLog{}, &fakeLog{}
	a, b := started.serve(t), added.serve(t)

	list := &listOf{uris: []string{a}}
	pos := newPositions()
	runFeed(t, refreshing([]string{a}, pos, list))

	waitFor(t, "the configured log to be followed", func() bool { return pos.seen(a) })
	if n := added.sths(); n != 0 {
		t.Fatalf("polled a log that is not on the list %d times", n)
	}

	// A new shard opens.
	list.set(a, b)
	waitFor(t, "the new log to be followed", func() bool { return pos.seen(b) })
}

func TestRefreshStopsALogTheListDrops(t *testing.T) {
	kept, dropped := &fakeLog{}, &fakeLog{treeSize: 100}
	a, b := kept.serve(t), dropped.serve(t)

	list := &listOf{uris: []string{a, b}}
	pos := newPositions()
	runFeed(t, refreshing([]string{a, b}, pos, list))
	waitFor(t, "both logs to be followed", func() bool { return pos.seen(a) && pos.seen(b) })

	// The shard expires out of the list.
	list.set(a)
	waitFor(t, "the dropped log to stop being polled", func() bool {
		before := dropped.sths()
		time.Sleep(50 * time.Millisecond)
		return dropped.sths() == before
	})

	// Stopping one follower must not stop the others.
	busy := kept.sths()
	waitFor(t, "the remaining log to keep being polled", func() bool { return kept.sths() > busy })

	// The position of a log that left is kept, because a shard can come back
	// and resuming it at the tip would lose everything logged in between.
	if got := pos.get(b); got != 100 {
		t.Errorf("position of the dropped log = %d, want the 100 it had reached", got)
	}
	list.set(a, b)
	resumed := dropped.sths()
	waitFor(t, "the returning log to be followed again", func() bool { return dropped.sths() > resumed })
	if got := pos.get(b); got != 100 {
		t.Errorf("position after the log came back = %d, want the 100 it left at", got)
	}
}

func TestRefreshThatFailsKeepsTheCurrentLogs(t *testing.T) {
	// A list that cannot be read, and a list that comes back empty, are both
	// reasons to keep following what is already working: neither is evidence
	// that every log on earth stopped accepting certificates.
	for _, tc := range []struct {
		name string
		list *listOf
	}{
		{"fetch fails", &listOf{uris: []string{"http://unused.invalid"}, err: errors.New("no route to host")}},
		{"list is empty", &listOf{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &fakeLog{}
			uri := log.serve(t)
			pos := newPositions()
			runFeed(t, refreshing([]string{uri}, pos, tc.list))

			waitFor(t, "the log to be followed", func() bool { return pos.seen(uri) })
			// Long enough for several refreshes to have come and gone.
			time.Sleep(100 * time.Millisecond)
			before := log.sths()
			waitFor(t, "the log to still be polled", func() bool { return log.sths() > before })
		})
	}
}

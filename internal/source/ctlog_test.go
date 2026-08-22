package source

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
}

func (f *fakeLog) serve(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ct/v1/get-sth", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
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

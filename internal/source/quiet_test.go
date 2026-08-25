package source

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// scriptedFeed answers Delivered with the next number in a script, so a test
// can put a feed through several checks without waiting for any of them. The
// last number stands for every check after it.
type scriptedFeed struct {
	name   string
	counts []int64
	at     int
}

func (f *scriptedFeed) Name() string { return f.name }

func (f *scriptedFeed) Delivered() int64 {
	n := f.counts[f.at]
	if f.at < len(f.counts)-1 {
		f.at++
	}
	return n
}

func (f *scriptedFeed) Run(context.Context, chan<- Cert) error { return nil }

// ticks is n checks, already due. Closing the channel is what ends the loop,
// so the watcher runs in the test's own goroutine and has finished with every
// tick by the time it returns: no sleeping, and nothing to race with.
func ticks(n int) <-chan time.Time {
	c := make(chan time.Time, n)
	for i := 0; i < n; i++ {
		c <- time.Time{}
	}
	close(c)
	return c
}

// watched runs the watcher over n checks and returns what it said above INFO.
func watched(n int, feeds ...Source) string {
	var lines bytes.Buffer
	log := slog.New(slog.NewTextHandler(&lines, &slog.HandlerOptions{Level: slog.LevelWarn}))
	watchFeeds(context.Background(), ticks(n), time.Minute, log, feeds)
	return lines.String()
}

// TestWatchFeedsReportsAFeedThatCarriesNothing is the case the run could not
// see: a feed that is connected, counted, and delivering none of the
// certificates the total is made of.
func TestWatchFeedsReportsAFeedThatCarriesNothing(t *testing.T) {
	dead := &scriptedFeed{name: "certstream", counts: []int64{0}}
	live := &scriptedFeed{name: "ctlog", counts: []int64{1000, 2000, 3000, 4000}}

	out := watched(quietBeforeWarning, dead, live)

	if !strings.Contains(out, "carried nothing since the run began") {
		t.Errorf("a feed that delivered nothing was not reported: %q", out)
	}
	if !strings.Contains(out, "source=certstream") || !strings.Contains(out, "certs=0") {
		t.Errorf("the warning does not name the silent feed or its count: %q", out)
	}
	if strings.Contains(out, "source=ctlog") {
		t.Errorf("the feed carrying the run was reported too: %q", out)
	}
	if !strings.Contains(out, "quiet_for=3m0s") {
		t.Errorf("the warning does not say how long the feed has been quiet: %q", out)
	}
}

// TestWatchFeedsWaitsOutAQuietStretch keeps the threshold honest. Certificate
// transparency has slow minutes, and a warning on the first of them would be
// noise nobody reads by the time it means something.
func TestWatchFeedsWaitsOutAQuietStretch(t *testing.T) {
	dead := &scriptedFeed{name: "certstream", counts: []int64{0}}
	if out := watched(quietBeforeWarning-1, dead); out != "" {
		t.Errorf("a feed quiet for under the threshold was reported: %q", out)
	}
}

// TestWatchFeedsSaysItOnce is the same argument turnedAway makes: a feed that
// is down for an afternoon is worth one line, not a column of them.
func TestWatchFeedsSaysItOnce(t *testing.T) {
	dead := &scriptedFeed{name: "certstream", counts: []int64{0}}
	out := watched(4*quietBeforeWarning, dead)
	if n := strings.Count(out, "source=certstream"); n != 1 {
		t.Errorf("a feed quiet throughout was reported %d times, want 1: %q", n, out)
	}
}

// TestWatchFeedsReportsAFeedThatGoesQuietTwice is the other half of saying it
// once. Carrying again is what clears the count, so a feed that recovers and
// stops a second time is a second thing worth knowing.
func TestWatchFeedsReportsAFeedThatGoesQuietTwice(t *testing.T) {
	// A baseline of 7, three checks that stay there, one delivery, and three
	// more checks that stay at 8.
	stuttering := &scriptedFeed{name: "tiled", counts: []int64{7, 7, 7, 7, 8, 8, 8, 8}}
	out := watched(8, stuttering)
	if n := strings.Count(out, "source=tiled"); n != 2 {
		t.Errorf("a feed that stopped twice was reported %d times, want 2: %q", n, out)
	}
}

// TestWatchFeedsTellsAStoppedFeedFromOneThatNeverStarted keeps the two
// silences apart. A feed that carried nothing was never going to work; one
// that has stopped was working, and its count says how well.
func TestWatchFeedsTellsAStoppedFeedFromOneThatNeverStarted(t *testing.T) {
	stopped := &scriptedFeed{name: "certstream", counts: []int64{412903}}
	out := watched(quietBeforeWarning, stopped)
	if !strings.Contains(out, "feed has gone quiet") {
		t.Errorf("a feed that stopped carrying reads as one that never carried: %q", out)
	}
	if !strings.Contains(out, "certs=412903") {
		t.Errorf("the warning does not say what the feed had carried: %q", out)
	}
}

// TestWatchFeedsLeavesACarryingFeedAlone is the ordinary run, which must stay
// silent however long it goes on.
func TestWatchFeedsLeavesACarryingFeedAlone(t *testing.T) {
	live := &scriptedFeed{name: "ctlog", counts: []int64{1, 2, 3, 4, 5, 6, 7, 8}}
	if out := watched(8, live); out != "" {
		t.Errorf("a feed delivering on every check was reported: %q", out)
	}
}

// TestWatchFeedsStopsWithTheRun guards the shutdown path: the watcher outlives
// nothing, and a cancelled run must not leave it ticking.
func TestWatchFeedsStopsWithTheRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		WatchFeeds(ctx, time.Millisecond, slog.Default(), []Source{
			&scriptedFeed{name: "certstream", counts: []int64{0}},
		})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher outlived the run")
	}
}

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

// checkEvery is the interval the tests tick at, and testStart is when their
// ticker is pretending to have started. The ticks carry real times because the
// warning measures with them.
const checkEvery = time.Minute

var testStart = time.Date(2026, 8, 25, 8, 46, 0, 0, time.UTC)

// ticks is n checks, already due, a checkEvery apart. Closing the channel is
// what ends the loop, so the watcher runs in the test's own goroutine and has
// finished with every tick by the time it returns: no sleeping, and nothing to
// race with.
func ticks(n int) <-chan time.Time {
	c := make(chan time.Time, n)
	for i := 1; i <= n; i++ {
		c <- testStart.Add(time.Duration(i) * checkEvery)
	}
	close(c)
	return c
}

// watched runs the watcher over n checks and returns what it said above INFO.
func watched(n int, feeds ...Source) string {
	return watchedWhile(n, nil, feeds...)
}

// watchedWhile is the same with a run that may not be reading.
func watchedWhile(n int, blocked func() bool, feeds ...Source) string {
	var lines bytes.Buffer
	log := slog.New(slog.NewTextHandler(&lines, &slog.HandlerOptions{Level: slog.LevelWarn}))
	watchFeeds(context.Background(), ticks(n), checkEvery, log, feeds, blocked)
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
		}, nil)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher outlived the run")
	}
}

// TestWatchFeedsBlamesNoFeedForABlockedRun is the confusion certstream's idle
// timeout already refuses to make. Every feed blocks in a send once the
// channel between them and the pipeline fills, so a run held up by a slow
// store freezes all of their counts at once — and reporting that as three
// separate feeds failing would point at everything except the problem.
func TestWatchFeedsBlamesNoFeedForABlockedRun(t *testing.T) {
	feeds := []Source{
		&scriptedFeed{name: "certstream", counts: []int64{5000}},
		&scriptedFeed{name: "ctlog", counts: []int64{9000}},
	}
	full := func() bool { return true }
	if out := watchedWhile(4*quietBeforeWarning, full, feeds...); out != "" {
		t.Errorf("a pipeline that stopped reading was reported as the feeds failing: %q", out)
	}
}

// TestWatchFeedsResumesWhenTheRunReadsAgain keeps the exemption from
// swallowing the thing it is exempting. A feed that is quiet with an empty
// channel is quiet on its own account, and the checks that found the run
// blocked must not have counted against it either way.
func TestWatchFeedsResumesWhenTheRunReadsAgain(t *testing.T) {
	dead := &scriptedFeed{name: "certstream", counts: []int64{0}}
	blocked := 0
	// Full for the first two checks, drained for every one after them.
	full := func() bool { blocked++; return blocked <= 2 }

	out := watchedWhile(2+quietBeforeWarning, full, dead)
	if !strings.Contains(out, "carried nothing") {
		t.Errorf("a dead feed went unreported after the run caught up: %q", out)
	}
}

// TestWatchFeedsMeasuresTheSilenceItSaw pins the elapsed figure to the ticks
// rather than to the interval it was configured with. A ticker drops ticks
// when the machine is busy or asleep, and three checks are worth however long
// they actually took.
func TestWatchFeedsMeasuresTheSilenceItSaw(t *testing.T) {
	dead := &scriptedFeed{name: "certstream", counts: []int64{0}}

	var lines bytes.Buffer
	log := slog.New(slog.NewTextHandler(&lines, &slog.HandlerOptions{Level: slog.LevelWarn}))
	// Three checks, but the machine was asleep across the last gap.
	c := make(chan time.Time, 3)
	c <- testStart.Add(checkEvery)
	c <- testStart.Add(2 * checkEvery)
	c <- testStart.Add(time.Hour)
	close(c)
	watchFeeds(context.Background(), c, checkEvery, log, []Source{dead}, nil)

	if out := lines.String(); !strings.Contains(out, "quiet_for=1h0m0s") {
		t.Errorf("the warning reports the interval it was configured with, not the silence it saw: %q", out)
	}
}

// TestQuietCheckOutlastsThePoll is the false positive --poll used to cause. A
// follower that has caught up delivers a burst per poll and nothing between
// them, so a check that outruns the poll finds a healthy feed at the same
// count and reports it, once per poll, forever.
func TestQuietCheckOutlastsThePoll(t *testing.T) {
	cases := []struct {
		poll time.Duration
		want time.Duration
	}{
		{30 * time.Second, DefaultQuietCheck}, // the default, unchanged
		{0, DefaultQuietCheck},                // a feed with no poll at all
		{time.Minute, 2 * time.Minute},
		{5 * time.Minute, 10 * time.Minute},
	}
	for _, c := range cases {
		if got := QuietCheck(c.poll); got != c.want {
			t.Errorf("QuietCheck(%v) = %v, want %v", c.poll, got, c.want)
		}
		if c.poll > 0 && QuietCheck(c.poll) <= c.poll {
			t.Errorf("QuietCheck(%v) does not outlast the poll it is watching", c.poll)
		}
	}
}

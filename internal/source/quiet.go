package source

import (
	"context"
	"log/slog"
	"time"
)

// DefaultQuietCheck is the shortest interval at which a run asks its feeds
// what they have carried.
const DefaultQuietCheck = time.Minute

// quietBeforeWarning is how many checks in a row a feed may carry nothing
// before the silence is worth saying out loud. It is missesBeforeWarning's
// argument applied to a whole feed rather than one tile: below it the quiet is
// certificate transparency having a slow minute, above it the feed has stopped
// carrying and nothing else in the run would report it — the counters read
// zero either way, and on any run with more than one feed a healthy total hides
// the feed contributing none of it.
//
// Three is lower than the five a tile gets because the units are checks of a
// whole feed and not requests to one log, and because a feed reading every log
// there is has a far weaker claim to a quiet stretch than a single shard does.
const quietBeforeWarning = 3

// WatchFeeds warns about a feed that has stopped carrying. It returns when ctx
// is cancelled.
//
// The interval belongs to the caller and is deliberately not --report: the
// counter line is a display preference, and a run watched on a terminal, or
// with reporting turned off entirely, loses coverage the same way as one
// logging every minute. It does have to outlast how often a healthy feed
// delivers, which is what QuietCheck is for.
//
// blocked reports whether the run has stopped reading what the feeds hand it.
// It may be nil, and see watchFeeds for why it is worth passing.
func WatchFeeds(ctx context.Context, every time.Duration, log *slog.Logger,
	feeds []Source, blocked func() bool) {
	if every <= 0 || len(feeds) == 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	watchFeeds(ctx, t.C, every, log, feeds, blocked)
}

// QuietCheck is how often a run whose logs are polled every poll should ask
// its feeds what they have carried.
//
// A follower that has caught up with a log delivers a burst once per --poll
// and nothing in between, so a check that outruns the poll finds a healthy
// feed sitting at the same count and reports it. --poll has no upper bound —
// at `--poll 5m` a one-minute check sees four still counts, warns, is rearmed
// by the next burst, and warns again, once per poll for the life of the run,
// which is the opposite of what saying it once was for. Two polls to a check
// puts a delivery inside every window a healthy feed is measured over.
func QuietCheck(poll time.Duration) time.Duration {
	if d := 2 * poll; d > DefaultQuietCheck {
		return d
	}
	return DefaultQuietCheck
}

// watchFeeds is the loop, over ticks a test can send by hand. Waiting out
// three real intervals to see one warning is the kind of test that is either
// slow or flaky, and the choice between those is not one this needs to make.
//
// The ticks carry the time they fired, and the elapsed figures come from them
// rather than from counting intervals. A ticker drops ticks when the machine
// is busy or asleep, and three checks are then worth however long they took.
func watchFeeds(ctx context.Context, tick <-chan time.Time, every time.Duration,
	log *slog.Logger, feeds []Source, blocked func() bool) {
	// The counts as they stand are the baseline, so that the first check
	// measures an interval rather than the whole run so far. Without it a
	// feed that has ever delivered spends its first check being told it
	// delivered, and reaches the warning one interval later than a feed that
	// never delivered at all.
	last := make([]int64, len(feeds))
	for i, f := range feeds {
		last[i] = f.Delivered()
	}
	quiet := make([]int, len(feeds))
	moved := make([]time.Time, len(feeds))
	for {
		var now time.Time
		select {
		case <-ctx.Done():
			return
		case t, ok := <-tick:
			if !ok {
				return
			}
			now = t
		}
		// The baseline was taken one interval before this, which is where the
		// first check measures from.
		for i := range moved {
			if moved[i].IsZero() {
				moved[i] = now.Add(-every)
			}
		}
		// A run that is not reading tells us nothing about the feeds. Every
		// feed blocks in send once the channel between them fills, so a
		// pipeline held up by a slow store freezes all of their counts at
		// once and would otherwise be reported as every feed failing
		// separately. certstream's idle timeout is careful about the same
		// confusion — a feed must not be dropped for the store's backlog —
		// and this must not name a feed for it either. A feed that is
		// carrying nothing leaves the channel empty, so the two do not look
		// alike from here.
		if blocked != nil && blocked() {
			continue
		}
		for i, f := range feeds {
			n := f.Delivered()
			if n != last[i] {
				last[i], quiet[i], moved[i] = n, 0, now
				continue
			}
			quiet[i]++
			// Said once and not every check afterwards, so a feed that is
			// down for an afternoon costs one line rather than a column of
			// them. Delivering again rearms it: a feed that goes quiet twice
			// is worth hearing about twice.
			if quiet[i] != quietBeforeWarning {
				continue
			}
			// A feed that has never carried anything and one that has
			// stopped are different problems — the first is a feed that was
			// never going to work, the second one that was working — and the
			// count it is holding at says which.
			msg := "feed has gone quiet"
			if n == 0 {
				msg = "feed has carried nothing since the run began"
			}
			log.Warn(msg, "source", f.Name(), "certs", n,
				"quiet_for", now.Sub(moved[i]).Round(time.Second))
		}
	}
}

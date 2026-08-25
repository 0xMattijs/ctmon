package source

import (
	"context"
	"log/slog"
	"time"
)

// DefaultQuietCheck is how often a run asks its feeds what they have carried.
const DefaultQuietCheck = time.Minute

// quietBeforeWarning is how many checks in a row a feed may carry nothing
// before the silence is worth saying out loud. It is missesBeforeWarning's
// argument applied to a whole feed rather than one tile: below it the quiet is
// certificate transparency having a slow minute, above it the feed has stopped
// carrying and nothing else in the run would report it — the counters read
// zero either way, and on --source both a healthy total hides the feed that is
// contributing none of it.
//
// Three is lower than the five a tile gets because the units are minutes and
// not requests, and because a feed reading every log there is has a far weaker
// claim to a quiet stretch than a single shard does.
const quietBeforeWarning = 3

// WatchFeeds warns about a feed that has stopped carrying. It returns when ctx
// is cancelled.
//
// The interval is the caller's and deliberately not --report: the counter line
// is a display preference, and a run watched on a terminal, or with reporting
// turned off entirely, loses coverage the same way as one logging every
// minute. What is being watched is the feeds, so the pace is theirs.
func WatchFeeds(ctx context.Context, every time.Duration, log *slog.Logger, feeds []Source) {
	if every <= 0 || len(feeds) == 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	watchFeeds(ctx, t.C, every, log, feeds)
}

// watchFeeds is the loop, over ticks a test can send by hand. Waiting out
// three real intervals to see one warning is the kind of test that is either
// slow or flaky, and the choice between those is not one this needs to make.
func watchFeeds(ctx context.Context, tick <-chan time.Time, every time.Duration,
	log *slog.Logger, feeds []Source) {
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
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-tick:
			if !ok {
				return
			}
		}
		for i, f := range feeds {
			n := f.Delivered()
			if n != last[i] {
				last[i], quiet[i] = n, 0
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
				"quiet_for", every*quietBeforeWarning)
		}
	}
}

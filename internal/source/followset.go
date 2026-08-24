package source

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// followSet runs one follower per log and keeps that set in line with the log
// list. It is the half of a log feed that has nothing to do with the protocol
// the logs speak: which logs to follow, when to reconsider, and how to stop
// one without disturbing the others.
//
// Both readers share it because the bookkeeping is identical and the mistakes
// in it are quiet ones. A second follower started on a log the first has not
// finished leaving reads the same entries and writes the same position, which
// can walk it backwards; a refresh that treats a failed fetch as an empty list
// stops the feed dead. Neither shows up as an error, in either protocol, so
// they are worth getting right once.
type followSet struct {
	// uris is the set to start with.
	uris []string
	// positions is read on the way out, to say where a log that left had got
	// to. Nothing else here touches it.
	positions Positions
	// discover re-reads the set, or is nil to keep uris for the life of the
	// run, which is what an explicitly named set asks for.
	discover func(context.Context) ([]string, error)
	// refresh is how often discover is called (default 24h). Logs are sharded
	// by time and roll over about twice a year, so this is about noticing a
	// boundary within a day of it happening, not about keeping up with a
	// fast-moving list.
	refresh time.Duration
	// kind names the feed in log lines, e.g. "ct log".
	kind string
	log  *slog.Logger
	// follow reads one log until ctx is cancelled. It is expected to retry on
	// its own: returning is how it says the run is over, not how it reports a
	// failure.
	follow func(ctx context.Context, uri string)
}

// run follows every log in the set until ctx is cancelled, and returns
// ctx.Err().
//
// With discover set, the set itself is reconsidered every refresh: a log the
// list has added gets a follower, one it has dropped loses its. Without that,
// a run outlives the shards it started with — logs are sharded by time, and at
// a rollover the whole set stops accepting certificates at once while this
// keeps politely asking it for entries.
func (s *followSet) run(ctx context.Context) error {
	// following holds every running follower, keyed by URI. It is touched
	// only from this goroutine — the refresh loop below runs here rather than
	// beside it — so it needs no lock of its own.
	var wg sync.WaitGroup
	following := make(map[string]*follower, len(s.uris))
	start := func(uri string) {
		fctx, cancel := context.WithCancel(ctx)
		f := &follower{cancel: cancel, done: make(chan struct{})}
		following[uri] = f
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(f.done)
			s.follow(fctx, uri)
		}()
	}
	for _, uri := range s.uris {
		if _, dup := following[uri]; !dup {
			start(uri)
		}
	}

	if s.discover != nil {
		s.refreshForever(ctx, following, start)
	}
	wg.Wait()
	return ctx.Err()
}

// refreshForever re-reads the log list on a timer and reconciles the running
// followers against it. It returns when ctx is cancelled.
//
// A refresh that fails changes nothing. The list comes over the network, and a
// monitor that stopped following every log because one fetch timed out would
// be worse off than one running on a list a day old.
func (s *followSet) refreshForever(ctx context.Context, following map[string]*follower, start func(string)) {
	t := time.NewTicker(s.refreshEvery())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		uris, err := s.discover(ctx)
		if ctx.Err() != nil {
			return
		}
		switch {
		case err != nil:
			s.log.Warn(s.kind+" list refresh failed; keeping the current logs",
				"err", err, "logs", len(following))
		case len(uris) == 0:
			// Every log at once is a broken list, not a rollover.
			s.log.Warn(s.kind+" list refresh returned no logs; keeping the current logs",
				"logs", len(following))
		default:
			s.reconcile(uris, following, start)
		}
	}
}

// reconcile starts and stops followers until the running set is uris. Both
// sides are logged at info: a monitor that swaps out its own inputs without
// saying so is hard to trust when its counters later move differently.
//
// The stored position of a log that dropped out is left where it is. A shard
// can return, Positions is keyed by URI, and forgetting the position would
// resume it at the tip and lose whatever it logged in between. It is logged on
// the way out, because a log that was behind when it left — a degraded one, or
// one --max-lag has been letting slip — leaves entries after it that nothing
// will read unless the list brings it back.
func (s *followSet) reconcile(uris []string, following map[string]*follower, start func(string)) {
	want := make(map[string]bool, len(uris))
	for _, uri := range uris {
		want[uri] = true
	}
	for uri, f := range following {
		if !want[uri] {
			f.stop()
			// Read the position after the follower has gone, not while it is
			// still moving it, so the number logged is the one it left.
			pos, _, _ := s.positions.LogPos(uri)
			s.log.Info(s.kind+" left the log list; stopped", "log", uri, "position", pos)
			delete(following, uri)
		}
	}
	for _, uri := range uris {
		if _, running := following[uri]; !running {
			s.log.Info(s.kind+" joined the log list; following", "log", uri)
			start(uri)
		}
	}
}

// refreshEvery is how often the log list is re-read.
func (s *followSet) refreshEvery() time.Duration {
	if s.refresh <= 0 {
		return 24 * time.Hour
	}
	return s.refresh
}

// follower is one running follow loop and the handle to stop it.
type follower struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// stop cancels the follower and waits for it to leave.
//
// The waiting is the point. Cancelling and returning would let the next
// refresh start a second follower for a URI the first has not finished
// leaving yet — a list served stale or half-written by a CDN is enough to ask
// for that — and two loops on one log read the same ranges and write the same
// position, which can walk it backwards. Every wait in the loop watches the
// context, so this returns as fast as the follower can notice.
func (f *follower) stop() {
	f.cancel()
	<-f.done
}

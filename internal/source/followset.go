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
	// logs is the set to start with.
	logs []Log
	// positions is read on the way out, to say where a log that left had got
	// to. Nothing else here touches it.
	positions Positions
	// discover re-reads the set, or is nil to keep logs for the life of the
	// run, which is what an explicitly named set asks for.
	discover func(context.Context) ([]Log, error)
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
	follow func(ctx context.Context, lg Log)
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
	following := make(map[string]*follower, len(s.logs))
	start := func(lg Log) {
		fctx, cancel := context.WithCancel(ctx)
		f := &follower{lg: lg, cancel: cancel, done: make(chan struct{})}
		following[lg.URI] = f
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(f.done)
			s.follow(fctx, lg)
		}()
	}
	for _, lg := range s.logs {
		if _, dup := following[lg.URI]; !dup {
			start(lg)
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
func (s *followSet) refreshForever(ctx context.Context, following map[string]*follower, start func(Log)) {
	t := time.NewTicker(s.refreshEvery())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		logs, err := s.discover(ctx)
		if ctx.Err() != nil {
			return
		}
		switch {
		case err != nil:
			s.log.Warn(s.kind+" list refresh failed; keeping the current logs",
				"err", err, "logs", len(following))
		case len(logs) == 0:
			// Every log at once is a broken list, not a rollover.
			s.log.Warn(s.kind+" list refresh returned no logs; keeping the current logs",
				"logs", len(following))
		default:
			s.reconcile(logs, following, start)
		}
	}
}

// reconcile starts and stops followers until the running set is logs. Every
// side is logged at info or above: a monitor that swaps out its own inputs
// without saying so is hard to trust when its counters later move differently.
//
// A log is matched by URI and then checked for whether it is still the same
// log. The list can republish a URL with a new key — an operator rotating one,
// or a shard replaced under the name it had — and a follower carries its key
// for the life of its run, so one that kept going would go on checking
// signatures against a key the list has retired. That is a running feed
// failing to verify a log that is behaving, which is the loudest possible way
// to be wrong about nothing, so the follower is stopped and started again on
// the new key. It is a warning rather than an info line because a log's key
// changing is rare enough to be worth a second look at.
//
// The stored position of a log that dropped out is left where it is. A shard
// can return, Positions is keyed by URI, and forgetting the position would
// resume it at the tip and lose whatever it logged in between. It is logged on
// the way out, because a log that was behind when it left — a degraded one, or
// one --max-lag has been letting slip — leaves entries after it that nothing
// will read unless the list brings it back.
func (s *followSet) reconcile(logs []Log, following map[string]*follower, start func(Log)) {
	want := make(map[string]Log, len(logs))
	for _, lg := range logs {
		want[lg.URI] = lg
	}
	// rekeyed are the logs stopped for a new key rather than for leaving, so
	// that starting them again below is not reported as joining.
	rekeyed := make(map[string]bool)
	for uri, f := range following {
		listed, stillListed := want[uri]
		if stillListed && sameLog(f.lg, listed) {
			continue
		}
		f.stop()
		// Read the position after the follower has gone, not while it is
		// still moving it, so the number logged is the one it left.
		pos, _, _ := s.positions.LogPos(uri)
		if stillListed {
			rekeyed[uri] = true
			s.log.Warn(s.kind+" changed key on the log list; restarting it",
				"log", uri, "position", pos)
		} else {
			s.log.Info(s.kind+" left the log list; stopped", "log", uri, "position", pos)
		}
		delete(following, uri)
	}
	for _, lg := range logs {
		if _, running := following[lg.URI]; running {
			continue
		}
		if !rekeyed[lg.URI] {
			s.log.Info(s.kind+" joined the log list; following", "log", lg.URI)
		}
		start(lg)
	}
}

// refreshEvery is how often the log list is re-read.
func (s *followSet) refreshEvery() time.Duration {
	if s.refresh <= 0 {
		return 24 * time.Hour
	}
	return s.refresh
}

// follower is one running follow loop, the log it was started on, and the
// handle to stop it. The log is kept so a refresh can tell a log that is still
// listed from one that has been republished with a different key.
type follower struct {
	lg     Log
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

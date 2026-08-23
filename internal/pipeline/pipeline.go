// Package pipeline turns a stream of certificates into stored domains.
//
// The work splits in two. Recording a hostname is cheap and must never be
// lost, so it happens first and blocks if the store falls behind. Fetching the
// site is slow and rate-limited, so it happens on a bounded worker pool that
// sheds load: a host whose probe is shed stays in the store marked unprobed,
// and the backfill sweep picks it up later.
package pipeline

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mvo/ct/internal/domain"
	"github.com/mvo/ct/internal/probe"
	"github.com/mvo/ct/internal/source"
	"github.com/mvo/ct/internal/store"
)

// Pipeline consumes certificates, expands their CNs into hostnames, and
// records each hostname with a hash of the HTML it serves.
type Pipeline struct {
	Store  *store.Store
	Prober *probe.Prober
	Log    *slog.Logger

	// Workers is the number of concurrent probes (default DefaultWorkers).
	Workers int
	// Writers is the number of goroutines writing to the store (default
	// DefaultWriters).
	Writers int
	// Reprobe re-fetches a known host when its last probe is older than
	// this, which is how body-hash changes get noticed. Zero never
	// re-probes a host that already has a result.
	Reprobe time.Duration
	// Backfill is how often to sweep the store for hosts that were recorded
	// but never probed. Zero disables the sweep.
	Backfill time.Duration
	// BackfillBatch caps how many pending hosts one sweep leases (default
	// DefaultBackfillBatch).
	BackfillBatch int
	// BackfillLease is how long a leased host stays out of the queue before
	// it becomes due again (default DefaultBackfillLease). It only matters
	// when a run ends holding leases: the hosts come back on their own.
	BackfillLease time.Duration
	// DeferBackoff is how long a host waits after its address turned it away
	// (default DefaultDeferBackoff).
	DeferBackoff time.Duration
	// Skip blocks hosts at or under these parent domains, muting a hosting
	// platform wholesale.
	Skip SuffixSet
	// ParentCap limits how many hosts under one registrable domain are
	// accepted per ParentWindow. Zero disables the cap.
	ParentCap int
	// ParentWindow is the cap's reset interval (default one hour).
	ParentWindow time.Duration
	// MaxDepth drops hostnames nested more than this many labels below their
	// registrable domain: 1 keeps www.example.com but drops
	// a.www.example.com. Zero accepts any depth.
	MaxDepth int
	// IgnoreSANs reads only the Common Name, skipping the SAN list.
	IgnoreSANs bool
	// MaxSANs caps how many SANs are read from one certificate. Packed
	// certificates carry thousands. Zero reads them all.
	MaxSANs int
	// NoProbe records hostnames without fetching anything.
	NoProbe bool
	// RecentHosts is how many hostnames the in-memory duplicate filter
	// remembers (default DefaultRecentHosts). Names it squashes never reach
	// the store, so they count as Dup rather than Repeat.
	RecentHosts int
	// LogDomains logs a line for every newly stored hostname. Off, the
	// counters are the only record of the flood.
	LogDomains bool

	stats   Stats
	parents *parentCap
	capOnce sync.Once
}

// Stats counts what the pipeline has done, for periodic reporting.
type Stats struct {
	Certs      atomic.Int64
	Names      atomic.Int64
	Skipped    atomic.Int64 // CNs that were not usable hostnames
	TooDeep    atomic.Int64 // hostnames rejected by MaxDepth or unowned suffixes
	Blocked    atomic.Int64 // hostnames under a skipped parent domain
	Capped     atomic.Int64 // hostnames over their parent's per-window cap
	FromSAN    atomic.Int64 // hostnames that came from a SAN, not the CN
	SANsCut    atomic.Int64 // SANs dropped by MaxSANs
	Dup        atomic.Int64 // names squashed by the in-memory recent set
	New        atomic.Int64 // hostnames stored for the first time
	Repeat     atomic.Int64 // hostnames already in the store
	Probed     atomic.Int64
	Failed     atomic.Int64
	Changed    atomic.Int64
	Deferred   atomic.Int64 // probes shed because every worker was busy
	Throttled  atomic.Int64 // probes put off because their address was over budget
	Unresolved atomic.Int64 // probes put off because the resolver gave no answer
	Backfilled atomic.Int64 // probes queued by the sweep
}

// Stats returns a pointer to the live counters.
func (p *Pipeline) Stats() *Stats { return &p.stats }

// Fields renders the counters as the alternating keys and values slog takes,
// so the progress line, the live status line, and the final line all read the
// same.
//
// The names live here rather than where they are printed, so that adding a
// counter above is one edit and not two in two packages.
func (s *Stats) Fields() []any {
	return []any{
		"certs", s.Certs.Load(),
		"names", s.Names.Load(),
		"skipped_cn", s.Skipped.Load(),
		"too_deep", s.TooDeep.Load(),
		"from_san", s.FromSAN.Load(),
		"sans_cut", s.SANsCut.Load(),
		"blocked", s.Blocked.Load(),
		"capped", s.Capped.Load(),
		"new", s.New.Load(),
		"repeat", s.Repeat.Load(),
		"dup", s.Dup.Load(),
		"probed", s.Probed.Load(),
		"probe_failed", s.Failed.Load(),
		"changed", s.Changed.Load(),
		"deferred", s.Deferred.Load(),
		"throttled", s.Throttled.Load(),
		"unresolved", s.Unresolved.Load(),
		"backfilled", s.Backfilled.Load(),
	}
}

// nameSeen is one hostname to record, with the certificate it came from.
type nameSeen struct {
	name domain.Name
	cert source.Cert
}

// Run reads certificates from in until the channel closes or ctx is
// cancelled, then returns once every queued write and probe has finished.
func (p *Pipeline) Run(ctx context.Context, in <-chan source.Cert) {
	workers, writers := p.workers(), p.writers()

	// Two queues, not one. With a single queue the sweep filled it — 5,000
	// hosts at a time, minutes to drain — so record's non-blocking send
	// always found it full and every fresh discovery was deferred. Measured
	// on a live store, a host found in the last hour was no likelier to have
	// been probed (18%) than one from the day before (22%), which is backwards
	// for a monitor whose point is noticing new things.
	fresh := make(chan string, workers*8)
	// The backlog queue stays short on purpose: the sweep can always read
	// more from the store, and buffering it only lets stale work pile up.
	backlog := make(chan store.Pending, workers)

	// Most workers take fresh discoveries first. A few are kept for the
	// backlog, so a sustained burst of new names cannot starve it completely
	// the way the backlog used to starve them.
	reserved := backlogWorkers(workers)
	var probeWG sync.WaitGroup
	for i := 0; i < workers; i++ {
		probeWG.Add(1)
		backlogOnly := i < reserved
		go func() {
			defer probeWG.Done()
			if backlogOnly {
				for item := range backlog {
					p.probeQueued(ctx, item)
				}
				return
			}
			p.probeFreshFirst(ctx, fresh, backlog)
		}()
	}

	names := make(chan nameSeen, 8192)
	var writeWG sync.WaitGroup
	for i := 0; i < writers; i++ {
		writeWG.Add(1)
		go func() {
			defer writeWG.Done()
			for n := range names {
				p.record(ctx, n, fresh)
			}
		}()
	}

	// The sweep outlives the feed only until the writers drain, so give it a
	// context we can stop independently of ctx.
	sweepCtx, stopSweep := context.WithCancel(ctx)
	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		p.sweepLoop(sweepCtx, backlog)
	}()

	// recent squashes the duplicate CNs the feeds emit within seconds of each
	// other, so a burst does not cost one store read per copy.
	recent := newRecentSet(p.recentHosts())

	for cert := range in {
		if ctx.Err() != nil {
			break
		}
		p.stats.Certs.Add(1)

		hosts := domain.ExpandCert(cert.CN, p.sans(cert.SANs))
		if len(hosts) == 0 {
			p.stats.Skipped.Add(1)
			continue
		}
		for _, h := range hosts {
			p.stats.Names.Add(1)
			if h.Origin == domain.OriginSAN {
				p.stats.FromSAN.Add(1)
			}
			if !p.acceptDepth(h.Host) {
				p.stats.TooDeep.Add(1)
				continue
			}
			if p.Skip.Blocks(h.Host) {
				p.stats.Blocked.Add(1)
				continue
			}
			if recent.seen(h.Host) {
				p.stats.Dup.Add(1)
				continue
			}
			// Recording is cheap; block rather than lose a discovery.
			select {
			case names <- nameSeen{name: h, cert: cert}:
			case <-ctx.Done():
			}
		}
	}

	close(names)
	writeWG.Wait()
	// The writers were the only senders on fresh; the sweep is the only one
	// on backlog. Close each once its senders are done.
	close(fresh)
	stopSweep()
	<-sweepDone
	close(backlog)
	probeWG.Wait()
}

// backlogWorkers is how many of the pool are pinned to the backlog. A quarter,
// and never zero: the backlog has to keep moving even while new names arrive
// faster than the pool can fetch them, which on live data is always.
func backlogWorkers(workers int) int {
	if n := workers / 4; n > 0 {
		return n
	}
	return 1
}

// probeFreshFirst serves both queues, preferring fresh. It returns once both
// are closed and drained.
func (p *Pipeline) probeFreshFirst(ctx context.Context, fresh chan string, backlog chan store.Pending) {
	for fresh != nil || backlog != nil {
		// Take a fresh discovery if one is waiting, without blocking.
		if fresh != nil {
			select {
			case host, ok := <-fresh:
				if !ok {
					fresh = nil
					continue
				}
				p.probe(ctx, host)
				continue
			default:
			}
		}
		// Nothing fresh right now, so wait on either. A nil channel blocks
		// forever in a select, which is what retires a closed queue; the loop
		// condition is what stops us waiting on two of them.
		select {
		case host, ok := <-fresh:
			if !ok {
				fresh = nil
				continue
			}
			p.probe(ctx, host)
		case item, ok := <-backlog:
			if !ok {
				backlog = nil
				continue
			}
			p.probeQueued(ctx, item)
		}
	}
}

// record stores the hostname and, when a probe is due, writes it to the
// store's pending queue and offers it to the in-memory fresh queue as well.
//
// The two are not alternatives. The queue entry is the durable one, written in
// the same transaction as the record so the two cannot disagree; the fresh
// queue is a fast path that gets recent discoveries probed ahead of a backlog
// that is drained oldest-first. A host taken by the fast path leaves its queue
// entry behind, and the sweep drops it on sight once the record shows a probe.
func (p *Pipeline) record(ctx context.Context, n nameSeen, freshQueue chan<- string) {
	var (
		fresh     bool
		wantProbe bool
		host      = n.name.Host
	)
	// The cap needs to know whether the host is already known, which costs a
	// read. Pay it only when a cap is configured.
	if p.ParentCap > 0 {
		existing, err := p.Store.Get(host)
		if err != nil {
			p.Log.Error("store read failed", "host", host, "err", err)
			return
		}
		if p.capped(host, existing != nil) {
			p.stats.Capped.Add(1)
			return
		}
	}

	// bolt may run the transaction below more than once, so the due time has
	// to be fixed before it starts: a clock read inside would queue the host
	// twice under two different keys.
	due := time.Now().UTC()
	err := p.Store.UpdateWithQueue(host, func(r *store.Record, existed bool) (bool, time.Time) {
		now := n.cert.SeenAt
		if now.IsZero() {
			now = due
		}
		fresh = !existed
		if fresh {
			r.FirstSeen = now
			r.CertName = n.name.From
			r.Origin = n.name.Origin
			r.FromWildcard = n.name.FromWildcard
		} else if r.Origin != domain.OriginCN && n.name.Origin == domain.OriginCN {
			// A later certificate names this host directly.
			r.CertName, r.Origin = n.name.From, n.name.Origin
		}
		r.LastSeen = now
		r.SeenCount++
		r.Source = n.cert.Source
		if n.cert.Issuer != "" {
			r.Issuer = n.cert.Issuer
		}
		wantProbe = !p.NoProbe && (!r.Probed || p.stale(r))
		if !wantProbe || !p.queuing() {
			return true, time.Time{}
		}
		return true, due
	})
	if err != nil {
		p.Log.Error("store write failed", "host", host, "err", err)
		return
	}

	if fresh {
		p.stats.New.Add(1)
		level := slog.LevelDebug
		if p.LogDomains {
			level = slog.LevelInfo
		}
		p.Log.Log(ctx, level, "new domain", "host", host, "from", n.name.From,
			"origin", n.name.Origin, "wildcard", n.name.FromWildcard,
			"source", n.cert.Source)
	} else {
		p.stats.Repeat.Add(1)
	}
	if !wantProbe {
		return
	}
	// A default case makes this select non-blocking, so watching ctx here
	// would only make the counter a coin flip during shutdown.
	select {
	case freshQueue <- host:
	default:
		p.stats.Deferred.Add(1)
	}
}

// probeQueued probes a host the sweep leased, then releases the lease.
//
// Dropping the entry is what finishes the work. A run that dies before this
// point leaves a lease that expires, so the host comes round again rather than
// going missing.
func (p *Pipeline) probeQueued(ctx context.Context, item store.Pending) {
	settled := p.probe(ctx, item.Host)
	if ctx.Err() != nil {
		// The run is stopping and this host may not have been fetched. Leave
		// the lease to expire rather than dropping work that was never done.
		return
	}
	if !settled {
		// The result never reached the store, so the record still says
		// unprobed. Releasing the lease here would drop the host from the
		// queue as well, and nothing would ever look at it again. Let the
		// lease run out instead.
		return
	}
	// A deferred probe has already queued the host afresh, so the lease goes
	// either way: keeping it would only fetch the host twice.
	if err := p.Store.PendingDone(item.Key); err != nil {
		p.Log.Error("release pending failed", "host", item.Host, "err", err)
	}
}

// probe fetches the host and folds the result into its record.
//
// A host turned away by its address's budget is queued again and nothing is
// written down: nothing was asked of it, so there is nothing to record, and a
// probe error would be a claim about the host that is not true.
//
// It reports whether the host is settled — either its result is in the store,
// or it has been queued afresh. A caller holding a lease must keep it when
// this is false.
func (p *Pipeline) probe(ctx context.Context, host string) bool {
	res := p.Prober.Probe(ctx, host)
	if ctx.Err() != nil {
		return false
	}
	if res.Deferred {
		if res.DeferReason == probe.DeferNoAnswer {
			p.stats.Unresolved.Add(1)
		} else {
			p.stats.Throttled.Add(1)
		}
		if err := p.Store.Enqueue(host, time.Now().UTC().Add(p.deferBackoff())); err != nil {
			p.Log.Error("requeue failed", "host", host, "err", err)
			return false
		}
		return true
	}
	p.stats.Probed.Add(1)
	if res.Err != nil {
		p.stats.Failed.Add(1)
	}

	changed := false
	probedAt := time.Now().UTC()
	// Re-probing is the only thing that queues a host again from here, and
	// its due time has to be fixed before the transaction for the same reason
	// record's does.
	var requeue time.Time
	if p.Reprobe > 0 && !p.NoProbe {
		requeue = probedAt.Add(p.Reprobe)
	}
	err := p.Store.UpdateWithQueue(host, func(r *store.Record, existed bool) (bool, time.Time) {
		if !existed {
			// The record was deleted underneath us; do not resurrect it.
			return false, time.Time{}
		}
		r.Probed = true
		r.ProbedAt = probedAt
		r.ProbeCount++
		r.HTTPStatus = res.Status
		r.FinalURL = res.FinalURL
		if res.Err != nil {
			r.ProbeError = res.Err.Error()
			return true, requeue
		}
		r.ProbeError = ""
		r.BodySize = res.Size
		if r.BodyHash != "" && r.BodyHash != res.Hash {
			r.PrevHash = r.BodyHash
			r.ChangedAt = r.ProbedAt
			changed = true
		}
		r.BodyHash = res.Hash
		return true, requeue
	})
	if err != nil {
		p.Log.Error("store write failed", "host", host, "err", err)
		return false
	}

	switch {
	case changed:
		p.stats.Changed.Add(1)
		p.Log.Info("body changed", "host", host, "sha256", res.Hash, "status", res.Status)
	case res.Err != nil:
		p.Log.Debug("probe failed", "host", host, "err", res.Err)
	default:
		p.Log.Debug("probed", "host", host, "status", res.Status,
			"size", res.Size, "sha256", res.Hash)
	}
	return true
}

// sweepLoop periodically hands the probers hosts from the store's pending
// queue, which is how shed and deferred probes eventually get done.
func (p *Pipeline) sweepLoop(ctx context.Context, backlog chan<- store.Pending) {
	if p.Backfill <= 0 || p.NoProbe {
		return
	}
	t := time.NewTicker(p.Backfill)
	defer t.Stop()
	stalled := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Feeding the backlog while the resolver cannot answer is worse
			// than doing nothing: every host leased comes straight back
			// undone, so the sweep spins through the queue rewriting entries
			// and the resolver never gets the quiet it needs to recover. On a
			// live run that looked like 156,130 deferrals against 9,981
			// probes. Wait instead.
			if !p.resolverHealthy() {
				if !stalled {
					stalled = true
					p.Log.Warn("backfill paused: the resolver is not answering")
				}
				continue
			}
			if stalled {
				stalled = false
				p.Log.Info("backfill resumed: the resolver is answering again")
			}
			p.sweep(ctx, backlog)
		}
	}
}

// resolverHealthy reports whether it is worth handing the probers more work.
// A pipeline without a prober — the no-probe path, and some tests — is never
// held back by this.
func (p *Pipeline) resolverHealthy() bool {
	return p.Prober == nil || p.Prober.ResolverHealthy()
}

// sweep leases a batch of due hosts and queues them. Queuing blocks, so the
// sweep runs at whatever pace the probers manage.
//
// The queue is ordered by due time, so this takes the hosts that have waited
// longest — no scan, and no part of the keyspace that the sweep never reaches.
func (p *Pipeline) sweep(ctx context.Context, backlog chan<- store.Pending) {
	pending, err := p.Store.PendingLease(time.Now().UTC(), p.backfillBatch(), p.backfillLease())
	if err != nil {
		p.Log.Error("backfill sweep failed", "err", err)
		return
	}
	if len(pending) == 0 {
		return
	}

	// The fast path leaves an entry behind for every discovery it probes
	// itself, so most of a batch is usually already done. Sort that out in one
	// read and one delete rather than a transaction per host: a 5,000-host
	// batch was costing some ten thousand of them every sweep.
	want, err := p.wantsProbe(pending)
	if err != nil {
		p.Log.Error("store read failed", "err", err)
		return
	}
	var done [][]byte
	queued := 0
	for _, item := range pending {
		if !want[item.Host] {
			done = append(done, item.Key)
			continue
		}
		select {
		case backlog <- item:
			queued++
			p.stats.Backfilled.Add(1)
		case <-ctx.Done():
			// Hand back what has not been sent. The rest keep their leases
			// and come round again.
			if err := p.Store.PendingDone(done...); err != nil {
				p.Log.Error("release pending failed", "err", err)
			}
			return
		}
	}
	if err := p.Store.PendingDone(done...); err != nil {
		p.Log.Error("release pending failed", "err", err)
	}
	p.Log.Info("backfill sweep", "queued", queued, "already_done", len(done))
}

// wantsProbe reports which of these hosts still need fetching. A host whose
// record has gone wants nothing: it was deleted, not forgotten.
func (p *Pipeline) wantsProbe(items []store.Pending) (map[string]bool, error) {
	hosts := make([]string, 0, len(items))
	for _, it := range items {
		hosts = append(hosts, it.Host)
	}
	recs, err := p.Store.GetAll(hosts)
	if err != nil {
		return nil, err
	}
	want := make(map[string]bool, len(recs))
	for host, rec := range recs {
		want[host] = !rec.Probed || p.stale(rec)
	}
	return want, nil
}

// queuing reports whether the pending queue is in use. Without a sweep nothing
// ever takes entries out of it, so writing them would grow the bucket by every
// hostname seen, for ever — at live rates some millions a day — while no probe
// ever came of it.
func (p *Pipeline) queuing() bool { return p.Backfill > 0 && !p.NoProbe }

// sans applies the SAN policy: none when IgnoreSANs is set, otherwise the
// first MaxSANs of them.
func (p *Pipeline) sans(sans []string) []string {
	switch {
	case p.IgnoreSANs:
		return nil
	case p.MaxSANs > 0 && len(sans) > p.MaxSANs:
		p.stats.SANsCut.Add(int64(len(sans) - p.MaxSANs))
		return sans[:p.MaxSANs]
	default:
		return sans
	}
}

// capped reports whether host is over its parent's budget. Known hosts are
// exempt: the cap exists to slow discovery of new names under a flooding
// parent, not to stop existing records from being refreshed.
func (p *Pipeline) capped(host string, existed bool) bool {
	p.capOnce.Do(func() { p.parents = newParentCap(p.ParentCap, p.ParentWindow) })
	if p.parents == nil || existed {
		return false
	}
	return !p.parents.allow(host, time.Now())
}

// acceptDepth applies the subdomain nesting limit. A host that is itself a
// public suffix is always rejected: nobody can own it, so it is not a
// discovery.
func (p *Pipeline) acceptDepth(host string) bool {
	depth, ok := domain.Depth(host)
	if !ok {
		return false
	}
	return p.MaxDepth <= 0 || depth <= p.MaxDepth
}

// stale reports whether a probed host is due for another probe.
func (p *Pipeline) stale(rec *store.Record) bool {
	if p.Reprobe <= 0 || !rec.Probed {
		return false
	}
	return time.Since(rec.ProbedAt) >= p.Reprobe
}

// recentSet is a bounded set of recently handled hosts. It exists to shed
// duplicate work, so forgetting an entry early is harmless.
type recentSet struct {
	mu    sync.Mutex
	max   int
	hosts map[string]struct{}
}

func newRecentSet(max int) *recentSet {
	return &recentSet{max: max, hosts: make(map[string]struct{}, max/4)}
}

// seen records host and reports whether it was already present.
func (r *recentSet) seen(host string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.hosts[host]; ok {
		return true
	}
	if len(r.hosts) >= r.max {
		// Cheapest possible eviction: start over. The set is an optimization,
		// not a correctness boundary — the store is the real deduplicator.
		r.hosts = make(map[string]struct{}, r.max/4)
	}
	r.hosts[host] = struct{}{}
	return false
}

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
	"errors"
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

	// Workers is the number of concurrent probes (default 16).
	Workers int
	// Writers is the number of goroutines writing to the store (default 4).
	Writers int
	// Reprobe re-fetches a known host when its last probe is older than
	// this, which is how body-hash changes get noticed. Zero never
	// re-probes a host that already has a result.
	Reprobe time.Duration
	// Backfill is how often to sweep the store for hosts that were recorded
	// but never probed. Zero disables the sweep.
	Backfill time.Duration
	// BackfillBatch caps how many pending hosts one sweep queues (default 5000).
	BackfillBatch int
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
	Backfilled atomic.Int64 // probes queued by the sweep
}

// Stats returns a pointer to the live counters.
func (p *Pipeline) Stats() *Stats { return &p.stats }

// nameSeen is one hostname to record, with the certificate it came from.
type nameSeen struct {
	name domain.Name
	cert source.Cert
}

// Run reads certificates from in until the channel closes or ctx is
// cancelled, then returns once every queued write and probe has finished.
func (p *Pipeline) Run(ctx context.Context, in <-chan source.Cert) {
	workers := p.Workers
	if workers <= 0 {
		workers = 16
	}
	writers := p.Writers
	if writers <= 0 {
		writers = 4
	}

	probes := make(chan string, workers*8)
	var probeWG sync.WaitGroup
	for i := 0; i < workers; i++ {
		probeWG.Add(1)
		go func() {
			defer probeWG.Done()
			for host := range probes {
				p.probe(ctx, host)
			}
		}()
	}

	names := make(chan nameSeen, 8192)
	var writeWG sync.WaitGroup
	for i := 0; i < writers; i++ {
		writeWG.Add(1)
		go func() {
			defer writeWG.Done()
			for n := range names {
				p.record(ctx, n, probes)
			}
		}()
	}

	// The sweep outlives the feed only until the writers drain, so give it a
	// context we can stop independently of ctx.
	sweepCtx, stopSweep := context.WithCancel(ctx)
	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		p.sweepLoop(sweepCtx, probes)
	}()

	// recent squashes the duplicate CNs the feeds emit within seconds of each
	// other, so a burst does not cost one store read per copy.
	recentHosts := p.RecentHosts
	if recentHosts <= 0 {
		recentHosts = DefaultRecentHosts
	}
	recent := newRecentSet(recentHosts)

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
	stopSweep()
	<-sweepDone
	close(probes)
	probeWG.Wait()
}

// record stores the hostname and queues a probe if one is due. A full probe
// queue is not an error: the record stays unprobed and the sweep retries it.
func (p *Pipeline) record(ctx context.Context, n nameSeen, probes chan<- string) {
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

	err := p.Store.Update(host, func(r *store.Record, existed bool) bool {
		now := n.cert.SeenAt
		if now.IsZero() {
			now = time.Now().UTC()
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
		return true
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
	case probes <- host:
	default:
		p.stats.Deferred.Add(1)
	}
}

// probe fetches the host and folds the result into its record.
func (p *Pipeline) probe(ctx context.Context, host string) {
	res := p.Prober.Probe(ctx, host)
	if ctx.Err() != nil {
		return
	}
	p.stats.Probed.Add(1)
	if res.Err != nil {
		p.stats.Failed.Add(1)
	}

	changed := false
	err := p.Store.Update(host, func(r *store.Record, existed bool) bool {
		if !existed {
			// The record was deleted underneath us; do not resurrect it.
			return false
		}
		r.Probed = true
		r.ProbedAt = time.Now().UTC()
		r.ProbeCount++
		r.HTTPStatus = res.Status
		r.FinalURL = res.FinalURL
		if res.Err != nil {
			r.ProbeError = res.Err.Error()
			return true
		}
		r.ProbeError = ""
		r.BodySize = res.Size
		if r.BodyHash != "" && r.BodyHash != res.Hash {
			r.PrevHash = r.BodyHash
			r.ChangedAt = r.ProbedAt
			changed = true
		}
		r.BodyHash = res.Hash
		return true
	})
	if err != nil {
		p.Log.Error("store write failed", "host", host, "err", err)
		return
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
}

// sweepLoop periodically queues hosts that were recorded but never probed,
// which is how shed probes eventually get done.
func (p *Pipeline) sweepLoop(ctx context.Context, probes chan<- string) {
	if p.Backfill <= 0 || p.NoProbe {
		return
	}
	t := time.NewTicker(p.Backfill)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.sweep(ctx, probes)
		}
	}
}

// sweep collects pending hosts in one read transaction, then queues them.
// Queuing blocks, so the sweep runs at whatever pace the probers manage.
func (p *Pipeline) sweep(ctx context.Context, probes chan<- string) {
	limit := p.BackfillBatch
	if limit <= 0 {
		limit = 5000
	}

	var pending []string
	err := p.Store.ForEach(func(r *store.Record) error {
		if len(pending) >= limit {
			return errStopWalk
		}
		if !r.Probed || p.stale(r) {
			pending = append(pending, r.Host)
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopWalk) {
		p.Log.Error("backfill sweep failed", "err", err)
		return
	}
	if len(pending) == 0 {
		return
	}
	p.Log.Info("backfill sweep", "pending", len(pending))
	for _, host := range pending {
		select {
		case probes <- host:
			p.stats.Backfilled.Add(1)
		case <-ctx.Done():
			return
		}
	}
}

// errStopWalk ends a store walk early. It never escapes sweep.
var errStopWalk = stopWalk{}

type stopWalk struct{}

func (stopWalk) Error() string { return "stop walk" }

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

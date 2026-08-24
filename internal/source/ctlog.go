package source

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
	"golang.org/x/time/rate"
)

// Positions persists how far each log has been read, so a restart resumes
// where the previous run stopped instead of replaying or skipping entries.
type Positions interface {
	LogPos(uri string) (pos uint64, ok bool, err error)
	SetLogPos(uri string, pos uint64) error
}

// CTLog polls CT logs directly over RFC 6962 (get-sth, get-entries). It
// depends on nobody but the logs themselves and resumes cleanly after a
// restart, at the cost of more requests than the firehose.
type CTLog struct {
	// URIs are the log base URLs to follow, e.g.
	// "https://ct.googleapis.com/logs/us1/argon2026h1".
	URIs []string
	// Positions stores per-log read positions. Required.
	Positions Positions
	// FromStart reads each log from index 0 the first time it is seen.
	// The default starts at the log's current tree head, which is what you
	// want for discovering newly issued certificates.
	FromStart bool
	// BatchSize is the number of entries to ask for per get-entries call
	// (default 256). It is a ceiling, not a promise: a log that cannot
	// deliver that many before the request times out gets asked for less.
	BatchSize int
	// MaxLag skips a log ahead to its tree head once it is more than this
	// many entries behind. A degraded log falls behind faster than any
	// client can read it, and this monitor is after new certificates, not a
	// complete history. Zero never skips, which is what you want when
	// following a log from the start.
	MaxLag uint64
	// PollInterval is how long to wait after catching up with a log's tree
	// head before asking for a new one (default 30s).
	PollInterval time.Duration
	// RequestsPerSecond caps get-entries calls per log (default 4).
	RequestsPerSecond float64
	UserAgent         string
	// DialContext overrides how connections to the logs are made. It exists
	// so the monitor can give its own feed the same resolver it gives the
	// probers: left to the system resolver, a run probing hard enough to
	// saturate DNS starves its own source of certificates, which fails as
	// "get-sth: ... server misbehaving" and stops the feed entirely.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// Discover re-reads the set of logs worth following, normally
	// DiscoverLogs against the same list URI startup used. Set it and Run
	// reconsiders the set every RefreshInterval; leave it nil and URIs is the
	// set for the life of the run, which is what --logs asks for.
	Discover func(ctx context.Context) ([]string, error)
	// RefreshInterval is how often Discover is called (default 24h). Logs are
	// sharded by time and roll over about twice a year, so this is about
	// noticing a boundary within a day of it happening, not about keeping up
	// with a fast-moving list.
	RefreshInterval time.Duration
	Log             *slog.Logger
}

// Batch sizes are adapted per log between minBatchSize and the configured
// ceiling: halved after a failed get-entries, raised a step after a good one.
// A log serving a few KB/s cannot answer for 256 entries inside the request
// timeout, and asking again for the same 256 makes no progress at all.
const minBatchSize = 8

// logState is what the follow loop learns about one log and keeps across
// restarts of that loop.
type logState struct {
	batch int // entries to request now
	max   int // the configured ceiling
}

// shrink halves the batch after a failure, down to minBatchSize.
func (s *logState) shrink() {
	if s.batch > minBatchSize {
		s.batch = max(minBatchSize, s.batch/2)
	}
}

// grow raises the batch a step after a success, up to the ceiling. It climbs
// by addition and falls by halving, so a log that is merely slow settles at a
// size it can serve instead of oscillating between the extremes.
func (s *logState) grow() {
	if s.batch < s.max {
		s.batch = min(s.max, s.batch+minBatchSize)
	}
}

// Name implements Source.
func (c *CTLog) Name() string { return "ctlog" }

// DefaultShardLookahead is how far ahead of now a shard may open and still be
// followed. It tracks the maximum certificate validity period the CA/Browser
// Forum allows: 200 days from March 2026, 100 from March 2027, 47 from March
// 2029.
//
// A shard's temporal interval bounds the certificate's NotAfter, not when it
// was submitted, so the shard new certificates land in runs ahead of the clock
// by up to that period. Set this shorter than the real limit and the newest
// shard is missed for the months before its interval opens — which is exactly
// when issuance is moving into it. Set it longer and the extra shards are
// merely empty: they cost a get-sth per poll and return nothing.
//
// So it is deliberately the *old*, longer limit rather than the current one.
// Being late to shrink it wastes a few requests; being early to shrink it
// loses certificates.
const DefaultShardLookahead = 200 * 24 * time.Hour

// DiscoverLogs returns the URIs of the logs in Google's v3 log list that are
// worth following now: approved for Chrome, and able to be accepting
// certificates today. Those are the logs where new certificates actually land.
//
// lookahead is how far ahead of now a shard may open and still be followed;
// zero means DefaultShardLookahead. See that constant for why the window is
// not simply "the interval contains now".
func DiscoverLogs(ctx context.Context, hc *http.Client, listURL string, lookahead time.Duration) ([]string, error) {
	if listURL == "" {
		listURL = loglist3.LogListURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch log list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch log list: %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read log list: %w", err)
	}
	ll, err := loglist3.NewFromJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("parse log list: %w", err)
	}

	uris := selectLogs(ll, time.Now(), lookahead)
	if len(uris) == 0 {
		return nil, fmt.Errorf("log list %s contained no logs accepting certificates now", listURL)
	}
	return uris, nil
}

// selectLogs picks the usable logs that could be accepting certificates at
// now, given the lookahead. It is separate from DiscoverLogs so the rule can
// be tested against a clock rather than against the calendar.
//
// A log with no temporal interval is not sharded and is always kept.
func selectLogs(ll *loglist3.LogList, now time.Time, lookahead time.Duration) []string {
	if lookahead <= 0 {
		lookahead = DefaultShardLookahead
	}
	opensBy := now.Add(lookahead)
	usable := ll.SelectByStatus([]loglist3.LogStatus{loglist3.UsableLogStatus})
	var uris []string
	for _, op := range usable.Operators {
		for _, lg := range op.Logs {
			if ti := lg.TemporalInterval; ti != nil {
				// Ended: it takes nothing now, whatever it took before.
				if !now.Before(ti.EndExclusive) {
					continue
				}
				// Too far out: nothing issued today expires that late, so
				// nothing is being written to it yet.
				if ti.StartInclusive.After(opensBy) {
					continue
				}
			}
			uris = append(uris, lg.URL)
		}
	}
	return uris
}

// Run follows every configured log until ctx is cancelled. A log that keeps
// failing is retried with backoff rather than taking the others down with it.
//
// With Discover set, the set itself is reconsidered every RefreshInterval:
// a log the list has added gets a follower, one it has dropped loses its.
// Without that, a run outlives the shards it started with — logs are sharded
// by time, and at a rollover the whole set stops accepting certificates at
// once while this keeps politely asking it for entries.
func (c *CTLog) Run(ctx context.Context, out chan<- Cert) error {
	if c.Positions == nil {
		return fmt.Errorf("ctlog: Positions is required")
	}
	if len(c.URIs) == 0 {
		return fmt.Errorf("ctlog: no log URIs configured")
	}

	// following holds every running follower, keyed by URI. It is touched
	// only from this goroutine — the refresh loop below runs here rather than
	// beside it — so it needs no lock of its own.
	var wg sync.WaitGroup
	following := make(map[string]*follower, len(c.URIs))
	follow := func(uri string) {
		fctx, cancel := context.WithCancel(ctx)
		f := &follower{cancel: cancel, done: make(chan struct{})}
		following[uri] = f
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(f.done)
			c.followForever(fctx, uri, out)
		}()
	}
	for _, uri := range c.URIs {
		if _, dup := following[uri]; !dup {
			follow(uri)
		}
	}

	if c.Discover != nil {
		c.refreshForever(ctx, following, follow)
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
func (c *CTLog) refreshForever(ctx context.Context, following map[string]*follower, follow func(string)) {
	t := time.NewTicker(c.refreshEvery())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		uris, err := c.Discover(ctx)
		if ctx.Err() != nil {
			return
		}
		switch {
		case err != nil:
			c.Log.Warn("ct log list refresh failed; keeping the current logs",
				"err", err, "logs", len(following))
		case len(uris) == 0:
			// Every log at once is a broken list, not a rollover.
			c.Log.Warn("ct log list refresh returned no logs; keeping the current logs",
				"logs", len(following))
		default:
			c.reconcile(uris, following, follow)
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
func (c *CTLog) reconcile(uris []string, following map[string]*follower, follow func(string)) {
	want := make(map[string]bool, len(uris))
	for _, uri := range uris {
		want[uri] = true
	}
	for uri, f := range following {
		if !want[uri] {
			f.stop()
			// Read the position after the follower has gone, not while it is
			// still moving it, so the number logged is the one it left.
			pos, _, _ := c.Positions.LogPos(uri)
			c.Log.Info("ct log left the log list; stopped", "log", uri, "position", pos)
			delete(following, uri)
		}
	}
	for _, uri := range uris {
		if _, running := following[uri]; !running {
			c.Log.Info("ct log joined the log list; following", "log", uri)
			follow(uri)
		}
	}
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

// refreshEvery is how often the log list is re-read.
func (c *CTLog) refreshEvery() time.Duration {
	if c.RefreshInterval <= 0 {
		return 24 * time.Hour
	}
	return c.RefreshInterval
}

// followForever restarts follow after any failure, backing off between tries.
// The backoff counter resets after a run that lasted, so an occasional failure
// on a healthy log costs one short pause rather than a permanently long one.
func (c *CTLog) followForever(ctx context.Context, uri string, out chan<- Cert) {
	st := &logState{batch: c.batchCeiling(), max: c.batchCeiling()}
	rt := retry{base: 5 * time.Second, max: 10 * time.Minute}
	for ctx.Err() == nil {
		start := time.Now()
		err := c.follow(ctx, uri, out, st)
		if ctx.Err() != nil {
			return
		}
		ran := time.Since(start)
		d := rt.after(ran)
		c.Log.Warn("ct log follow failed", "log", uri, "err", err,
			"ran", ran.Round(time.Second), "batch", st.batch, "retry_in", d)
		if sleep(ctx, d) != nil {
			return
		}
	}
}

// batchCeiling is the configured entries-per-request limit.
func (c *CTLog) batchCeiling() int {
	if c.BatchSize <= 0 {
		return 256
	}
	return max(minBatchSize, c.BatchSize)
}

// follow reads one log from its stored position to the tip, then keeps pace
// with it. It returns on the first error so the caller can back off.
func (c *CTLog) follow(ctx context.Context, uri string, out chan<- Cert, st *logState) error {
	poll := c.PollInterval
	if poll <= 0 {
		poll = 30 * time.Second
	}
	rps := c.RequestsPerSecond
	if rps <= 0 {
		rps = 4
	}
	limiter := rate.NewLimiter(rate.Limit(rps), 1)

	lc, err := client.New(uri, c.httpClient(), jsonclient.Options{UserAgent: c.UserAgent})
	if err != nil {
		return fmt.Errorf("client: %w", err)
	}

	pos, ok, err := c.Positions.LogPos(uri)
	if err != nil {
		return fmt.Errorf("read position: %w", err)
	}

	for ctx.Err() == nil {
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
		sth, err := lc.GetSTH(ctx)
		if err != nil {
			return fmt.Errorf("get-sth: %w", err)
		}
		firstSight := !ok
		if !ok {
			// First sight of this log: start at the tip unless asked to
			// backfill, so we report new certificates rather than history.
			pos = 0
			if !c.FromStart {
				pos = sth.TreeSize
			}
			ok = true
			if err := c.Positions.SetLogPos(uri, pos); err != nil {
				return fmt.Errorf("save position: %w", err)
			}
			c.Log.Info("following ct log", "log", uri, "start", pos, "tree_size", sth.TreeSize)
		}
		// A log that outruns us by more than MaxLag is serving history we
		// will never catch up on, and almost every certificate in that
		// backlog reached the store through another log hours ago. Skipping
		// is deliberate data loss, so it happens only when asked for, and
		// never on the first sight of a log, where --from-start means the
		// gap is the point.
		if c.MaxLag > 0 && !firstSight && sth.TreeSize > pos && sth.TreeSize-pos > c.MaxLag {
			skipped := sth.TreeSize - pos
			pos = sth.TreeSize
			if err := c.Positions.SetLogPos(uri, pos); err != nil {
				return fmt.Errorf("save position: %w", err)
			}
			c.Log.Warn("ct log too far behind; skipped to tip",
				"log", uri, "skipped", skipped, "tree_size", sth.TreeSize)
		}
		if pos > sth.TreeSize {
			// The log shrank, which means it was reset or replaced.
			c.Log.Warn("ct log tree shrank; resetting position",
				"log", uri, "pos", pos, "tree_size", sth.TreeSize)
			pos = sth.TreeSize
			if err := c.Positions.SetLogPos(uri, pos); err != nil {
				return fmt.Errorf("save position: %w", err)
			}
		}

		for pos < sth.TreeSize && ctx.Err() == nil {
			end := pos + uint64(st.batch) - 1
			if end >= sth.TreeSize {
				end = sth.TreeSize - 1
			}
			if err := limiter.Wait(ctx); err != nil {
				return err
			}
			resp, err := lc.GetRawEntries(ctx, int64(pos), int64(end))
			if err != nil {
				// Any failure here is a reason to ask for less: a timeout
				// says the log cannot serve this many in time, and a refusal
				// often says the same about the range. Our own shutdown says
				// nothing about the log, so it leaves the size alone.
				if ctx.Err() == nil {
					st.shrink()
					c.Log.Debug("ct log batch shrunk", "log", uri, "batch", st.batch, "err", err)
				}
				return fmt.Errorf("get-entries [%d,%d]: %w", pos, end, err)
			}
			if len(resp.Entries) == 0 {
				st.shrink()
				return fmt.Errorf("get-entries [%d,%d]: empty response", pos, end)
			}
			st.grow()
			for i := range resp.Entries {
				index := int64(pos) + int64(i)
				cert, ok := c.parseEntry(uri, index, &resp.Entries[i])
				if !ok {
					continue
				}
				if err := send(ctx, out, cert); err != nil {
					return err
				}
			}
			// Logs may return fewer entries than asked for, so trust the count.
			pos += uint64(len(resp.Entries))
			if err := c.Positions.SetLogPos(uri, pos); err != nil {
				return fmt.Errorf("save position: %w", err)
			}
		}

		if err := sleep(ctx, poll); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// parseEntry pulls the CN out of one log entry. Entries that fail to parse are
// skipped: CT logs carry plenty of certificates that Go's parser rejects, and
// one bad entry must not stall the feed.
func (c *CTLog) parseEntry(uri string, index int64, leaf *ct.LeafEntry) (Cert, bool) {
	raw, err := ct.RawLogEntryFromLeaf(index, leaf)
	if err != nil {
		c.Log.Debug("ct entry unreadable", "log", uri, "index", index, "err", err)
		return Cert{}, false
	}
	entry, err := raw.ToLogEntry()
	if entry == nil {
		c.Log.Debug("ct entry unparsable", "log", uri, "index", index, "err", err)
		return Cert{}, false
	}

	// A precertificate carries its names in a TBSCertificate, which ct-go
	// parses into the same x509.Certificate an ordinary entry holds, so both
	// kinds are read the same way once the right one is in hand.
	var x *x509.Certificate
	switch {
	case entry.X509Cert != nil:
		x = entry.X509Cert
	case entry.Precert != nil:
		x = entry.Precert.TBSCertificate
	}
	if x == nil {
		return Cert{}, false
	}
	if x.Subject.CommonName == "" && len(x.DNSNames) == 0 {
		return Cert{}, false
	}
	cert := Cert{
		CN:        x.Subject.CommonName,
		SANs:      x.DNSNames,
		Issuer:    issuerName(x.Issuer.CommonName, x.Issuer.Organization),
		NotBefore: x.NotBefore.UTC(),
		NotAfter:  x.NotAfter.UTC(),
	}
	cert.SeenAt = time.Now().UTC()
	cert.Source = uri
	cert.Index = index
	return cert, true
}

func issuerName(cn string, org []string) string {
	if cn != "" {
		return cn
	}
	if len(org) > 0 {
		return org[0]
	}
	return ""
}

// httpClient builds the client used to talk to a log, honouring DialContext.
func (c *CTLog) httpClient() *http.Client {
	hc := &http.Client{Timeout: 60 * time.Second}
	if c.DialContext != nil {
		hc.Transport = &http.Transport{
			DialContext:         c.DialContext,
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 2,
		}
	}
	return hc
}

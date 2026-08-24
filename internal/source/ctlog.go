package source

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
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

// LogSet is one pass over the log list, split by the protocol the logs speak.
//
// Google's v3 list carries two kinds of log per operator and they are not two
// spellings of the same thing: an RFC 6962 log answers get-sth and
// get-entries, a Static CT API log serves a signed checkpoint and tiles off
// static storage and answers neither. They need separate readers, so they are
// discovered into separate fields rather than concatenated into one list of
// URLs that would fail every poll for half its members.
type LogSet struct {
	// RFC6962 are base URLs, e.g.
	// "https://ct.googleapis.com/logs/us1/argon2026h2/".
	RFC6962 []string
	// Tiled are monitoring URLs, e.g.
	// "https://mon.sycamore.ct.letsencrypt.org/2026h2/". A tiled log also
	// publishes a submission URL, which is where certificates are sent and
	// not where they are read.
	//
	// Which of the two is stored here is a decision that outlives the run:
	// Positions is keyed by URI, so switching to the other one later resumes
	// every tiled log at its tip.
	Tiled []string
}

// Total is how many logs the set holds, of either kind.
func (s LogSet) Total() int { return len(s.RFC6962) + len(s.Tiled) }

// DiscoverLogs returns the logs in Google's v3 log list that are worth
// following now: approved for Chrome, and able to be accepting certificates
// today. Those are the logs where new certificates actually land.
//
// lookahead is how far ahead of now a shard may open and still be followed.
// Zero is no lookahead: only the shards whose interval contains now, which is
// cheaper and misses the shard being written to. See DefaultShardLookahead for
// why that is the wrong default.
//
// Both kinds of log come back from one fetch. Which of them a run follows is
// the caller's decision, and an empty side is not an error here — only a list
// with nothing usable on it at all is.
func DiscoverLogs(ctx context.Context, hc *http.Client, listURL string, lookahead time.Duration) (LogSet, error) {
	if listURL == "" {
		listURL = loglist3.LogListURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return LogSet{}, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return LogSet{}, fmt.Errorf("fetch log list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return LogSet{}, fmt.Errorf("fetch log list: %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return LogSet{}, fmt.Errorf("read log list: %w", err)
	}
	ll, err := loglist3.NewFromJSON(raw)
	if err != nil {
		return LogSet{}, fmt.Errorf("parse log list: %w", err)
	}

	set := selectLogs(ll, time.Now(), lookahead)
	if set.Total() == 0 {
		return LogSet{}, fmt.Errorf("log list %s contained no logs accepting certificates now", listURL)
	}
	return set, nil
}

// selectLogs picks the usable logs that could be accepting certificates at
// now, given the lookahead. It is separate from DiscoverLogs so the rule can
// be tested against a clock rather than against the calendar.
//
// A lookahead of zero asks for no lookahead at all, matching what zero means
// on every other duration this program takes. It is not quietly promoted to
// DefaultShardLookahead: the only caller that can pass zero is one that asked
// for it, and answering an explicit "cheapest" with the widest window there is
// would double the request load the operator was trying to avoid. Negative is
// the same as zero — there is no window narrower than none.
//
// A log with no temporal interval is not sharded and is always kept.
//
// The status filter is written out here rather than taken from
// loglist3.SelectByStatus, which cannot be used for this: it filters Logs and
// copies TiledLogs through untouched, and it drops any operator left with no
// usable RFC 6962 log — taking that operator's tiled logs with it. Both
// mistakes point the same way, which is towards following tiled logs Chrome
// has retired while missing the ones it has not.
func selectLogs(ll *loglist3.LogList, now time.Time, lookahead time.Duration) LogSet {
	opensBy := now
	if lookahead > 0 {
		opensBy = now.Add(lookahead)
	}
	var set LogSet
	for _, op := range ll.Operators {
		for _, lg := range op.Logs {
			if usableNow(lg.State, lg.TemporalInterval, now, opensBy) {
				set.RFC6962 = append(set.RFC6962, lg.URL)
			}
		}
		for _, lg := range op.TiledLogs {
			if usableNow(lg.State, lg.TemporalInterval, now, opensBy) {
				set.Tiled = append(set.Tiled, lg.MonitoringURL)
			}
		}
	}
	return set
}

// usableNow is the rule both kinds of log are judged by: approved for Chrome,
// and with a temporal interval that has not ended and opens by opensBy.
func usableNow(state *loglist3.LogStates, ti *loglist3.TemporalInterval, now, opensBy time.Time) bool {
	if state.LogStatus() != loglist3.UsableLogStatus {
		return false
	}
	if ti == nil {
		return true
	}
	// Ended: it takes nothing now, whatever it took before.
	if !now.Before(ti.EndExclusive) {
		return false
	}
	// Too far out: nothing issued today expires that late, so nothing is
	// being written to it yet.
	return !ti.StartInclusive.After(opensBy)
}

// Run follows every configured log until ctx is cancelled. A log that keeps
// failing is retried with backoff rather than taking the others down with it.
// The set is reconsidered on a timer when Discover is set; see followSet.
func (c *CTLog) Run(ctx context.Context, out chan<- Cert) error {
	if c.Positions == nil {
		return fmt.Errorf("ctlog: Positions is required")
	}
	if len(c.URIs) == 0 {
		return fmt.Errorf("ctlog: no log URIs configured")
	}
	set := &followSet{
		uris:      c.URIs,
		positions: c.Positions,
		discover:  c.Discover,
		refresh:   c.RefreshInterval,
		kind:      "ct log",
		log:       c.Log,
		follow: func(fctx context.Context, uri string) {
			c.followForever(fctx, uri, out)
		},
	}
	return set.run(ctx)
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
	return certFrom(x, uri, index)
}

// certFrom reduces a parsed certificate to the fields the monitor needs, and
// reports whether it named anything worth keeping. Both readers end here: what
// differs between RFC 6962 and the Static CT API is how the certificate is
// found, not what is taken from it.
func certFrom(x *x509.Certificate, uri string, index int64) (Cert, bool) {
	if x == nil {
		return Cert{}, false
	}
	if x.Subject.CommonName == "" && len(x.DNSNames) == 0 {
		return Cert{}, false
	}
	return Cert{
		CN:        x.Subject.CommonName,
		SANs:      x.DNSNames,
		Issuer:    issuerName(x.Issuer.CommonName, x.Issuer.Organization),
		NotBefore: x.NotBefore.UTC(),
		NotAfter:  x.NotAfter.UTC(),
		SeenAt:    time.Now().UTC(),
		Source:    uri,
		Index:     index,
	}, true
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

// httpClient builds the client used to talk to a log.
func (c *CTLog) httpClient() *http.Client { return logHTTPClient(c.DialContext) }

// logHTTPClient builds a client for talking to a log, honouring dial.
//
// The dialer is the point: left to the system resolver, a run probing hard
// enough to saturate DNS starves its own source of certificates, which fails
// as "server misbehaving" and stops the feed entirely.
func logHTTPClient(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	hc := &http.Client{Timeout: 60 * time.Second}
	if dial != nil {
		hc.Transport = &http.Transport{
			DialContext:         dial,
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 2,
		}
	}
	return hc
}

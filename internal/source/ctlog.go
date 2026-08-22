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
	Log         *slog.Logger
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

// DiscoverLogs returns the URIs of the logs in Google's v3 log list that are
// usable now: approved for Chrome, and accepting certificates that expire
// today. Those are the logs where new certificates actually land.
func DiscoverLogs(ctx context.Context, hc *http.Client, listURL string) ([]string, error) {
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

	now := time.Now()
	usable := ll.SelectByStatus([]loglist3.LogStatus{loglist3.UsableLogStatus})
	var uris []string
	for _, op := range usable.Operators {
		for _, lg := range op.Logs {
			if ti := lg.TemporalInterval; ti != nil {
				if now.Before(ti.StartInclusive) || !now.Before(ti.EndExclusive) {
					continue
				}
			}
			uris = append(uris, lg.URL)
		}
	}
	if len(uris) == 0 {
		return nil, fmt.Errorf("log list %s contained no usable current logs", listURL)
	}
	return uris, nil
}

// Run follows every configured log until ctx is cancelled. A log that keeps
// failing is retried with backoff rather than taking the others down with it.
func (c *CTLog) Run(ctx context.Context, out chan<- Cert) error {
	if c.Positions == nil {
		return fmt.Errorf("ctlog: Positions is required")
	}
	if len(c.URIs) == 0 {
		return fmt.Errorf("ctlog: no log URIs configured")
	}

	var wg sync.WaitGroup
	for _, uri := range c.URIs {
		wg.Add(1)
		go func(uri string) {
			defer wg.Done()
			c.followForever(ctx, uri, out)
		}(uri)
	}
	wg.Wait()
	return ctx.Err()
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

	var cert Cert
	switch {
	case entry.X509Cert != nil:
		x := entry.X509Cert
		cert = Cert{
			CN:        x.Subject.CommonName,
			SANs:      x.DNSNames,
			Issuer:    issuerName(x.Issuer.CommonName, x.Issuer.Organization),
			NotBefore: x.NotBefore.UTC(),
			NotAfter:  x.NotAfter.UTC(),
		}
	case entry.Precert != nil && entry.Precert.TBSCertificate != nil:
		x := entry.Precert.TBSCertificate
		cert = Cert{
			CN:        x.Subject.CommonName,
			SANs:      x.DNSNames,
			Issuer:    issuerName(x.Issuer.CommonName, x.Issuer.Organization),
			NotBefore: x.NotBefore.UTC(),
			NotAfter:  x.NotAfter.UTC(),
		}
	default:
		return Cert{}, false
	}
	if cert.CN == "" && len(cert.SANs) == 0 {
		return Cert{}, false
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

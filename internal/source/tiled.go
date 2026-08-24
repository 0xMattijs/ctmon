package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"golang.org/x/time/rate"
)

// TiledLog reads Static CT API logs: a signed checkpoint saying how big the
// tree is, and the entries themselves served as fixed-size tiles off static
// storage. It is the second half of what Google's v3 list carries — the logs
// CTLog cannot read, because they answer no RFC 6962 endpoint at all.
//
// It is a sibling of CTLog rather than a mode of it. The two share the things
// that are about following a log — where each one has been read to, when to
// reconsider the set, how hard to push — and share nothing about how entries
// are fetched, because there is nothing to share: one asks a JSON API for a
// range and the other downloads a file.
type TiledLog struct {
	// Logs are the logs to follow, each a monitoring prefix, the key it signs
	// with, and the origin its checkpoint names itself by. A trailing slash on
	// the prefix is optional and not stored: positions are keyed by URI, so
	// the key has to mean the same thing however the list spelled it that day.
	// A log with no key is followed and not checked; see verifierFor.
	Logs []Log
	// Positions stores per-log read positions. Required.
	//
	// A tiled log's position is a leaf index, exactly as it is for an RFC 6962
	// log, so the two kinds share one keyspace without colliding: the URI they
	// are keyed by differs.
	Positions Positions
	// FromStart reads each log from index 0 the first time it is seen. The
	// default starts at the log's current tree size, which is what you want
	// for discovering newly issued certificates.
	FromStart bool
	// MaxLag skips a log ahead to its checkpoint once it is more than this
	// many entries behind. Zero never skips.
	MaxLag uint64
	// PollInterval is how long to wait after catching up with a log's
	// checkpoint before fetching a new one (default 30s).
	PollInterval time.Duration
	// RequestsPerSecond caps requests per log (default 4). A request here is a
	// whole tile — up to 256 entries and a few hundred kilobytes — so the same
	// number buys considerably more entries than it does over RFC 6962.
	RequestsPerSecond float64
	UserAgent         string
	// DialContext overrides how connections to the logs are made, so the feed
	// can share the run's own resolver. See logHTTPClient.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// Discover re-reads the set of tiled logs worth following. Set it and Run
	// reconsiders the set every RefreshInterval; leave it nil and Logs is the
	// set for the life of the run.
	Discover func(ctx context.Context) ([]Log, error)
	// RefreshInterval is how often Discover is called (default 24h).
	RefreshInterval time.Duration
	Log             *slog.Logger
}

// Name implements Source.
func (t *TiledLog) Name() string { return "tiled" }

// maxTileBytes bounds one tile read. A full data tile of 256 entries with
// full chains runs to a few hundred kilobytes; this is an order of magnitude
// above that, and there only so a redirect to something enormous cannot be
// read into memory.
const maxTileBytes = 32 << 20

// errTileMissing is a tile the log does not have. It is worth a name of its
// own because it is the one HTTP failure here that is usually not a failure:
// a tile the checkpoint has already counted may be a moment away from the
// edge serving it, and a partial tile stops existing entirely the moment the
// tree grows past it.
var errTileMissing = errors.New("not published")

// missesBeforeWarning is how many tiles a log may fail to publish in a row
// before the wait is worth saying out loud. Below it the wait is the protocol
// working; above it the log is stuck, and the run has gone quiet for a reason
// nothing else would report.
const missesBeforeWarning = 5

// throttled is a log asking to be left alone for a while, which is not the
// same as a log that has failed and is worth telling apart from one.
//
// Tiles are served off ordinary object storage and several operators put an
// ordinary rate limit in front of it — Geomys answers 429 with a Retry-After
// naming the instant the bucket refills. Doing as asked keeps the follower
// alive and reads the log again the moment it is welcome to, where treating
// the refusal as a failure would put the whole follower into a backoff that
// has no idea what it is waiting for and doubles past it.
type throttled struct {
	wait time.Duration
	// reason is whatever the log put in the 429 body, which is the one place
	// a refusal says anything beyond how long. Geomys answers a User-Agent
	// naming no contact with "Please add an email address to your
	// User-Agent." — a refusal no amount of waiting clears, and one that
	// reads as an ordinary rate limit with the body thrown away.
	reason string
}

func (t *throttled) Error() string {
	if t.reason == "" {
		return fmt.Sprintf("rate limited, asked to wait %v", t.wait.Round(time.Second))
	}
	return fmt.Sprintf("rate limited, asked to wait %v: %s", t.wait.Round(time.Second), t.reason)
}

// maxThrottleReasonBytes caps how much of a 429 body is kept. The body is a
// sentence meant for a human, not a payload; a log that answers with a page
// gets the first line of it and nothing more.
const maxThrottleReasonBytes = 256

// throttleReason reads a 429 body into one line fit for a log field. Anything
// unreadable leaves the reason empty, because a refusal that cannot be
// explained is still a refusal and must not become a failure.
func throttleReason(r io.Reader) string {
	body, err := io.ReadAll(io.LimitReader(r, maxThrottleReasonBytes))
	if err != nil {
		return ""
	}
	return strings.Join(strings.Fields(string(body)), " ")
}

// maxThrottleWait caps how long a log can send this feed away for. A log is
// entitled to refuse, and not entitled to park a follower for an afternoon: at
// the cap the wait becomes an ordinary poll cycle again, which re-reads the
// checkpoint and finds out whether the refusal still stands.
const maxThrottleWait = 10 * time.Minute

// Run follows every configured log until ctx is cancelled. A log that keeps
// failing is retried with backoff rather than taking the others down with it.
// The set is reconsidered on a timer when Discover is set; see followSet.
func (t *TiledLog) Run(ctx context.Context, out chan<- Cert) error {
	if t.Positions == nil {
		return fmt.Errorf("tiled: Positions is required")
	}
	if len(t.Logs) == 0 {
		return fmt.Errorf("tiled: no log URIs configured")
	}
	discover := t.Discover
	if discover != nil {
		discover = func(ctx context.Context) ([]Log, error) {
			logs, err := t.Discover(ctx)
			return tiledPrefixes(logs), err
		}
	}
	set := &followSet{
		logs:      tiledPrefixes(t.Logs),
		positions: t.Positions,
		discover:  discover,
		refresh:   t.RefreshInterval,
		kind:      "static ct log",
		log:       t.Log,
		follow: func(fctx context.Context, lg Log) {
			t.followForever(fctx, lg, out)
		},
	}
	return set.run(ctx)
}

// tiledPrefixes trims the trailing slash off each monitoring URL, so that one
// log spelled two ways is one log.
//
// This has to happen at every boundary the URIs come in through, not inside
// the follow loop. followSet compares what the list returned against what it
// is running and looks positions up by the same string, so a normalisation
// that only reached as far as the fetch would have it stop and restart the
// same follower on every refresh, at a position it never wrote.
func tiledPrefixes(logs []Log) []Log {
	out := make([]Log, 0, len(logs))
	for _, lg := range logs {
		lg.URI = strings.TrimRight(lg.URI, "/")
		out = append(out, lg)
	}
	return out
}

// followForever restarts follow after any failure, backing off between tries.
// The backoff counter resets after a run that lasted, so an occasional failure
// on a healthy log costs one short pause rather than a permanently long one.
func (t *TiledLog) followForever(ctx context.Context, lg Log, out chan<- Cert) {
	rt := retry{base: 5 * time.Second, max: 10 * time.Minute}
	for ctx.Err() == nil {
		start := time.Now()
		err := t.follow(ctx, lg, out)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errUntrusted) {
			// Not a bad minute. See errUntrusted: this is the wrong key or a
			// log serving what it did not sign, and neither is waited out.
			t.Log.Error("static ct log signature did not verify; no longer following it",
				"log", lg.URI, "err", err)
			return
		}
		ran := time.Since(start)
		d := rt.after(ran)
		t.Log.Warn("static ct log follow failed", "log", lg.URI, "err", err,
			"ran", ran.Round(time.Second), "retry_in", d)
		if sleep(ctx, d) != nil {
			return
		}
	}
}

// follow reads one log from its stored position to the size its checkpoint
// gives, then keeps pace with it. It returns on the first error so the caller
// can back off.
//
// There is no adaptive batch here, and no room for one. A tile is 256 entries
// because the API says so, and a log too slow to serve one inside the timeout
// cannot be asked for less — the smaller request does not exist. What CTLog
// spends on finding a size the log can manage, this spends on not having to.
func (t *TiledLog) follow(ctx context.Context, lg Log, out chan<- Cert) error {
	uri := lg.URI
	poll := t.pollEvery()
	rps := t.RequestsPerSecond
	if rps <= 0 {
		rps = 4
	}
	limiter := rate.NewLimiter(rate.Limit(rps), 1)
	hc := logHTTPClient(t.DialContext)

	v, err := verifierFor(lg.Key)
	if err != nil {
		return err
	}

	pos, ok, err := t.Positions.LogPos(uri)
	if err != nil {
		return fmt.Errorf("read position: %w", err)
	}

	// misses counts tiles the checkpoint promised and the log did not have,
	// in a row.
	//
	// One is ordinary and means the log moved: a partial tile stops existing
	// the moment the tree grows past it, and a tile that has just been
	// published takes a moment to reach every edge of the storage serving it.
	// The answer to one is a fresh checkpoint, immediately.
	//
	// A run of them is not a race any more, and the answer is to wait: a log
	// that serves no partial tiles at all, or that is slow to publish, is
	// still read correctly a tile at a time as each one lands. Backing off the
	// whole follower instead would be the same wait with the entries arriving
	// in bursts, and one that hides the difference between a log that is
	// behind and a log that is broken.
	misses := 0

	for ctx.Err() == nil {
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
		cp, err := t.checkpoint(ctx, hc, uri)
		if sentAway, ok := askedToWait(err); ok {
			t.Log.Info("static ct log rate limited; waiting", "log", uri,
				"wait", sentAway.wait, "reason", sentAway.reason)
			if err := sleep(ctx, sentAway.wait); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if err := verifyCheckpoint(v, cp, lg.Origin, lg.Key); err != nil {
			return fmt.Errorf("checkpoint: %w", err)
		}

		firstSight := !ok
		if !ok {
			// First sight of this log: start at the tip unless asked to
			// backfill, so we report new certificates rather than history.
			pos = 0
			if !t.FromStart {
				pos = cp.Size
			}
			ok = true
			if err := t.Positions.SetLogPos(uri, pos); err != nil {
				return fmt.Errorf("save position: %w", err)
			}
			t.Log.Info("following static ct log", "log", uri, "origin", cp.Origin,
				"start", pos, "tree_size", cp.Size)
		}
		// A log that outruns us by more than MaxLag is serving history we will
		// never catch up on, and almost every certificate in that backlog
		// reached the store through another log hours ago. Skipping is
		// deliberate data loss, so it happens only when asked for, and never
		// on the first sight of a log, where --from-start means the gap is the
		// point.
		if t.MaxLag > 0 && !firstSight && cp.Size > pos && cp.Size-pos > t.MaxLag {
			skipped := cp.Size - pos
			pos = cp.Size
			if err := t.Positions.SetLogPos(uri, pos); err != nil {
				return fmt.Errorf("save position: %w", err)
			}
			t.Log.Warn("static ct log too far behind; skipped to tip",
				"log", uri, "skipped", skipped, "tree_size", cp.Size)
		}
		if pos > cp.Size {
			// The log shrank, which means it was reset or replaced.
			t.Log.Warn("static ct log tree shrank; resetting position",
				"log", uri, "pos", pos, "tree_size", cp.Size)
			pos = cp.Size
			if err := t.Positions.SetLogPos(uri, pos); err != nil {
				return fmt.Errorf("save position: %w", err)
			}
		}

		stopped := caughtUp
		for pos < cp.Size && ctx.Err() == nil {
			n := pos / tileWidth
			base := n * tileWidth
			width := tileWidth
			if cp.Size-base < tileWidth {
				width = int(cp.Size - base)
			}
			if err := limiter.Wait(ctx); err != nil {
				return err
			}
			path := dataTilePath(n, width)
			t.Log.Debug("static ct tile", "log", uri, "tile", path,
				"position", pos, "tree_size", cp.Size)
			body, err := t.fetchTile(ctx, hc, uri, path)
			if sentAway, ok := askedToWait(err); ok {
				t.Log.Info("static ct log rate limited; waiting",
					"log", uri, "tile", path, "wait", sentAway.wait,
					"reason", sentAway.reason)
				if err := sleep(ctx, sentAway.wait); err != nil {
					return err
				}
				stopped = wasThrottled
				break
			}
			if errors.Is(err, errTileMissing) {
				misses++
				stopped = tileMissing
				if misses == missesBeforeWarning {
					t.Log.Warn("static ct log has not published the tile its checkpoint promised",
						"log", uri, "tile", path, "position", pos, "tree_size", cp.Size)
				}
				break
			}
			if err != nil {
				return fmt.Errorf("tile %s: %w", path, err)
			}
			misses = 0
			entries, err := parseDataTile(body)
			if err != nil {
				return fmt.Errorf("tile %s: %w", path, err)
			}
			// A tile that holds more than was asked for is a log serving the
			// full tile for a partial request, which is allowed to happen and
			// must not be taken at face value: reading it whole would put pos
			// past the size the checkpoint gave, and the next pass would read
			// that as the tree having shrunk and rewind.
			if len(entries) > width {
				entries = entries[:width]
			}
			// A tile is only ever read forwards, so one that holds fewer
			// entries than the position already reached leaves nowhere to go:
			// advancing would skip the gap and staying would fetch it again.
			// It means the log rewrote a tile this run had already read, which
			// is a broken log rather than a slow one.
			off := int(pos - base)
			if off >= len(entries) {
				return fmt.Errorf("tile %s: %d entries, want more than %d", path, len(entries), off)
			}
			for i := off; i < len(entries); i++ {
				cert, ok := t.parseEntry(uri, int64(base)+int64(i), entries[i])
				if !ok {
					continue
				}
				if err := send(ctx, out, cert); err != nil {
					return err
				}
			}
			// Tiles may hold fewer entries than the checkpoint implied, so
			// trust the count.
			pos = base + uint64(len(entries))
			if err := t.Positions.SetLogPos(uri, pos); err != nil {
				return fmt.Errorf("save position: %w", err)
			}
		}

		switch {
		case stopped == caughtUp:
			// Caught up, so whatever was missing has been served. Leaving the
			// count standing would spend the next genuine race's fast re-check
			// on a miss that is long over.
			misses = 0
		case stopped == wasThrottled:
			// Already waited exactly as long as the log asked to be left for.
			continue
		case stopped == tileMissing && misses == 1:
			// One missing tile is the log having moved; go and read how far.
			continue
		}
		if err := sleep(ctx, poll); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// stopReason is why the inner loop stopped, where that changes what happens
// next: everything else falls through to an ordinary poll.
type stopReason int

const (
	caughtUp     stopReason = iota // reached the size the checkpoint gave
	tileMissing                    // the log has not published a tile it counted
	wasThrottled                   // the log asked to be left alone, and was
)

// askedToWait reports whether err is a log asking to be left alone, and hands
// back what it said: how long, and why if it gave a reason.
func askedToWait(err error) (*throttled, bool) {
	var t *throttled
	if errors.As(err, &t) {
		return t, true
	}
	return nil, false
}

// pollEvery is how long to wait after catching up with a log.
func (t *TiledLog) pollEvery() time.Duration {
	if t.PollInterval <= 0 {
		return 30 * time.Second
	}
	return t.PollInterval
}

// checkpoint fetches and parses the log's head.
func (t *TiledLog) checkpoint(ctx context.Context, hc *http.Client, uri string) (checkpoint, error) {
	body, err := t.get(ctx, hc, uri+"/checkpoint")
	if err != nil {
		return checkpoint{}, fmt.Errorf("checkpoint: %w", err)
	}
	return parseCheckpoint(body)
}

// fetchTile downloads one tile, relative to the log's monitoring prefix.
func (t *TiledLog) fetchTile(ctx context.Context, hc *http.Client, uri, path string) ([]byte, error) {
	return t.get(ctx, hc, uri+"/"+path)
}

// get reads one static resource from a log.
//
// Two statuses are given meanings rather than being reported as failures. A
// 404 or 403 is errTileMissing, because both mean the same thing from object
// storage: the caller asked for something that is not there. Google serves
// tiles out of a bucket that answers 403 for a missing object, so treating
// only 404 as absence would turn every lost race against a Google log into a
// backoff. A 429 is throttled, carrying however long the log asked for.
func (t *TiledLog) get(ctx context.Context, hc *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if t.UserAgent != "" {
		req.Header.Set("User-Agent", t.UserAgent)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusForbidden:
		return nil, fmt.Errorf("%s: %w", resp.Status, errTileMissing)
	case http.StatusTooManyRequests:
		return nil, &throttled{
			wait:   retryAfter(resp.Header.Get("Retry-After"), t.pollEvery()),
			reason: throttleReason(resp.Body),
		}
	default:
		return nil, fmt.Errorf("%s", resp.Status)
	}
	// One byte past the cap, so a body that reaches it is reported rather
	// than quietly truncated. A truncated tile parses as a framing error,
	// which would send whoever reads that line looking at the log's encoder
	// instead of at this limit.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxTileBytes {
		return nil, fmt.Errorf("body is larger than the %d byte limit", maxTileBytes)
	}
	return body, nil
}

// parseEntry pulls the names out of one tile entry. Entries that fail to parse
// are skipped: CT logs carry plenty of certificates that Go's parser rejects,
// and one bad entry must not stall the feed.
//
// Non-fatal parse errors are kept, matching what the RFC 6962 path does
// through ct-go: the ct-go x509 parser reports the malformations it tolerated
// as an error alongside a certificate that is perfectly good enough to read
// names from, and a great many real certificates arrive that way.
func (t *TiledLog) parseEntry(uri string, index int64, e tileEntry) (Cert, bool) {
	var (
		x   *x509.Certificate
		err error
	)
	if e.precert {
		x, err = x509.ParseTBSCertificate(e.der)
	} else {
		x, err = x509.ParseCertificate(e.der)
	}
	if err != nil && x509.IsFatal(err) {
		t.Log.Debug("static ct entry unparsable", "log", uri, "index", index, "err", err)
		return Cert{}, false
	}
	return certFrom(x, uri, index)
}

// retryAfter reads a Retry-After header, which RFC 9110 allows to be either a
// number of seconds or an HTTP date. Anything else, including an absent header
// or a date already in the past, falls back to fallback.
//
// The result is clamped to maxThrottleWait, and never to less than a second:
// a log that answered 429 and then asked for no wait at all would have this
// spinning against it at the rate limiter's pace.
func retryAfter(header string, fallback time.Duration) time.Duration {
	d := fallback
	if secs, err := strconv.Atoi(strings.TrimSpace(header)); err == nil {
		d = time.Duration(secs) * time.Second
	} else if at, err := http.ParseTime(header); err == nil {
		d = time.Until(at)
	}
	return min(max(d, time.Second), maxThrottleWait)
}

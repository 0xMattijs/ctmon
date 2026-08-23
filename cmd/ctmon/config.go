package main

import (
	"flag"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/mvo/ct/internal/pipeline"
	"github.com/mvo/ct/internal/probe"
	"github.com/mvo/ct/internal/source"
	"github.com/mvo/ct/internal/store"
)

// runConfig is everything "ctmon run" reads off the command line.
//
// The flags are grouped the way the program is: a feed, a set of filters, a
// prober, the pipeline joining them, and what all of it prints. Grouping is
// not decoration — it is what lets each part be built from the piece of the
// configuration it needs instead of from a dozen loose arguments.
type runConfig struct {
	dbPath string
	// userAgent goes out on probes and on CT requests alike, so it belongs to
	// neither group.
	userAgent    string
	compactEvery time.Duration
	snapshot     string

	feed   feedConfig
	filter filterConfig
	prober proberConfig
	pipe   pipeConfig
	output outputConfig
}

// feedConfig selects and paces the certificate sources.
type feedConfig struct {
	sources   string
	certURL   string
	logURIs   string
	listURL   string
	fromStart bool
	batch     int
	maxLag    uint64
	poll      time.Duration
	rps       float64
}

// filterConfig decides which discovered hostnames are worth keeping.
type filterConfig struct {
	skipSuffix  string
	skipFile    string
	useDefaults bool
	parentCap   int
	parentWin   time.Duration
	recentHosts int
	maxDepth    int
	useSANs     bool
	maxSANs     int
}

// proberConfig governs the HTTPS fetch and the resolution in front of it.
type proberConfig struct {
	disabled     bool
	rps          float64
	perIPRPS     float64
	timeout      time.Duration
	dialTimeout  time.Duration
	tlsTimeout   time.Duration
	resolvers    string
	resolveTO    time.Duration
	dnsTTL       time.Duration
	dnsNegTTL    time.Duration
	resolveConc  int
	maxBody      int64
	verifyTLS    bool
	allowPrivate bool
}

// pipeConfig sizes the pipeline and its backfill sweep.
type pipeConfig struct {
	workers       int
	writers       int
	backfill      time.Duration
	backfillBatch int
	backfillLease time.Duration
	reprobe       time.Duration
}

// outputConfig is what the run says about itself while it runs.
type outputConfig struct {
	report  time.Duration
	status  bool
	domains bool
	verbose bool
}

// bind registers every "run" flag against the fields it fills. Flag names are
// the program's interface, so they are spelled out here in full rather than
// generated.
func (c *runConfig) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.dbPath, "db", "ct.db", "path to the bbolt database")
	fs.StringVar(&c.userAgent, "user-agent", "ctmon/1.0 (+domain discovery)", "User-Agent for probes and CT requests")
	fs.DurationVar(&c.compactEvery, "compact-every", 24*time.Hour, "rewrite the database into full pages this often (0 disables)")
	fs.StringVar(&c.snapshot, "snapshot", "", "where SIGUSR1 writes a readable copy of the database (default: <db>.snap)")

	f := &c.feed
	fs.StringVar(&f.sources, "source", "both", "certificate feed: certstream, ctlog, or both")
	fs.StringVar(&f.certURL, "certstream-url", source.DefaultCertstreamURL, "certstream websocket URL")
	fs.StringVar(&f.logURIs, "logs", "", "comma-separated CT log URLs (default: discover usable logs)")
	fs.StringVar(&f.listURL, "log-list-url", "", "CT log list URL (default: Google's v3 list)")
	fs.BoolVar(&f.fromStart, "from-start", false, "read each new log from index 0 instead of its current tip")
	fs.IntVar(&f.batch, "batch", 256, "entries per get-entries request (a ceiling: a log that times out gets asked for less)")
	fs.Uint64Var(&f.maxLag, "max-lag", 0, "skip a log to its tree head when it falls this many entries behind (0 = never skip)")
	fs.DurationVar(&f.poll, "poll", 30*time.Second, "how long to wait after catching up with a log")
	fs.Float64Var(&f.rps, "log-rps", 4, "get-entries requests per second, per log")

	l := &c.filter
	fs.StringVar(&l.skipSuffix, "skip-suffix", "", "extra parent domains to drop, comma-separated, e.g. workers.dev,pages.dev")
	fs.StringVar(&l.skipFile, "skip-suffix-file", "", "file of extra parent domains to drop, one per line (# comments allowed)")
	fs.BoolVar(&l.useDefaults, "default-skip", true, "apply the built-in hosting-platform blocklist")
	fs.IntVar(&l.parentCap, "parent-cap", pipeline.DefaultParentCap, "maximum new hosts accepted per registrable domain per window (0 = no cap)")
	fs.DurationVar(&l.parentWin, "parent-window", pipeline.DefaultParentWindow, "window for --parent-cap")
	fs.IntVar(&l.recentHosts, "recent-hosts", pipeline.DefaultRecentHosts, "hostnames the in-memory duplicate filter remembers (0 = default)")
	fs.IntVar(&l.maxDepth, "max-depth", pipeline.DefaultMaxDepth, "drop hosts nested deeper than this below their registrable domain (0 = no limit)")
	fs.BoolVar(&l.useSANs, "sans", true, "read hostnames from subject alternative names, not just the CN")
	fs.IntVar(&l.maxSANs, "max-sans", 0, "maximum SANs to read from one certificate (0 = all)")

	p := &c.prober
	fs.BoolVar(&p.disabled, "no-probe", false, "record domains without fetching them")
	fs.Float64Var(&p.rps, "probe-rps", 100, "ceiling on HTTPS probes per second across all workers, which is what bounds NAT state on the way out (0 = no limit)")
	fs.Float64Var(&p.perIPRPS, "probe-rps-per-ip", 32, "HTTPS probes per second to one destination address (0 = no per-address limit)")
	fs.DurationVar(&p.timeout, "probe-timeout", 6*time.Second, "per-probe timeout, end to end")
	fs.DurationVar(&p.dialTimeout, "dial-timeout", 2*time.Second, "how long to wait for the TCP connect")
	fs.DurationVar(&p.tlsTimeout, "tls-timeout", 3*time.Second, "how long to wait for the TLS handshake")
	fs.StringVar(&p.resolvers, "resolvers", "", "nameservers to probe with, comma-separated host:port (default: the system's)")
	fs.DurationVar(&p.resolveTO, "resolve-timeout", 2*time.Second, "how long to wait for a DNS answer")
	fs.DurationVar(&p.dnsTTL, "dns-ttl", 5*time.Minute, "how long to cache a name that resolved")
	fs.DurationVar(&p.dnsNegTTL, "dns-negative-ttl", 15*time.Minute, "how long to cache a name that did not resolve")
	fs.IntVar(&p.resolveConc, "resolve-concurrency", 64, "how many DNS lookups may run at once")
	fs.Int64Var(&p.maxBody, "max-body", 2<<20, "bytes of body to read and hash")
	fs.BoolVar(&p.verifyTLS, "verify-tls", false, "verify TLS certificates when probing")
	fs.BoolVar(&p.allowPrivate, "allow-private", false, "probe hosts that resolve to loopback, RFC 1918, or other non-public addresses")

	n := &c.pipe
	fs.IntVar(&n.workers, "workers", pipeline.DefaultWorkers, "concurrent HTTPS probes")
	fs.IntVar(&n.writers, "writers", pipeline.DefaultWriters, "concurrent store writers")
	fs.DurationVar(&n.backfill, "backfill", 10*time.Second, "how often to take hosts off the pending queue (0 disables)")
	fs.IntVar(&n.backfillBatch, "backfill-batch", pipeline.DefaultBackfillBatch, "maximum hosts leased per sweep")
	fs.DurationVar(&n.backfillLease, "backfill-lease", pipeline.DefaultBackfillLease, "how long a host handed to a prober stays off the pending queue; must outlast a whole --backfill-batch")
	fs.DurationVar(&n.reprobe, "reprobe", 0, "re-probe a known host after this long (0 disables)")

	o := &c.output
	fs.DurationVar(&o.report, "report", time.Minute, "how often to log counters (0 disables)")
	fs.BoolVar(&o.status, "status", true, "on a terminal, redraw the counters in place instead of logging a line per report interval")
	fs.BoolVar(&o.domains, "domains", false, "log every new domain, one line each")
	fs.BoolVar(&o.verbose, "v", false, "debug logging")
}

// snapshotPath is where a SIGUSR1 snapshot is written, defaulting to a file
// beside the database.
func (c *runConfig) snapshotPath() string {
	if c.snapshot != "" {
		return c.snapshot
	}
	return c.dbPath + ".snap"
}

// logger builds the run's logger, and the status line it writes through when
// there is one. The line is nil unless the counters are being redrawn in
// place, and the caller has to stop it at the end of the run.
func (c *runConfig) logger() (*slog.Logger, *statusLine) {
	level := slog.LevelInfo
	if c.output.verbose {
		level = slog.LevelDebug
	}
	// The live counter line and debug logging fight over the terminal, so
	// -v keeps the plain scrolling output.
	var line *statusLine
	if c.output.status && !c.output.verbose && c.output.report > 0 {
		line = newStatusLine(os.Stderr)
	}
	var out io.Writer = os.Stderr
	if line != nil {
		out = line
	}
	return slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: level})), line
}

// newProber builds the prober from the probe and resolver flags.
func (c *runConfig) newProber() *probe.Prober {
	p := c.prober
	return probe.New(probe.Options{
		Timeout:           p.timeout,
		DialTimeout:       p.dialTimeout,
		TLSTimeout:        p.tlsTimeout,
		MaxBody:           p.maxBody,
		RequestsPerSecond: p.rps,
		PerIPRPS:          p.perIPRPS,
		// Zero means "use the default" for every other option here, so
		// turning the per-address budget off has to say so separately.
		NoPerIPLimit:   p.perIPRPS == 0,
		Resolvers:      splitList(p.resolvers),
		ResolveTimeout: p.resolveTO,
		MaxLookups:     p.resolveConc,
		DNSTTL:         p.dnsTTL,
		DNSNegativeTTL: p.dnsNegTTL,
		VerifyTLS:      p.verifyTLS,
		AllowPrivate:   p.allowPrivate,
		UserAgent:      c.userAgent,
	})
}

// newPipeline assembles the pipeline from the filter, probe, and sizing flags.
func (c *runConfig) newPipeline(db *store.Store, prober *probe.Prober, log *slog.Logger, skip pipeline.SuffixSet) *pipeline.Pipeline {
	return &pipeline.Pipeline{
		Store:         db,
		Prober:        prober,
		Log:           log,
		Workers:       c.pipe.workers,
		Writers:       c.pipe.writers,
		Skip:          skip,
		ParentCap:     c.filter.parentCap,
		ParentWindow:  c.filter.parentWin,
		MaxDepth:      c.filter.maxDepth,
		IgnoreSANs:    !c.filter.useSANs,
		MaxSANs:       c.filter.maxSANs,
		Reprobe:       c.pipe.reprobe,
		Backfill:      c.pipe.backfill,
		BackfillBatch: c.pipe.backfillBatch,
		BackfillLease: c.pipe.backfillLease,
		NoProbe:       c.prober.disabled,
		LogDomains:    c.output.domains,
		RecentHosts:   c.filter.recentHosts,
	}
}

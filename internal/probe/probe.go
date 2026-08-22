// Package probe fetches https://<host>/ and hashes the body.
package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"golang.org/x/time/rate"
)

// DeferReason says why a probe did not happen.
type DeferReason string

const (
	// DeferAddressBudget: the destination address had already had its share.
	DeferAddressBudget DeferReason = "address_budget"
	// DeferNoAnswer: the resolver did not answer, so there is no address to
	// spend a budget against and nothing to record about the host.
	DeferNoAnswer DeferReason = "no_dns_answer"
)

// Result is one HTTPS fetch.
type Result struct {
	Status   int    // HTTP status of the final response
	FinalURL string // URL after redirects
	Size     int64  // bytes hashed, capped at MaxBody
	Hash     string // sha256 of the body, hex; empty when the fetch failed
	Err      error
	// Deferred says the probe never happened. It is not a result about the
	// host: nothing was asked, nothing should be recorded, and the host
	// should be tried again. DeferReason says which kind of not-happening it
	// was, because the two call for different fixes — one is the monitor
	// pacing itself, the other is the resolver failing to answer.
	Deferred    bool
	DeferReason DeferReason
}

// Prober fetches sites politely: bounded concurrency, a global rate limit,
// hard timeouts, and a cap on how much body it will read.
type Prober struct {
	client  *http.Client
	limiter *rate.Limiter // optional overall ceiling; nil when unset
	ips     *ipLimiter
	// lookup resolves a name, or is nil when something else owns resolution:
	// a caller-supplied DialContext resolves for itself, and the per-address
	// budget goes with it.
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// dial is the transport's dialer, kept so callers outside this package
	// can reach the network the same way probes do.
	dial         func(ctx context.Context, network, addr string) (net.Conn, error)
	resolver     *resolver
	allowPrivate bool
	userAgent    string
	maxBody      int64
}

// Options configure a Prober.
type Options struct {
	// Timeout bounds one probe end to end (default 6s).
	//
	// It used to be 10s. On live data the hosts that ran it out were 1,445 of
	// 57,000 failures but the most expensive failure there is, and a site
	// that has sent no headers in a few seconds is not one this monitor needs
	// to keep waiting for.
	Timeout time.Duration
	// TLSTimeout bounds the TLS handshake (default 3s).
	//
	// It is separate from DialTimeout, and larger, because the two are not
	// the same kind of wait. A connect either lands quickly or not at all; a
	// handshake means several round trips to a server that has already
	// answered, so a budget tight enough to be right for the connect turns
	// slow-but-real sites into "TLS handshake timeout" — which was the
	// largest new failure in a run once the resolver stopped being the
	// bottleneck.
	TLSTimeout time.Duration
	// DialTimeout bounds the TCP connect (default 2s).
	//
	// This is the knob that matters for throughput. Hosts that never answer
	// are common in CT and each one holds a worker for the whole of this
	// timeout, so on a measured live run they were 19% of probes but around
	// 40% of all worker time. Timeout does not bound them: it covers the
	// request once a connection exists.
	DialTimeout time.Duration
	// MaxBody caps how many bytes are read and hashed (default 2 MiB).
	// Bodies larger than this hash their first MaxBody bytes.
	MaxBody int64
	// RequestsPerSecond caps outbound probes across all workers (default
	// 100). Zero turns the ceiling off.
	//
	// This is not about politeness to the sites — PerIPRPS is the limit that
	// means anything to them. It is about the network between here and them.
	// Keepalives are off, so every probe is a fresh connection, and every
	// connection holds a translation entry on whatever does NAT for this
	// machine until it times out. The steady-state table size is roughly the
	// probe rate times that timeout: at 100 a second against a typical
	// two-minute timeout, some 12,000 entries. Consumer routers fall over
	// well below that, and when they do it is not the monitor that suffers,
	// it is everything else on the network.
	//
	// Lower it if probing is making the network unhappy. Raise it, or turn it
	// off, when the path out is yours to saturate.
	RequestsPerSecond float64
	// Burst is the overall limiter's burst (default 20).
	Burst int
	// PerIPRPS caps requests to one destination address (default 32), and
	// PerIPBurst is its burst (default 64). A probe over the budget is
	// returned Deferred rather than delayed.
	//
	// The default is not as generous as it looks. Certificate transparency
	// concentrates hard on a few CDN addresses — thousands of unrelated
	// hostnames behind one of them — so a tight per-address budget throttles
	// the monitor without sparing anybody: at 8 a second, seven probes in
	// eight were being put off. What the budget is really for is the small
	// shared host that a burst of its tenants' names would otherwise hit all
	// at once.
	PerIPRPS   float64
	PerIPBurst int
	// MaxIPs bounds the per-address table (default 65536).
	MaxIPs int
	// Resolvers are the nameservers to ask, as host:port. Empty uses the
	// system's, which on a machine running a local forwarder means every
	// lookup queues behind one process; naming real upstreams here is what
	// lets the worker count rise.
	Resolvers []string
	// ResolveTimeout bounds one lookup (default 2s).
	ResolveTimeout time.Duration
	// DNSTTL is how long a good lookup is cached (default 5m), DNSNegativeTTL
	// how long a failed one is (default 15m), and MaxDNSEntries how many are
	// held (default 131072).
	DNSTTL         time.Duration
	DNSNegativeTTL time.Duration
	MaxDNSEntries  int
	// MaxLookups bounds how many lookups run at once (default 64). It is
	// deliberately far below the worker count: the workers wait on sockets,
	// but their lookups usually land on one local forwarder, and a forwarder
	// asked several hundred questions at once answers some of them with
	// failures. Lookups over the bound wait their turn.
	MaxLookups int
	// MaxRedirects is how many redirects to follow (default 3).
	MaxRedirects int
	// VerifyTLS validates certificates. It is off by default: the point is
	// to fingerprint whatever the host serves, and hosts found through CT
	// routinely serve mismatched or expired certificates.
	VerifyTLS bool
	// AllowPrivate permits probes of loopback, RFC 1918, link-local, and the
	// other addresses that are not out on the public internet. It is off by
	// default. Every hostname reaching this package came out of a stranger's
	// certificate, and anyone who can have one issued for a name that resolves
	// to 127.0.0.1 could otherwise point the monitor at services on the
	// machine running it and read the status, size, and body hash back out of
	// the store.
	AllowPrivate bool
	UserAgent    string
	// DialContext overrides how connections are made. Leave it nil for
	// normal use; it exists so tests can point every host at one server.
	// A dialer supplied here brings its own policy: AllowPrivate applies to
	// the built-in dialer, which is the only one that sees resolved
	// addresses before connecting. Supplying one also turns off the lookup
	// step and the per-address budget that depends on it, unless Lookup says
	// otherwise.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// Lookup overrides name resolution. Leave it nil for normal use; it
	// exists so tests can resolve without a nameserver.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
}

// New builds a Prober. The returned Prober is safe for concurrent use.
func New(opts Options) *Prober {
	if opts.Timeout <= 0 {
		opts.Timeout = 6 * time.Second
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 2 * time.Second
	}
	if opts.TLSTimeout <= 0 {
		opts.TLSTimeout = 3 * time.Second
	}
	if opts.MaxBody <= 0 {
		opts.MaxBody = 2 << 20
	}
	if opts.RequestsPerSecond < 0 {
		opts.RequestsPerSecond = 0
	}
	if opts.Burst <= 0 {
		opts.Burst = 20
	}
	if opts.PerIPRPS <= 0 {
		opts.PerIPRPS = 32
	}
	if opts.PerIPBurst <= 0 {
		opts.PerIPBurst = 64
	}
	if opts.MaxIPs <= 0 {
		opts.MaxIPs = 1 << 16
	}
	if opts.ResolveTimeout <= 0 {
		opts.ResolveTimeout = 2 * time.Second
	}
	if opts.DNSTTL <= 0 {
		opts.DNSTTL = 5 * time.Minute
	}
	if opts.DNSNegativeTTL <= 0 {
		opts.DNSNegativeTTL = 15 * time.Minute
	}
	if opts.MaxDNSEntries <= 0 {
		opts.MaxDNSEntries = 1 << 17
	}
	if opts.MaxLookups <= 0 {
		opts.MaxLookups = 64
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = 3
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "ctmon/1.0"
	}

	base := opts.DialContext
	if base == nil {
		d := &net.Dialer{
			Timeout:   opts.DialTimeout,
			KeepAlive: 15 * time.Second,
		}
		if !opts.AllowPrivate {
			d.Control = refusePrivate
		}
		base = d.DialContext
	}
	p := &Prober{
		ips:          newIPLimiter(opts.PerIPRPS, opts.PerIPBurst, opts.MaxIPs),
		resolver:     newResolver(opts.Resolvers, opts.ResolveTimeout, opts.DNSTTL, opts.DNSNegativeTTL, opts.MaxDNSEntries, opts.MaxLookups),
		allowPrivate: opts.AllowPrivate,
		userAgent:    opts.UserAgent,
		maxBody:      opts.MaxBody,
	}
	switch {
	case opts.Lookup != nil:
		p.lookup = opts.Lookup
	case opts.DialContext == nil:
		p.lookup = p.resolver.lookup
	}
	if opts.RequestsPerSecond > 0 {
		p.limiter = rate.NewLimiter(rate.Limit(opts.RequestsPerSecond), opts.Burst)
	}
	// A supplied DialContext brings its own policy, resolution included, so
	// leave it alone; the cache only fronts the built-in dialer.
	dial := base
	if p.lookup != nil {
		dial = p.dialer(base)
	}
	// Keepalives are off on purpose. A probe makes one request per host and
	// the hosts almost never repeat, so a pool would only hold thousands of
	// idle sockets open to sites we are done with. That also means there is no
	// connection to hand back, so nothing here drains a body it has finished
	// with: the transport closes the socket either way.
	tr := &http.Transport{
		DialContext:           dial,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: !opts.VerifyTLS},
		TLSHandshakeTimeout:   opts.TLSTimeout,
		ResponseHeaderTimeout: opts.Timeout,
		DisableKeepAlives:     true,
	}
	p.dial = dial
	p.client = &http.Client{
		Transport: tr,
		Timeout:   opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= opts.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return p
}

// Probe fetches https://host/ and returns the body hash. A failed fetch is
// reported in Result.Err, not as an error return: an unreachable host is a
// normal outcome worth recording.
func (p *Prober) Probe(ctx context.Context, host string) Result {
	if p.limiter != nil {
		if err := p.limiter.Wait(ctx); err != nil {
			return Result{Err: err}
		}
	}
	if res, ok := p.reserve(ctx, host); !ok {
		return res
	}

	url := "https://" + host + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{Err: err}
	}
	req.Header.Set("User-Agent", p.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := p.client.Do(req)
	if err != nil {
		// Do returns a *url.Error, which already reads
		// `Get "https://host/": <cause>`. Naming the URL again here only
		// printed it twice. When a redirect failed, the URL it carries is
		// the one that failed, which is worth more than the one we asked
		// for, so pass it through rather than restating either.
		return Result{Err: err}
	}
	defer resp.Body.Close()

	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(resp.Body, p.maxBody))
	res := Result{
		Status:   resp.StatusCode,
		FinalURL: resp.Request.URL.String(),
		Size:     n,
		Hash:     hex.EncodeToString(h.Sum(nil)),
	}
	if err != nil {
		// Keep the partial hash out of the record: it is not reproducible.
		return Result{Status: res.Status, FinalURL: res.FinalURL, Err: fmt.Errorf("read body: %w", err)}
	}
	return res
}

// reserve resolves host and claims a slot in its address's budget. It reports
// whether the fetch may go ahead; when it may not, the Result it returns is
// the one to record — or, when Deferred is set, the one to record nothing for.
//
// Doing the lookup here rather than leaving it to the HTTP client is what
// makes a name that does not exist cheap. It costs a DNS round trip, usually
// none at all, against the full dial timeout it used to hold a worker for.
func (p *Prober) reserve(ctx context.Context, host string) (Result, bool) {
	if p.lookup == nil {
		return Result{}, true
	}
	addrs, err := p.lookup(ctx, host)
	if err != nil {
		// A failed lookup is put off only while the resolver is failing
		// generally. Once it is answering again, a name that still will not
		// resolve is a fact about the name — record it, or the host comes
		// back on every sweep for as long as the database exists.
		if transientDNS(err) && !p.resolver.health.reliable() {
			return Result{Deferred: true, DeferReason: DeferNoAnswer}, false
		}
		return Result{Err: err}, false
	}
	addrs = usable(addrs, p.allowPrivate)
	if len(addrs) == 0 {
		return Result{Err: fmt.Errorf("%w: %s resolves only to non-public addresses", ErrPrivateAddress, host)}, false
	}
	// The first address is the one the dialer will try first, so it is the
	// one whose budget this probe spends.
	if !p.ips.allow(addrs[0]) {
		return Result{Deferred: true, DeferReason: DeferAddressBudget}, false
	}
	return Result{}, true
}

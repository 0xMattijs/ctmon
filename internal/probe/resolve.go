package probe

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mvo/ct/internal/bounded"
)

// Resolution happens before the fetch, on purpose.
//
// A quarter of all probes on live data end in "no such host". Left to the HTTP
// client, each of those costs a worker a full dial attempt; asked as a plain
// DNS question first, it costs a few milliseconds and no connection at all.
// The answers are cached, including the failures, because CT delivers the same
// parent domain over and over and the second name under it should not pay for
// the lookup again.
//
// The cache is also what makes a resolved address available to the dialer, so
// a probe resolves a name exactly once no matter how many addresses it tries.

// ErrNoAddress reports a name that resolved to nothing this monitor may fetch.
var ErrNoAddress = errors.New("no usable address")

// transientDNS reports whether a lookup failed for a reason that says nothing
// about the name.
//
// The difference matters more than it looks. "No such host" is an answer: the
// name does not exist, and recording that is the monitor doing its job. A
// timeout or a SERVFAIL is not an answer, it is the resolver declining to give
// one — and on a machine forwarding through systemd-resolved, a few percent of
// lookups decline that way even at low concurrency. Writing those into a
// record would put a claim about the host in the store that nobody ever
// checked, and caching them would spread it to every name under the same
// parent.
func transientDNS(err error) bool {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return !dns.IsNotFound
	}
	// A context that ran out is the caller giving up, not an answer either.
	return err != nil
}

// Health thresholds for deciding whether a failed lookup says something about
// the name or about the resolver.
const (
	// healthWindow is roughly how many recent lookups the judgement rests on.
	healthWindow = 1024
	// healthMinSamples is how much evidence is needed before distrusting the
	// resolver at all. Below it, a failure is taken at face value.
	healthMinSamples = 64
	// healthMinRate is the share of lookups that must come back with an
	// answer — including "no such host", which is an answer — for the
	// resolver to be considered to be working.
	healthMinRate = 0.5
	// healthStale is how long a judgement survives without fresh evidence.
	healthStale = 30 * time.Second
)

// health tracks how often lookups come back with an answer.
//
// It exists to settle one question: when a lookup fails, is that about the
// name or about the resolver? Getting it wrong is expensive in both
// directions. Record a resolver's bad minute and the store fills with claims
// about hosts nobody asked; defer a name whose nameservers are permanently
// dead and it never gets marked probed at all, so it returns on every sweep
// forever. The second mistake is the one that was made: on a live run it left
// 50,137 deferrals against 8,520 actual probes, the backlog spinning through
// names that could never resolve.
type health struct {
	mu               sync.Mutex
	answered, missed float64
	last             time.Time
}

// observe records one lookup outcome. Counts are halved rather than reset when
// the window fills, so the view stays recent without lurching.
func (h *health) observe(answered bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.last = time.Now()
	if answered {
		h.answered++
	} else {
		h.missed++
	}
	if h.answered+h.missed >= healthWindow {
		h.answered /= 2
		h.missed /= 2
	}
}

// reliable reports whether the resolver is answering well enough that a
// failure for one name can be believed about that name. With too little
// evidence it says yes: the default is to trust what the resolver says.
func (h *health) reliable() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	// A verdict only means anything while lookups are still happening. The
	// backfill stops when this says no, and if the feed is quiet too then
	// nothing else is asking — so the counts freeze and the answer stays no
	// forever, long after the resolver came back. Go stale rather than latch:
	// forget what we saw and let the next attempt find out.
	if !h.last.IsZero() && time.Since(h.last) >= healthStale {
		h.answered, h.missed = 0, 0
		return true
	}
	total := h.answered + h.missed
	if total < healthMinSamples {
		return true
	}
	return h.answered/total >= healthMinRate
}

// resolver is a caching DNS front end. It is safe for concurrent use.
type resolver struct {
	net     *net.Resolver
	timeout time.Duration
	ttl     time.Duration // how long a good answer is kept
	negTTL  time.Duration // how long a failure is kept
	// retryTTL is how long a lookup that got no answer is remembered. It is
	// short on purpose: the point is to stop a burst of names under one
	// parent from re-asking a struggling resolver all at once, not to
	// remember a non-answer.
	retryTTL time.Duration
	// slots bounds how many lookups are in flight. Probing concurrency and
	// resolver concurrency are different numbers: hundreds of workers can
	// wait on sockets happily, while the thing answering their DNS is often
	// one local forwarder that starts returning failures rather than answers
	// when too many questions arrive at once. Queueing here turns that into
	// waiting, which costs a moment; the alternative is a timeout recorded
	// against a host that was never asked about.
	slots chan struct{}

	health health

	entries *bounded.Map[string, *answer]
}

// answer is one cached lookup. A failed lookup is cached too: a name that does
// not exist will not exist a second later either.
type answer struct {
	addrs   []netip.Addr
	err     error
	expires time.Time
}

// newResolver builds a caching resolver. servers, when given, are the
// nameservers to ask, as host:port; empty means the system's own, read from
// resolv.conf by Go's resolver rather than by libc.
func newResolver(servers []string, timeout, ttl, negTTL time.Duration, max, inFlight int) *resolver {
	r := &net.Resolver{PreferGo: true}
	if len(servers) > 0 {
		// Spread the queries over the configured servers. One local
		// forwarder answering every lookup is the first thing to fall over
		// when the worker count goes up.
		pool := append([]string(nil), servers...)
		d := &net.Dialer{Timeout: timeout}
		r.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, pool[rand.IntN(len(pool))])
		}
	}
	res := &resolver{
		net:      r,
		timeout:  timeout,
		ttl:      ttl,
		negTTL:   negTTL,
		retryTTL: 5 * time.Second,
		entries:  bounded.New[string, *answer](max),
	}
	if inFlight > 0 {
		res.slots = make(chan struct{}, inFlight)
	}
	return res
}

// lookup returns the addresses for host, from the cache when it can.
func (r *resolver) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	now := time.Now()
	if a, ok := r.cached(host, now); ok {
		return a.addrs, a.err
	}

	if r.slots != nil {
		select {
		case r.slots <- struct{}{}:
			defer func() { <-r.slots }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		// Someone may have answered the same question while this one waited.
		if a, ok := r.cached(host, time.Now()); ok {
			return a.addrs, a.err
		}
	}

	// The timeout starts once the lookup does, so a lookup that waited for a
	// slot still gets its full go.
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	addrs, err := r.net.LookupNetIP(ctx, "ip", host)
	// Read the clock again. The one taken before the semaphore wait can be
	// seconds stale by now, which is exactly the case the retry TTL is meant
	// to cover: measured from then, a five-second entry is often born already
	// expired, so the burst it exists to absorb goes straight back to a
	// resolver that is already struggling.
	now = time.Now()

	// "No such host" counts as an answer: the resolver did its job and the
	// name does not exist.
	r.health.observe(err == nil || !transientDNS(err))

	ttl := r.ttl
	switch {
	case err == nil:
	case transientDNS(err):
		ttl = r.retryTTL
	default:
		ttl = r.negTTL
	}
	r.store(host, &answer{addrs: addrs, err: err, expires: now.Add(ttl)})
	return addrs, err
}

func (r *resolver) cached(host string, now time.Time) (*answer, bool) {
	a, ok := r.entries.Get(host)
	if !ok || now.After(a.expires) {
		return nil, false
	}
	return a, true
}

// store keeps an answer. The cache sheds work rather than deciding anything,
// so an entry the table drops on its way past its ceiling costs one lookup.
func (r *resolver) store(host string, a *answer) {
	r.entries.Put(host, a)
}

// usable filters a lookup down to the addresses this monitor may dial, which
// unless AllowPrivate is set means the ones out on the public internet.
func usable(addrs []netip.Addr, allowPrivate bool) []netip.Addr {
	if allowPrivate {
		return addrs
	}
	out := addrs[:0:0]
	for _, a := range addrs {
		if public(a) {
			out = append(out, a)
		}
	}
	return out
}

// dialer returns a DialContext that dials the addresses already in the cache
// rather than resolving the name a second time. A redirect to a host nobody
// has looked at yet resolves here, and lands in the same cache.
func (p *Prober) dialer(base func(ctx context.Context, network, addr string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return p.cachedDialer(base, false)
}

// trustingDialer is dialer without the public-address filter.
func (p *Prober) trustingDialer(base func(ctx context.Context, network, addr string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return p.cachedDialer(base, true)
}

func (p *Prober) cachedDialer(base func(ctx context.Context, network, addr string) (net.Conn, error), trusted bool) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return base(ctx, network, addr)
		}
		addrs, err := p.lookup(ctx, host)
		if err != nil {
			return nil, err
		}
		addrs = usable(addrs, p.allowPrivate || trusted)
		if len(addrs) == 0 {
			return nil, fmt.Errorf("%w for %s", ErrNoAddress, host)
		}
		var errs []error
		for _, a := range addrs {
			conn, err := base(ctx, network, net.JoinHostPort(a.String(), port))
			if err == nil {
				return conn, nil
			}
			errs = append(errs, err)
			if ctx.Err() != nil {
				break
			}
		}
		return nil, errors.Join(errs...)
	}
}

// DialContext returns the prober's dialer: the same resolution, cache, and
// public-address policy the probes use.
func (p *Prober) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return p.dial(ctx, network, addr)
}

// TrustedDialContext is DialContext without the public-address refusal, for
// hosts the operator named rather than hosts a stranger's certificate did.
//
// The refusal exists because anyone can get a certificate for a name pointing
// at 127.0.0.1 and would otherwise aim this monitor at its own machine. That
// reasoning does not reach a CT log URL from --logs or a log list on the
// operator's own network: refusing those would break a perfectly ordinary
// setup to guard against the operator's own configuration.
//
// It still shares the resolver and its cache, which is the part the feed
// actually needs — without it the feed resolves through the system resolver
// and gets starved by the probing it is supposed to be feeding.
func (p *Prober) TrustedDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return p.trustedDial(ctx, network, addr)
}

// ResolverHealthy reports whether lookups are coming back with answers often
// enough to be worth making. It is false when the resolver is failing
// generally, which is the monitor's cue to stop asking for a while rather than
// to keep feeding work that cannot be done.
func (p *Prober) ResolverHealthy() bool { return p.resolver.health.reliable() }

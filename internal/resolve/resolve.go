// Package resolve provides a caching DNS front end and a dialer that uses it.
//
// It is its own package because two unrelated parts of the monitor need the
// same resolver, and they need it to be the *same* one. Probing saturates DNS:
// left on the system resolver, a run fetching hundreds of hosts a second
// starves its own certificate feed of lookups, which surfaces as
// "get-sth: ... server misbehaving" and stops the feed entirely. Sharing one
// cache and one in-flight bound between the feed and the probes is what stops
// that, and neither of them is the right owner of the thing they share.
package resolve

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

// ErrNoAddress reports a name that resolved to nothing the caller may dial.
var ErrNoAddress = errors.New("no usable address")

// Defaults for Options. They are exported so that whoever renders them as
// command-line flags names one value rather than a second copy of it.
const (
	// DefaultTimeout bounds one lookup.
	DefaultTimeout = 2 * time.Second
	// DefaultTTL is how long a good answer is kept.
	DefaultTTL = 5 * time.Minute
	// DefaultNegativeTTL is how long a failed one is kept.
	DefaultNegativeTTL = 15 * time.Minute
	// DefaultMaxEntries is how many answers are held.
	DefaultMaxEntries = 1 << 17
	// DefaultMaxInFlight bounds how many lookups run at once. It is
	// deliberately far below a prober's worker count: the workers wait on
	// sockets, but their lookups usually land on one local forwarder, and a
	// forwarder asked several hundred questions at once answers some of them
	// with failures. Lookups over the bound wait their turn.
	DefaultMaxInFlight = 64
	// DefaultDialTimeout bounds the TCP connect of the dialer Dialer builds
	// when given no base of its own.
	DefaultDialTimeout = 10 * time.Second
)

// retryTTL is how long a lookup that got no answer is remembered. It is short
// on purpose: the point is to stop a burst of names under one parent from
// re-asking a struggling resolver all at once, not to remember a non-answer.
const retryTTL = 5 * time.Second

// DialFunc is the shape of net.Dialer's DialContext, which is what an
// http.Transport wants and what this package hands back.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Lookuper is the part of a Resolver that Dialer needs. Taking the smaller
// interface is what lets a caller wrap or fake resolution without also having
// to answer for the health of a resolver it does not own.
type Lookuper interface {
	Lookup(ctx context.Context, host string) ([]netip.Addr, error)
}

// TransientErr reports whether a lookup failed for a reason that says nothing
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
func TransientErr(err error) bool {
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

// Options configure a Resolver. Every zero field takes the matching Default
// above.
type Options struct {
	// Servers are the nameservers to ask, as host:port. Empty uses the
	// system's, which on a machine running a local forwarder means every
	// lookup queues behind one process; naming real upstreams here is what
	// lets a prober's worker count rise.
	Servers []string
	// Timeout bounds one lookup.
	Timeout time.Duration
	// TTL is how long a good answer is cached, NegativeTTL how long a failed
	// one is, and MaxEntries how many are held.
	TTL         time.Duration
	NegativeTTL time.Duration
	MaxEntries  int
	// MaxInFlight bounds how many lookups run at once.
	MaxInFlight int
}

// Resolver is a caching DNS front end. It is safe for concurrent use.
type Resolver struct {
	net     *net.Resolver
	timeout time.Duration
	ttl     time.Duration // how long a good answer is kept
	negTTL  time.Duration // how long a failure is kept
	// slots bounds how many lookups are in flight. Queueing here turns too
	// much concurrency into waiting, which costs a moment; the alternative is
	// a timeout recorded against a host that was never asked about.
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

// New builds a caching resolver.
func New(opts Options) *Resolver {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.TTL <= 0 {
		opts.TTL = DefaultTTL
	}
	if opts.NegativeTTL <= 0 {
		opts.NegativeTTL = DefaultNegativeTTL
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = DefaultMaxEntries
	}
	if opts.MaxInFlight <= 0 {
		opts.MaxInFlight = DefaultMaxInFlight
	}

	// PreferGo reads resolv.conf in Go rather than going through libc, which
	// is what makes Dial below reachable at all.
	r := &net.Resolver{PreferGo: true}
	if len(opts.Servers) > 0 {
		// Spread the queries over the configured servers. One local forwarder
		// answering every lookup is the first thing to fall over when the
		// worker count goes up.
		pool := append([]string(nil), opts.Servers...)
		d := &net.Dialer{Timeout: opts.Timeout}
		r.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, pool[rand.IntN(len(pool))])
		}
	}
	return &Resolver{
		net:     r,
		timeout: opts.Timeout,
		ttl:     opts.TTL,
		negTTL:  opts.NegativeTTL,
		slots:   make(chan struct{}, opts.MaxInFlight),
		entries: bounded.New[string, *answer](opts.MaxEntries),
	}
}

// Lookup returns the addresses for host, from the cache when it can.
func (r *Resolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
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
	r.health.observe(err == nil || !TransientErr(err))

	ttl := r.ttl
	switch {
	case err == nil:
	case TransientErr(err):
		ttl = retryTTL
	default:
		ttl = r.negTTL
	}
	r.store(host, &answer{addrs: addrs, err: err, expires: now.Add(ttl)})
	return addrs, err
}

// Healthy reports whether lookups are coming back with answers often enough to
// be worth making. It is false when the resolver is failing generally, which is
// a caller's cue to stop asking for a while rather than to keep feeding work
// that cannot be done.
func (r *Resolver) Healthy() bool { return r.health.reliable() }

func (r *Resolver) cached(host string, now time.Time) (*answer, bool) {
	a, ok := r.entries.Get(host)
	if !ok || now.After(a.expires) {
		return nil, false
	}
	return a, true
}

// store keeps an answer. The cache sheds work rather than deciding anything,
// so an entry the table drops on its way past its ceiling costs one lookup.
func (r *Resolver) store(host string, a *answer) {
	r.entries.Put(host, a)
}

// Dialer returns a DialContext that dials the addresses already in r's cache
// rather than resolving the name a second time. A redirect to a host nobody
// has looked at yet resolves here, and lands in the same cache.
//
// base is what actually opens the connection; nil means an ordinary dialer with
// a DefaultDialTimeout connect timeout. allow, when non-nil, decides which
// resolved addresses may be dialled at all — this package has no opinion on
// that, because who may be dialled depends on where the hostname came from.
func Dialer(r Lookuper, base DialFunc, allow func(netip.Addr) bool) DialFunc {
	if base == nil {
		base = (&net.Dialer{Timeout: DefaultDialTimeout, KeepAlive: 30 * time.Second}).DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return base(ctx, network, addr)
		}
		addrs, err := r.Lookup(ctx, host)
		if err != nil {
			return nil, err
		}
		addrs = Allowed(addrs, allow)
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

// Allowed filters a lookup down to the addresses allow accepts. A nil allow
// accepts everything.
func Allowed(addrs []netip.Addr, allow func(netip.Addr) bool) []netip.Addr {
	if allow == nil {
		return addrs
	}
	out := addrs[:0:0]
	for _, a := range addrs {
		if allow(a) {
			out = append(out, a)
		}
	}
	return out
}

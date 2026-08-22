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

// resolver is a caching DNS front end. It is safe for concurrent use.
type resolver struct {
	net     *net.Resolver
	timeout time.Duration
	ttl     time.Duration // how long a good answer is kept
	negTTL  time.Duration // how long a failure is kept
	max     int
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

	mu      sync.Mutex
	entries map[string]*answer
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
		max:      max,
		entries:  make(map[string]*answer, max/4),
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
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.entries[host]
	if !ok || now.After(a.expires) {
		return nil, false
	}
	return a, true
}

func (r *resolver) store(host string, a *answer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) >= r.max {
		// The same eviction the recent-hosts filter uses: start over. The
		// cache sheds work, it does not decide anything, so forgetting an
		// entry early only costs one lookup.
		r.entries = make(map[string]*answer, r.max/4)
	}
	r.entries[host] = a
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
		addrs = usable(addrs, p.allowPrivate)
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

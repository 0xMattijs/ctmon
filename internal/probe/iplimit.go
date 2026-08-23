package probe

import (
	"net/netip"
	"sync"

	"golang.org/x/time/rate"
)

// Politeness is per destination, not per monitor.
//
// The old global limit of 20 requests a second was the wrong unit: every probe
// is a different host getting exactly one request, so the limit was not
// sparing anybody — it was only capping the monitor at a fourteenth of its
// intake. What a site can object to is how often *it* is asked, and after
// resolution that question has an answer: the address about to be dialled.
//
// Addresses are shared, which is the point. Thousands of CT names sit behind
// the same few CDN addresses, and those are exactly the ones a global limit
// spread thin while leaving the long tail of one-name hosts untouched.

// ipLimiter rations requests per destination address.
type ipLimiter struct {
	rate  rate.Limit
	burst int
	max   int

	mu      sync.Mutex
	buckets map[netip.Addr]*rate.Limiter
}

func newIPLimiter(perSecond float64, burst, max int) *ipLimiter {
	return &ipLimiter{
		rate:    rate.Limit(perSecond),
		burst:   burst,
		max:     max,
		buckets: make(map[netip.Addr]*rate.Limiter, max/4),
	}
}

// allow reports whether addr may be dialled now. It never waits: a probe held
// back here goes back on the pending queue and comes round again, which keeps
// a busy address from pinning a worker that could be fetching something else.
func (l *ipLimiter) allow(addr netip.Addr) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	b, ok := l.buckets[addr]
	if !ok {
		if len(l.buckets) >= l.max {
			// Dropping the table refunds every bucket at once. It is a real
			// loss of accounting, so the table is sized to hold far more
			// addresses than a busy monitor sees in a burst.
			l.buckets = make(map[netip.Addr]*rate.Limiter, l.max/4)
		}
		b = rate.NewLimiter(l.rate, l.burst)
		l.buckets[addr] = b
	}
	l.mu.Unlock()
	return b.Allow()
}

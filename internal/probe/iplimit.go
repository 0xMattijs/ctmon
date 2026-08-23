package probe

import (
	"net/netip"

	"golang.org/x/time/rate"

	"github.com/mvo/ct/internal/bounded"
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
//
// The table is bounded, and filling it drops every bucket at once — which
// refunds every budget at once. That is a real loss of accounting rather than
// a stale entry, so the ceiling is set far above the number of addresses a
// busy monitor sees in a burst.
type ipLimiter struct {
	rate    rate.Limit
	burst   int
	buckets *bounded.Map[netip.Addr, *rate.Limiter]
}

func newIPLimiter(perSecond float64, burst, max int) *ipLimiter {
	return &ipLimiter{
		rate:    rate.Limit(perSecond),
		burst:   burst,
		buckets: bounded.New[netip.Addr, *rate.Limiter](max),
	}
}

// allow reports whether addr may be dialled now. It never waits: a probe held
// back here goes back on the pending queue and comes round again, which keeps
// a busy address from pinning a worker that could be fetching something else.
func (l *ipLimiter) allow(addr netip.Addr) bool {
	if l == nil {
		return true
	}
	// Spending from the bucket happens after GetOrPut returns, so the table is
	// not locked while it does.
	b, _ := l.buckets.GetOrPut(addr, func() *rate.Limiter {
		return rate.NewLimiter(l.rate, l.burst)
	})
	return b.Allow()
}

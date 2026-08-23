package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// A name that does not resolve costs a DNS answer and nothing else. Left to
// the HTTP client it cost a worker the whole dial timeout, and a quarter of
// all probes on live data end this way.
func TestProbeSkipsTheFetchWhenTheNameDoesNotResolve(t *testing.T) {
	dialed := false
	missing := &net.DNSError{Err: "no such host", Name: "nowhere.test", IsNotFound: true}
	p := New(Options{
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return nil, missing
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("should not be reached")
		},
	})

	res := p.Probe(context.Background(), "nowhere.test")
	if !errors.Is(res.Err, missing) {
		t.Errorf("err = %v, want the lookup failure", res.Err)
	}
	if dialed {
		t.Error("probe dialled a name that does not resolve")
	}
	if res.Deferred {
		t.Error("a name that does not resolve was reported as deferred, not as a result")
	}
}

// A name that resolves only inside the local network is refused before the
// dialler ever sees it, which is the same answer the Control hook gives and
// one round trip cheaper.
func TestProbeRefusesANameThatResolvesPrivate(t *testing.T) {
	p := New(Options{
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			t.Error("probe dialled a private address")
			return nil, errors.New("should not be reached")
		},
	})

	res := p.Probe(context.Background(), "internal.test")
	if !errors.Is(res.Err, ErrPrivateAddress) {
		t.Errorf("err = %v, want it to refuse a non-public address", res.Err)
	}
}

func TestResolverCachesBothAnswersAndFailures(t *testing.T) {
	var calls atomic.Int64
	r := newResolver(nil, time.Second, time.Minute, time.Minute, 16, 8)
	lookup := func(host string) ([]netip.Addr, error) {
		calls.Add(1)
		if host == "gone.test" {
			return nil, errors.New("no such host")
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	// Fill the cache the way lookup does, then read it back.
	for _, host := range []string{"here.test", "gone.test"} {
		addrs, err := lookup(host)
		ttl := r.ttl
		if err != nil {
			ttl = r.negTTL
		}
		r.store(host, &answer{addrs: addrs, err: err, expires: time.Now().Add(ttl)})
	}

	for _, host := range []string{"here.test", "gone.test"} {
		if _, ok := r.cached(host, time.Now()); !ok {
			t.Errorf("%s was not cached", host)
		}
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("looked up %d times, want 2", n)
	}
	// A failure is cached too: a name that does not exist will not exist a
	// second later either.
	if a, _ := r.cached("gone.test", time.Now()); a.err == nil {
		t.Error("the failed lookup was cached as a success")
	}
	// And an expired entry is a miss.
	if _, ok := r.cached("here.test", time.Now().Add(2*time.Minute)); ok {
		t.Error("an expired entry was served from the cache")
	}
}

func TestResolverCacheStaysBounded(t *testing.T) {
	r := newResolver(nil, time.Second, time.Minute, time.Minute, 8, 4)
	for i := 0; i < 100; i++ {
		r.store(string(rune('a'+i%26))+string(rune('a'+i/26)), &answer{expires: time.Now().Add(time.Minute)})
	}
	if n := r.entries.Len(); n > 8 {
		t.Errorf("cache holds %d entries, want at most its 8-entry bound", n)
	}
}

func TestUsableDropsPrivateAddressesUnlessAllowed(t *testing.T) {
	addrs := []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("10.0.0.1"),
	}
	if got := usable(addrs, false); len(got) != 1 || got[0].String() != "192.0.2.1" {
		t.Errorf("usable = %v, want only the public address", got)
	}
	if got := usable(addrs, true); len(got) != 3 {
		t.Errorf("usable with AllowPrivate = %v, want all three", got)
	}
}

// While the resolver is failing generally, a lookup failure says nothing about
// the host, so the probe is put off. Once it recovers, the same failure is a
// fact about the name and gets recorded — otherwise a name whose nameservers
// are dead returns on every sweep forever.
func TestFailedLookupsAreDeferredOnlyWhileTheResolverIsFailing(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"timeout", &net.DNSError{Err: "i/o timeout", IsTimeout: true}},
		{"servfail", &net.DNSError{Err: "server misbehaving", IsTemporary: true}},
		{"context", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := New(Options{
				Lookup: func(context.Context, string) ([]netip.Addr, error) {
					return nil, tc.err
				},
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					t.Error("probe dialled a host it could not resolve")
					return nil, errors.New("should not be reached")
				},
			})

			// With no evidence either way, the resolver is trusted and the
			// failure is recorded.
			if res := p.Probe(context.Background(), "unknown.test"); res.Deferred {
				t.Errorf("res = %+v, want the failure recorded while the resolver looks fine", res)
			}

			// Enough failures in a row and it plainly is not fine.
			for i := 0; i < healthMinSamples; i++ {
				p.resolver.health.observe(false)
			}
			res := p.Probe(context.Background(), "unknown.test")
			if !res.Deferred {
				t.Errorf("res = %+v, want it deferred while the resolver is failing", res)
			}
			if res.DeferReason != DeferNoAnswer {
				t.Errorf("defer reason = %q, want the resolver", res.DeferReason)
			}
			if res.Err != nil {
				t.Errorf("a deferred probe carries err %v, want nothing to record", res.Err)
			}

			// And once it recovers, failures are believed again.
			for i := 0; i < healthMinSamples*2; i++ {
				p.resolver.health.observe(true)
			}
			if res := p.Probe(context.Background(), "unknown.test"); res.Deferred {
				t.Errorf("res = %+v, want the failure recorded once the resolver recovered", res)
			}
		})
	}
}

func TestHealthNeedsEvidenceBeforeDistrustingTheResolver(t *testing.T) {
	var h health
	if !h.reliable() {
		t.Error("an untouched resolver was distrusted; want the benefit of the doubt")
	}
	for i := 0; i < healthMinSamples-1; i++ {
		h.observe(false)
	}
	if !h.reliable() {
		t.Errorf("distrusted after %d failures, want to wait for %d samples",
			healthMinSamples-1, healthMinSamples)
	}
	h.observe(false)
	if h.reliable() {
		t.Error("still trusted after a full window of nothing but failures")
	}
	// A resolver answering most of the time is working, even with some misses.
	var mixed health
	for i := 0; i < healthMinSamples; i++ {
		mixed.observe(i%4 != 0) // 75% answered
	}
	if !mixed.reliable() {
		t.Error("a resolver answering three lookups in four was called broken")
	}
}

func TestTransientDNSSeparatesAnswersFromNonAnswers(t *testing.T) {
	if transientDNS(&net.DNSError{Err: "no such host", IsNotFound: true}) {
		t.Error("no-such-host is an answer, not a non-answer")
	}
	for _, err := range []error{
		&net.DNSError{Err: "i/o timeout", IsTimeout: true},
		&net.DNSError{Err: "server misbehaving", IsTemporary: true},
		context.DeadlineExceeded,
	} {
		if !transientDNS(err) {
			t.Errorf("%v was treated as an answer about the name", err)
		}
	}
}

// A non-answer is remembered only briefly, so a struggling resolver does not
// get its bad moment cached over every name under one parent.
func TestNonAnswersAreNotCachedForLong(t *testing.T) {
	r := newResolver(nil, time.Second, 5*time.Minute, 15*time.Minute, 16, 8)
	now := time.Now()
	r.store("gone.test", &answer{
		err:     &net.DNSError{Err: "no such host", IsNotFound: true},
		expires: now.Add(r.negTTL),
	})
	r.store("busy.test", &answer{
		err:     &net.DNSError{Err: "i/o timeout", IsTimeout: true},
		expires: now.Add(r.retryTTL),
	})

	later := now.Add(time.Minute)
	if _, ok := r.cached("gone.test", later); !ok {
		t.Error("a name that does not exist was forgotten after a minute")
	}
	if _, ok := r.cached("busy.test", later); ok {
		t.Error("a lookup that got no answer was still cached after a minute")
	}
}

package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

// fakeResolver answers every lookup the same way and reports whatever health
// the test wants. Both together, because the two are only meaningful as a
// pair: whether a failed lookup is a fact about the name depends on whether
// the resolver is answering at all.
type fakeResolver struct {
	addrs   []netip.Addr
	err     error
	healthy bool
}

func (f *fakeResolver) Lookup(context.Context, string) ([]netip.Addr, error) {
	return f.addrs, f.err
}

func (f *fakeResolver) Healthy() bool { return f.healthy }

// A name that does not resolve costs a DNS answer and nothing else. Left to
// the HTTP client it cost a worker the whole dial timeout, and a quarter of
// all probes on live data end this way.
func TestProbeSkipsTheFetchWhenTheNameDoesNotResolve(t *testing.T) {
	dialed := false
	missing := &net.DNSError{Err: "no such host", Name: "nowhere.test", IsNotFound: true}
	p := New(Options{
		Resolver: &fakeResolver{err: missing, healthy: true},
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
		Resolver: &fakeResolver{
			addrs:   []netip.Addr{netip.MustParseAddr("127.0.0.1")},
			healthy: true,
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
			res := &fakeResolver{err: tc.err, healthy: true}
			p := New(Options{
				Resolver: res,
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					t.Error("probe dialled a host it could not resolve")
					return nil, errors.New("should not be reached")
				},
			})

			// A resolver that is answering is believed, so the failure is
			// recorded against the name.
			if got := p.Probe(context.Background(), "unknown.test"); got.Deferred {
				t.Errorf("res = %+v, want the failure recorded while the resolver looks fine", got)
			}

			res.healthy = false
			got := p.Probe(context.Background(), "unknown.test")
			if !got.Deferred {
				t.Errorf("res = %+v, want it deferred while the resolver is failing", got)
			}
			if got.DeferReason != DeferNoAnswer {
				t.Errorf("defer reason = %q, want the resolver", got.DeferReason)
			}
			if got.Err != nil {
				t.Errorf("a deferred probe carries err %v, want nothing to record", got.Err)
			}

			// And once it recovers, failures are believed again.
			res.healthy = true
			if got := p.Probe(context.Background(), "unknown.test"); got.Deferred {
				t.Errorf("res = %+v, want the failure recorded once the resolver recovered", got)
			}
		})
	}
}

// The address policy is what a Prober hands the resolver's dialer. It is the
// public-address guard, and nothing at all when AllowPrivate lifts it.
func TestAddressPolicyFollowsAllowPrivate(t *testing.T) {
	guarded := New(Options{}).addressPolicy()
	if guarded == nil {
		t.Fatal("the default Prober has no address policy; want the public-address guard")
	}
	if guarded(netip.MustParseAddr("127.0.0.1")) {
		t.Error("the guard allowed loopback")
	}
	if !guarded(netip.MustParseAddr("192.0.2.1")) {
		t.Error("the guard refused a public address")
	}
	if New(Options{AllowPrivate: true}).addressPolicy() != nil {
		t.Error("AllowPrivate left an address policy in place")
	}
}

// A Prober given a dialer and no resolver does not resolve, so it can neither
// judge the resolver's health nor be held back by it.
func TestProberWithoutAResolverIsAlwaysHealthy(t *testing.T) {
	p := New(Options{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("should not be reached")
		},
	})
	if p.res != nil {
		t.Error("a Prober given its own dialer built a resolver anyway")
	}
	if !p.ResolverHealthy() {
		t.Error("a Prober that does not resolve reported an unhealthy resolver")
	}
}

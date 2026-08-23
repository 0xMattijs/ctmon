package resolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestResolverCachesBothAnswersAndFailures(t *testing.T) {
	var calls atomic.Int64
	r := New(Options{Timeout: time.Second, TTL: time.Minute, NegativeTTL: time.Minute, MaxEntries: 16, MaxInFlight: 8})
	lookup := func(host string) ([]netip.Addr, error) {
		calls.Add(1)
		if host == "gone.test" {
			return nil, errors.New("no such host")
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	// Fill the cache the way Lookup does, then read it back.
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
	r := New(Options{Timeout: time.Second, TTL: time.Minute, NegativeTTL: time.Minute, MaxEntries: 8, MaxInFlight: 4})
	for i := 0; i < 100; i++ {
		r.store(string(rune('a'+i%26))+string(rune('a'+i/26)), &answer{expires: time.Now().Add(time.Minute)})
	}
	if n := r.entries.Len(); n > 8 {
		t.Errorf("cache holds %d entries, want at most its 8-entry bound", n)
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

func TestTransientErrSeparatesAnswersFromNonAnswers(t *testing.T) {
	if TransientErr(&net.DNSError{Err: "no such host", IsNotFound: true}) {
		t.Error("no-such-host is an answer, not a non-answer")
	}
	for _, err := range []error{
		&net.DNSError{Err: "i/o timeout", IsTimeout: true},
		&net.DNSError{Err: "server misbehaving", IsTemporary: true},
		context.DeadlineExceeded,
	} {
		if !TransientErr(err) {
			t.Errorf("%v was treated as an answer about the name", err)
		}
	}
}

// A non-answer is remembered only briefly, so a struggling resolver does not
// get its bad moment cached over every name under one parent.
func TestNonAnswersAreNotCachedForLong(t *testing.T) {
	r := New(Options{Timeout: time.Second, MaxEntries: 16, MaxInFlight: 8})
	now := time.Now()
	r.store("gone.test", &answer{
		err:     &net.DNSError{Err: "no such host", IsNotFound: true},
		expires: now.Add(r.negTTL),
	})
	r.store("busy.test", &answer{
		err:     &net.DNSError{Err: "i/o timeout", IsTimeout: true},
		expires: now.Add(retryTTL),
	})

	later := now.Add(time.Minute)
	if _, ok := r.cached("gone.test", later); !ok {
		t.Error("a name that does not exist was forgotten after a minute")
	}
	if _, ok := r.cached("busy.test", later); ok {
		t.Error("a lookup that got no answer was still cached after a minute")
	}
}

func TestAllowedFiltersAddresses(t *testing.T) {
	addrs := []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("10.0.0.1"),
	}
	only := func(a netip.Addr) bool { return a.String() == "192.0.2.1" }
	if got := Allowed(addrs, only); len(got) != 1 || got[0].String() != "192.0.2.1" {
		t.Errorf("Allowed = %v, want only the address the filter accepts", got)
	}
	// A nil filter is the caller saying it has no opinion, not an empty one.
	if got := Allowed(addrs, nil); len(got) != 3 {
		t.Errorf("Allowed with no filter = %v, want all three", got)
	}
}

// The dialer resolves once and dials what it found, rather than handing the
// name back to the network stack to look up a second time.
func TestDialerDialsResolvedAddresses(t *testing.T) {
	var dialed []string
	fake := lookupFunc(func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("192.0.2.1"),
			netip.MustParseAddr("192.0.2.2"),
		}, nil
	})
	dial := Dialer(fake, func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return nil, errors.New("refused by the test")
	}, nil)

	if _, err := dial(context.Background(), "tcp", "example.test:443"); err == nil {
		t.Fatal("want the dial failure")
	}
	want := []string{"192.0.2.1:443", "192.0.2.2:443"}
	if len(dialed) != len(want) {
		t.Fatalf("dialled %v, want every resolved address tried: %v", dialed, want)
	}
	for i := range want {
		if dialed[i] != want[i] {
			t.Errorf("dial %d = %s, want %s", i, dialed[i], want[i])
		}
	}
}

// A name that resolves only to addresses the filter refuses never reaches the
// base dialer at all.
func TestDialerRefusesWhenTheFilterLeavesNothing(t *testing.T) {
	fake := lookupFunc(func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	dial := Dialer(fake, func(context.Context, string, string) (net.Conn, error) {
		t.Error("the base dialer was reached for a refused address")
		return nil, errors.New("should not be reached")
	}, func(netip.Addr) bool { return false })

	_, err := dial(context.Background(), "tcp", "internal.test:443")
	if !errors.Is(err, ErrNoAddress) {
		t.Errorf("err = %v, want ErrNoAddress", err)
	}
}

// lookupFunc adapts a function to Lookuper.
type lookupFunc func(context.Context, string) ([]netip.Addr, error)

func (f lookupFunc) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return f(ctx, host)
}

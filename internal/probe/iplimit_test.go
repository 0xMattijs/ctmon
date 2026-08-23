package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestIPLimiterRationsPerAddress(t *testing.T) {
	l := newIPLimiter(1, 2, 16)
	busy := netip.MustParseAddr("192.0.2.1")
	quiet := netip.MustParseAddr("192.0.2.2")

	if !l.allow(busy) || !l.allow(busy) {
		t.Fatal("the first two requests to an address were refused, want the burst honoured")
	}
	if l.allow(busy) {
		t.Error("a third request went through, want the address over its budget")
	}
	// Another address has its own budget. That is the whole point: the limit
	// this replaced was shared by hosts that had nothing to do with each other.
	if !l.allow(quiet) {
		t.Error("a different address was refused for its neighbour's traffic")
	}
}

func TestIPLimiterStaysBounded(t *testing.T) {
	l := newIPLimiter(1, 1, 4)
	for i := 0; i < 100; i++ {
		l.allow(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}))
	}
	if n := l.buckets.Len(); n > 4 {
		t.Errorf("table holds %d addresses, want at most its 4-address bound", n)
	}
}

// A probe over its address's budget is handed back undone rather than delayed,
// so the worker moves on instead of sitting on a busy CDN address.
func TestProbeDefersWhenTheAddressIsOverBudget(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.1")
	dials := 0
	p := New(Options{
		PerIPRPS:   1,
		PerIPBurst: 1,
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{addr}, nil
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dials++
			return nil, errors.New("dial refused by the test")
		},
	})

	if res := p.Probe(context.Background(), "first.test"); res.Deferred {
		t.Fatal("the first probe was deferred, want the burst honoured")
	}
	res := p.Probe(context.Background(), "second.test")
	if !res.Deferred {
		t.Errorf("second probe = %+v, want it deferred", res)
	}
	if res.DeferReason != DeferAddressBudget {
		t.Errorf("defer reason = %q, want the address budget", res.DeferReason)
	}
	if res.Err != nil {
		t.Errorf("a deferred probe carries err %v, want nothing to record", res.Err)
	}
	if dials != 1 {
		t.Errorf("dialled %d times, want only the probe that was under budget", dials)
	}
}

// Zero means the default everywhere else in Options, so turning the
// per-address budget off has to be said explicitly.
func TestPerIPLimitCanBeTurnedOff(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.1")
	p := New(Options{
		NoPerIPLimit: true,
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{addr}, nil
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial refused by the test")
		},
	})
	for i := 0; i < 200; i++ {
		if res := p.Probe(context.Background(), "busy.test"); res.Deferred {
			t.Fatalf("probe %d was deferred with the per-address budget off", i)
		}
	}
}

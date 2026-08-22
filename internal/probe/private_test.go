package probe

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestPublicAddresses(t *testing.T) {
	cases := map[string]bool{
		// Ordinary internet addresses.
		"1.1.1.1":              true,
		"93.184.216.34":        true,
		"2606:4700:4700::1111": true,

		// Loopback, in both families and in the v4-in-v6 form that slips
		// past a check that forgets to unmap.
		"127.0.0.1":        false,
		"127.1.2.3":        false,
		"::1":              false,
		"::ffff:127.0.0.1": false,

		// RFC 1918 and its v6 counterpart.
		"10.0.0.1":           false,
		"172.16.0.1":         false,
		"172.31.255.255":     false,
		"192.168.1.1":        false,
		"fd00::1":            false,
		"::ffff:192.168.1.1": false,

		// Just outside RFC 1918, so still public.
		"172.15.0.1": true,
		"172.32.0.1": true,
		"11.0.0.1":   true,

		// Link-local, multicast, unspecified, broadcast.
		"169.254.169.254": false, // the cloud metadata endpoint
		"fe80::1":         false,
		"224.0.0.1":       false,
		"ff02::1":         false,
		"0.0.0.0":         false,
		"::":              false,
		"255.255.255.255": false,

		// IPv6 forms that carry an IPv4 address and reach it. The embedded
		// address decides, so a DNS64 network can still fetch ordinary
		// IPv4 sites while a translated 127.0.0.1 stays blocked.
		"64:ff9b::7f00:1":    false, // NAT64 of 127.0.0.1
		"64:ff9b::a00:1":     false, // NAT64 of 10.0.0.1
		"64:ff9b::a9fe:a9fe": false, // NAT64 of 169.254.169.254
		"64:ff9b::101:101":   true,  // NAT64 of 1.1.1.1, a real site
		"2002:7f00:1::":      false, // 6to4 of 127.0.0.1
		"2002:c0a8:101::":    false, // 6to4 of 192.168.1.1
		"2002:101:101::":     true,  // 6to4 of 1.1.1.1
		"::127.0.0.1":        false, // IPv4-compatible loopback
		"::10.0.0.1":         false,
		"::1.1.1.1":          true,

		// Ranges netip has no predicate for.
		"0.1.2.3":     false, // "this network"
		"100.64.0.1":  false, // carrier-grade NAT
		"100.128.0.1": true,  // just past it
		"192.0.0.1":   false, // IETF protocol assignments
		"192.0.1.1":   true,  // just past it
		"198.18.0.1":  false, // benchmarking
		"198.20.0.1":  true,  // just past it
	}
	for s, want := range cases {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("bad test address %q: %v", s, err)
		}
		if got := public(addr); got != want {
			t.Errorf("public(%s) = %v, want %v", s, got, want)
		}
	}
}

// refusePrivate fails closed: an address it cannot read is not dialed.
func TestRefusePrivateRejectsUnreadableAddresses(t *testing.T) {
	for _, addr := range []string{"", "not-an-address", "example.com:443", "1.1.1.1"} {
		if err := refusePrivate("tcp", addr, nil); err == nil {
			t.Errorf("refusePrivate(%q) allowed an address it could not parse", addr)
		}
	}
	if err := refusePrivate("tcp", "1.1.1.1:443", nil); err != nil {
		t.Errorf("refusePrivate rejected a public address: %v", err)
	}
}

// The guard is on by default, and the refusal reaches the caller as the
// probe's recorded error rather than a connection attempt.
func TestProbeRefusesPrivateAddressesByDefault(t *testing.T) {
	p := New(Options{Timeout: 2 * time.Second})
	for _, host := range []string{"127.0.0.1", "localhost", "169.254.169.254"} {
		res := p.Probe(context.Background(), host)
		if res.Err == nil {
			t.Errorf("probe of %s was allowed", host)
			continue
		}
		if !errors.Is(res.Err, ErrPrivateAddress) {
			t.Errorf("probe of %s failed with %v, want ErrPrivateAddress", host, res.Err)
		}
	}
}

// --allow-private takes the guard off. The probe still fails, because nothing
// is listening, but it fails at the connection rather than at the guard.
func TestAllowPrivateLiftsTheGuard(t *testing.T) {
	p := New(Options{Timeout: 2 * time.Second, AllowPrivate: true})
	res := p.Probe(context.Background(), "127.0.0.1")
	if errors.Is(res.Err, ErrPrivateAddress) {
		t.Errorf("AllowPrivate did not lift the guard: %v", res.Err)
	}
}

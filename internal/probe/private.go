package probe

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// ErrPrivateAddress reports a probe refused because the host resolved to an
// address inside a private or otherwise local network.
var ErrPrivateAddress = errors.New("refusing to probe a non-public address")

// refusePrivate is a net.Dialer Control hook that fails a connection about to
// leave the public internet.
//
// It runs after the name resolves and before the connect, so it sees the
// address the connection would actually use. That is the whole reason to check
// here rather than up front: it covers redirects to an internal host, hosts
// with a mix of public and private records, and names that resolve one way now
// and another way a moment later.
//
// It fails closed. An address it cannot parse is refused rather than dialed,
// because a guard that waves through what it does not understand is not one.
func refusePrivate(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: cannot read address %q", ErrPrivateAddress, address)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: cannot read address %q", ErrPrivateAddress, host)
	}
	if !public(addr) {
		return fmt.Errorf("%w: %s", ErrPrivateAddress, addr)
	}
	return nil
}

// reservedV4 holds the ranges that netip's own predicates do not cover but
// that still are not a site on the public internet.
var reservedV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),     // "this network", RFC 1122
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT, RFC 6598
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking, RFC 2544
}

// broadcastV4 is the limited broadcast address, which has no netip predicate.
var broadcastV4 = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// IPv6 forms that carry an IPv4 address inside them and reach it.
var (
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96") // RFC 6052
	sixToFour      = netip.MustParsePrefix("2002::/16")    // RFC 3056
	ipv4Compatible = netip.MustParsePrefix("::/96")        // deprecated, RFC 4291
)

// embeddedV4 returns the IPv4 address carried inside an IPv6 one, and whether
// there was one.
//
// A packet to 64:ff9b::7f00:1 comes out of the translator addressed to
// 127.0.0.1, and none of the IPv6 predicates see anything wrong with it, so an
// IPv6-only host behind NAT64 would have no guard at all. 6to4 and the
// deprecated IPv4-compatible form encode a destination the same way.
//
// Blocking these prefixes outright would be wrong: on an IPv6-only network
// with DNS64, every ordinary IPv4 website arrives as a synthesized address
// under 64:ff9b::/96. What matters is the address on the far side of the
// translation, so hand that back and let the usual test decide.
func embeddedV4(addr netip.Addr) (netip.Addr, bool) {
	if !addr.Is6() {
		return netip.Addr{}, false
	}
	b := addr.As16()
	switch {
	case nat64WellKnown.Contains(addr), ipv4Compatible.Contains(addr):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(addr):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

// public reports whether addr is an ordinary address out on the internet, and
// so something this monitor may fetch.
func public(addr netip.Addr) bool {
	// ::ffff:127.0.0.1 is loopback wearing a v6 hat, and every predicate
	// below would miss it in that form.
	addr = addr.Unmap()
	if !addr.IsValid() {
		return false
	}
	switch {
	case addr.IsUnspecified(),
		addr.IsLoopback(),
		addr.IsPrivate(),
		addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(),
		addr.IsInterfaceLocalMulticast(),
		addr.IsMulticast(),
		addr == broadcastV4:
		return false
	}
	for _, p := range reservedV4 {
		if p.Contains(addr) {
			return false
		}
	}
	// Checked last, so :: and ::1 are already refused above rather than
	// arriving here as an embedded 0.0.0.0 and 0.0.0.1.
	if v4, ok := embeddedV4(addr); ok {
		return public(v4)
	}
	return true
}

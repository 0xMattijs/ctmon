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
	return true
}

// Package domain turns a certificate Common Name into the set of hostnames
// worth storing and probing.
package domain

import (
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Origin says which certificate field a name came from.
const (
	OriginCN  = "cn"
	OriginSAN = "san"
)

// Name is one hostname derived from a certificate.
type Name struct {
	// Host is the normalized hostname: lowercase, no trailing dot.
	Host string
	// FromWildcard reports whether Host was derived from a wildcard.
	FromWildcard bool
	// From is the certificate name this was derived from, verbatim.
	From string
	// Origin is OriginCN or OriginSAN. ExpandCert sets it; Expand does not.
	Origin string
}

// ExpandCert expands a certificate's Common Name and its dNSName SANs into
// the set of hostnames to store, without duplicates.
//
// Most certificates repeat the CN in the SAN list, and many carry no CN at
// all. Where a host comes from both, the CN wins: it is the more specific
// claim about what the certificate is for.
func ExpandCert(cn string, sans []string) []Name {
	var out []Name
	at := make(map[string]int)

	add := func(raw, origin string) {
		for _, n := range Expand(raw) {
			n.From, n.Origin = raw, origin
			i, ok := at[n.Host]
			if !ok {
				at[n.Host] = len(out)
				out = append(out, n)
				continue
			}
			// Already have it. Let a CN sighting overwrite a SAN one.
			if origin == OriginCN && out[i].Origin != OriginCN {
				out[i] = n
			}
		}
	}

	add(cn, OriginCN)
	for _, s := range sans {
		add(s, OriginSAN)
	}
	return out
}

// Expand normalizes a Common Name and returns the hostnames to store.
//
// A plain CN yields itself. A wildcard CN yields the apex it covers plus the
// www host under it, because those are the two names a wildcard almost always
// serves:
//
//	shop.example.com   -> [shop.example.com]
//	*.example.com      -> [example.com, www.example.com]
//	*.www.example.com  -> [www.example.com]
//
// Expand returns nil for anything that is not a usable hostname: empty CNs,
// IP addresses, CNs holding a CA name or an email address, and hostnames with
// a wildcard anywhere other than the leading label.
func Expand(cn string) []Name {
	host := normalize(cn)
	if host == "" {
		return nil
	}

	wildcard := strings.HasPrefix(host, "*.")
	if wildcard {
		host = host[2:]
	}
	if !Valid(host) {
		return nil
	}
	if !wildcard {
		return []Name{{Host: host}}
	}

	// A wildcard over *.www.example.com already covers hosts under www, so the
	// www form is the apex here and prefixing again would invent a name.
	if strings.HasPrefix(host, "www.") {
		return []Name{{Host: host, FromWildcard: true}}
	}
	return []Name{
		{Host: host, FromWildcard: true},
		{Host: "www." + host, FromWildcard: true},
	}
}

// normalize lowercases the CN and strips the decoration CAs put around it.
func normalize(cn string) string {
	host := strings.ToLower(strings.TrimSpace(cn))
	host = strings.TrimSuffix(host, ".")
	// Some CNs carry a URL scheme or path; keep only the host part.
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	return strings.TrimSuffix(host, ".")
}

// Valid reports whether host is a hostname we can resolve and fetch: a dotted
// name of DNS labels, not an IP address, with a plausible TLD.
func Valid(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if strings.ContainsAny(host, " \t*@_:,\"'()") {
		return false
	}
	if net.ParseIP(host) != nil {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !validLabel(l) {
			return false
		}
	}
	return validTLD(labels[len(labels)-1])
}

func validLabel(l string) bool {
	if len(l) == 0 || len(l) > 63 {
		return false
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// validTLD accepts alphabetic TLDs and punycode ones (xn--...).
func validTLD(tld string) bool {
	if len(tld) < 2 {
		return false
	}
	if strings.HasPrefix(tld, "xn--") {
		return len(tld) > 4
	}
	for i := 0; i < len(tld); i++ {
		if tld[i] < 'a' || tld[i] > 'z' {
			return false
		}
	}
	return true
}

// Depth reports how many labels sit below the registrable domain, and whether
// the host has a registrable domain at all.
//
//	example.com            -> 0
//	www.example.com        -> 1
//	a.b.example.com        -> 2
//	www.example.co.uk      -> 1, because co.uk is a public suffix
//	co.uk                  -> 0, false: a public suffix is not a domain
//
// Depth uses the public suffix list, so it counts real subdomain nesting
// rather than dots: example.com.br is depth 0, not depth 1.
func Depth(host string) (int, bool) {
	etld1, ok := Registrable(host)
	if !ok {
		return 0, false
	}
	if host == etld1 {
		return 0, true
	}
	prefix := strings.TrimSuffix(host, "."+etld1)
	if prefix == host {
		// EffectiveTLDPlusOne returned something that is not a suffix of
		// host, which should not happen; treat it as unnestable.
		return 0, true
	}
	return strings.Count(prefix, ".") + 1, true
}

// Registrable returns the registrable domain of host — the public suffix plus
// one label, the part somebody actually registered — and reports whether it
// has one. A host that is itself a public suffix does not.
//
//	a.b.example.co.uk -> example.co.uk, true
//	co.uk             -> "", false
func Registrable(host string) (string, bool) {
	etld1, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return "", false
	}
	return etld1, true
}

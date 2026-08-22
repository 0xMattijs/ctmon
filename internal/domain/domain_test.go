package domain

import (
	"reflect"
	"testing"
)

func TestExpand(t *testing.T) {
	tests := []struct {
		cn   string
		want []Name
	}{
		{"example.com", []Name{{Host: "example.com"}}},
		{"shop.example.com", []Name{{Host: "shop.example.com"}}},
		{"  Shop.Example.COM. ", []Name{{Host: "shop.example.com"}}},
		{"*.example.com", []Name{
			{Host: "example.com", FromWildcard: true},
			{Host: "www.example.com", FromWildcard: true},
		}},
		{"*.co.uk", []Name{
			{Host: "co.uk", FromWildcard: true},
			{Host: "www.co.uk", FromWildcard: true},
		}},
		{"*.www.example.com", []Name{{Host: "www.example.com", FromWildcard: true}}},
		{"*.deep.example.com", []Name{
			{Host: "deep.example.com", FromWildcard: true},
			{Host: "www.deep.example.com", FromWildcard: true},
		}},
		{"xn--80ak6aa92e.xn--p1ai", []Name{{Host: "xn--80ak6aa92e.xn--p1ai"}}},
		{"https://example.com/path", []Name{{Host: "example.com"}}},

		// Not hostnames.
		{"", nil},
		{"*", nil},
		{"*.*.example.com", nil},
		{"localhost", nil},
		{"192.0.2.1", nil},
		{"2001:db8::1", nil},
		{"R3", nil},
		{"DigiCert Global Root CA", nil},
		{"admin@example.com", nil},
		{"example.com:8443", nil},
		{"-bad.example.com", nil},
		{"bad-.example.com", nil},
		{"example.123", nil},
		{"example.c", nil},
		{"..", nil},
	}

	for _, tt := range tests {
		got := Expand(tt.cn)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Expand(%q) = %+v, want %+v", tt.cn, got, tt.want)
		}
	}
}

func TestValidLongHost(t *testing.T) {
	long := ""
	for i := 0; i < 4; i++ {
		long += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa." // 63 + dot
	}
	if Valid(long + "com") {
		t.Error("Valid accepted a 256-character host")
	}
	tooLongLabel := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com" // 64
	if Valid(tooLongLabel) {
		t.Error("Valid accepted a 64-character label")
	}
}

func TestDepth(t *testing.T) {
	tests := []struct {
		host  string
		depth int
		ok    bool
	}{
		{"example.com", 0, true},
		{"www.example.com", 1, true},
		{"a.b.example.com", 2, true},
		{"a.b.c.d.example.com", 4, true},

		// Multi-label public suffixes count as one level, not several.
		{"example.co.uk", 0, true},
		{"www.example.co.uk", 1, true},
		{"example.com.br", 0, true},
		{"a-cliente-final.shs-adm.com.br", 1, true},
		{"www.a-cliente-final.shs-adm.com.br", 2, true},

		// Unknown TLDs are treated as suffixes, so the name under them is
		// registrable and sits at depth 0.
		{"example.somenewtld", 0, true},

		// A public suffix is not a domain anyone owns.
		{"co.uk", 0, false},
		{"com", 0, false},
	}

	for _, tt := range tests {
		depth, ok := Depth(tt.host)
		if depth != tt.depth || ok != tt.ok {
			t.Errorf("Depth(%q) = %d, %v; want %d, %v", tt.host, depth, ok, tt.depth, tt.ok)
		}
	}
}

func TestExpandCert(t *testing.T) {
	got := ExpandCert("*.example.com", []string{
		"example.com",      // already produced by the wildcard CN
		"api.example.com",  // new
		"api.example.com",  // repeated SAN
		"DigiCert Root CA", // not a hostname
		"*.eu.example.com", // wildcard SAN
	})

	want := []struct {
		host     string
		origin   string
		from     string
		wildcard bool
	}{
		{"example.com", OriginCN, "*.example.com", true},
		{"www.example.com", OriginCN, "*.example.com", true},
		{"api.example.com", OriginSAN, "api.example.com", false},
		{"eu.example.com", OriginSAN, "*.eu.example.com", true},
		{"www.eu.example.com", OriginSAN, "*.eu.example.com", true},
	}
	if len(got) != len(want) {
		t.Fatalf("ExpandCert returned %d names, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.Host != w.host || g.Origin != w.origin || g.From != w.from || g.FromWildcard != w.wildcard {
			t.Errorf("name %d = %+v, want %s/%s/%s/%v", i, g, w.host, w.origin, w.from, w.wildcard)
		}
	}
}

func TestExpandCertPrefersCNOverSAN(t *testing.T) {
	// The host appears first as a SAN, then as the CN of the same cert.
	got := ExpandCert("shop.example.com", []string{"shop.example.com"})
	if len(got) != 1 {
		t.Fatalf("got %d names, want 1: %+v", len(got), got)
	}
	if got[0].Origin != OriginCN {
		t.Errorf("origin = %s, want %s", got[0].Origin, OriginCN)
	}

	// And the other way around: a SAN never downgrades a CN sighting.
	got = ExpandCert("", []string{"a.example.com"})
	if len(got) != 1 || got[0].Origin != OriginSAN {
		t.Errorf("SAN-only cert = %+v, want one SAN name", got)
	}
}

func TestExpandCertWithNoUsableNames(t *testing.T) {
	if got := ExpandCert("DigiCert Global Root CA", []string{"192.0.2.1", ""}); got != nil {
		t.Errorf("ExpandCert = %+v, want nil", got)
	}
}

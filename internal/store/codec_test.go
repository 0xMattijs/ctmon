package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReverseHost(t *testing.T) {
	cases := map[string]string{
		"www.example.com": "com.example.www",
		"example.com":     "com.example",
		"a.b.c.d.test":    "test.d.c.b.a",
		"localhost":       "localhost",
		"":                "",
	}
	for in, want := range cases {
		if got := reverseHost(in); got != want {
			t.Errorf("reverseHost(%q) = %q, want %q", in, got, want)
		}
		if back := reverseHost(reverseHost(in)); back != in {
			t.Errorf("reverseHost is not its own inverse for %q: got %q", in, back)
		}
	}
}

func TestReversedKeysCluster(t *testing.T) {
	// Reversed, every name under one domain sorts into one contiguous run,
	// even when unrelated domains interleave alphabetically.
	hosts := []string{"api.example.com", "zebra.com", "www.example.com", "example.com", "aardvark.com"}
	keys := make([]string, len(hosts))
	for i, h := range hosts {
		keys[i] = reverseHost(h)
	}
	sortStrings(keys)

	run := 0
	for _, k := range keys {
		if strings.HasPrefix(k, "com.example") {
			run++
			continue
		}
		if run > 0 && run < 3 {
			t.Fatalf("example.com keys were split apart: %v", keys)
		}
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func TestRecordRoundTrip(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)

	full := &Record{
		Host:         "www.example.com",
		CertName:     "*.example.com",
		Origin:       "san",
		FromWildcard: true,
		Source:       "https://ct.googleapis.com/logs/us1/argon2026h2/",
		Issuer:       "WE1",
		FirstSeen:    now.Add(-time.Hour),
		LastSeen:     now,
		SeenCount:    7,
		Probed:       true,
		ProbedAt:     now.Add(-time.Minute),
		HTTPStatus:   404,
		FinalURL:     "https://www.example.com/landing",
		BodySize:     150342,
		BodyHash:     strings.Repeat("ab", 32),
		PrevHash:     strings.Repeat("cd", 32),
		ChangedAt:    now.Add(-30 * time.Minute),
		ProbeCount:   3,
		ProbeError:   "",
	}

	minimal := &Record{
		Host:      "example.org",
		CertName:  "example.org",
		Origin:    "cn",
		Source:    "certstream",
		FirstSeen: now,
		LastSeen:  now,
		SeenCount: 1,
	}

	failed := &Record{
		Host:       "down.example.net",
		CertName:   "down.example.net",
		Origin:     "cn",
		Source:     "certstream",
		FirstSeen:  now,
		LastSeen:   now,
		SeenCount:  1,
		Probed:     true,
		ProbedAt:   now,
		ProbeCount: 1,
		ProbeError: `get https://down.example.net/: dial tcp: lookup down.example.net: no such host`,
	}

	for _, want := range []*Record{full, minimal, failed} {
		if err := s.Update(want.Host, func(r *Record, _ bool) bool { *r = *want; return true }); err != nil {
			t.Fatalf("%s: update: %v", want.Host, err)
		}
		got, err := s.Get(want.Host)
		if err != nil {
			t.Fatalf("%s: get: %v", want.Host, err)
		}
		if got == nil {
			t.Fatalf("%s: not found after write", want.Host)
		}
		if *got != *want {
			t.Errorf("%s round-tripped wrong:\n got %+v\nwant %+v", want.Host, got, want)
		}
	}
}

func TestDerivedFieldsCostNothing(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)

	// A record whose cert name and final URL are both derivable.
	derived := &Record{
		Host: "example.com", CertName: "example.com", Origin: "cn",
		Source: "certstream", FirstSeen: now, LastSeen: now, SeenCount: 1,
		Probed: true, ProbedAt: now, HTTPStatus: 200,
		FinalURL: "https://example.com/", BodySize: 1200,
		BodyHash: strings.Repeat("ab", 32), ProbeCount: 1,
	}
	// The same record with a literal cert name and a redirect target.
	literal := *derived
	literal.Host = "other.com"
	literal.CertName = "san.elsewhere.example"
	literal.FinalURL = "https://elsewhere.example/landing"

	sizes := map[string]int{}
	for _, rec := range []*Record{derived, &literal} {
		r := rec
		if err := s.Update(r.Host, func(x *Record, _ bool) bool { *x = *r; return true }); err != nil {
			t.Fatal(err)
		}
		sizes[r.Host] = s.rawLen(t, r.Host)
	}
	if sizes["example.com"] >= sizes["other.com"] {
		t.Errorf("derived record (%d B) is not smaller than the literal one (%d B)",
			sizes["example.com"], sizes["other.com"])
	}
	// A probed record with a hash should still fit in well under 100 bytes.
	if got := sizes["example.com"]; got > 80 {
		t.Errorf("packed probed record is %d B, want under 80", got)
	}
}

func TestErrorTemplatesAreInterned(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)

	// The same failure for a thousand different hosts is one dictionary entry.
	for i := 0; i < 50; i++ {
		host := "h" + string(rune('a'+i%26)) + strings.Repeat("x", i%5) + ".example.com"
		msg := "get https://" + host + "/: dial tcp: lookup " + host + ": no such host"
		err := s.Update(host, func(r *Record, _ bool) bool {
			r.FirstSeen, r.LastSeen = now, now
			r.Probed, r.ProbedAt, r.ProbeError = true, now, msg
			return true
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := s.errors.len(); n != 1 {
		t.Errorf("error dictionary holds %d entries, want 1", n)
	}

	// And the message still reads back with the right host in it.
	rec, err := s.Get("ha.example.com")
	if err != nil || rec == nil {
		t.Fatalf("get: %v", err)
	}
	if !strings.Contains(rec.ProbeError, "lookup ha.example.com:") {
		t.Errorf("probe error lost its host: %q", rec.ProbeError)
	}
}

func TestForEachUnder(t *testing.T) {
	s := open(t)
	hosts := []string{
		"example.com", "www.example.com", "api.example.com", "deep.api.example.com",
		"notexample.com", "example.com.br", "zebra.com", "example.org",
	}
	for _, h := range hosts {
		if err := s.Update(h, func(r *Record, _ bool) bool { return true }); err != nil {
			t.Fatal(err)
		}
	}

	var got []string
	if err := s.ForEachUnder("example.com", func(r *Record) error {
		got = append(got, r.Host)
		return nil
	}); err != nil {
		t.Fatalf("ForEachUnder: %v", err)
	}
	want := map[string]bool{
		"example.com": true, "www.example.com": true,
		"api.example.com": true, "deep.api.example.com": true,
	}
	if len(got) != len(want) {
		t.Fatalf("ForEachUnder returned %v, want the 4 hosts under example.com", got)
	}
	for _, h := range got {
		if !want[h] {
			t.Errorf("ForEachUnder returned %q, which is not under example.com", h)
		}
	}
}

func TestOpenRejectsLegacyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	writeLegacyDB(t, path, map[string]string{
		"example.com": `{"host":"example.com","cn":"*.example.com","first_seen":"2026-08-21T20:49:54Z"}`,
	})
	if _, err := Open(path); err == nil {
		t.Fatal("Open accepted a legacy database")
	} else if !strings.Contains(err.Error(), "migrate") {
		t.Errorf("error does not point at migration: %v", err)
	}
}

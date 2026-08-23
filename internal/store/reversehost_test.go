package store

import (
	"fmt"
	"strings"
	"testing"
)

// reverseHostSplit is the implementation reverseHost replaced, kept as the
// reference the fast one is checked against.
func reverseHostSplit(host string) string {
	if !strings.Contains(host, ".") {
		return host
	}
	labels := strings.Split(host, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".")
}

// reverseHostCorpus covers the ordinary shapes and the malformed ones a
// certificate can put in front of the store.
var reverseHostCorpus = []string{
	"", ".", "..", "host", "example.com", "www.example.com",
	"a.b.c.d.e.f", "shop.example.co.uk", ".com", "com.",
	"a..b", "..a", "a..", "xn--80ak6aa92e.com",
	strings.Repeat("a.", 60) + "com",
	strings.Repeat("long-label-here.", 12) + "example.com",
}

func TestReverseHostMatchesSplit(t *testing.T) {
	for _, in := range reverseHostCorpus {
		if got, want := reverseHost(in), reverseHostSplit(in); got != want {
			t.Errorf("reverseHost(%q) = %q, want %q", in, got, want)
		}
		if back := reverseHost(reverseHost(in)); back != in {
			t.Errorf("reverseHost is not its own inverse for %q: got %q", in, back)
		}
	}
}

func BenchmarkReverseHost(b *testing.B) {
	for _, host := range []string{"example.com", "www.example.com", "a.b.c.d.e.f"} {
		b.Run(fmt.Sprintf("%d-labels", strings.Count(host, ".")+1), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				sink = reverseHost(host)
			}
		})
	}
}

func BenchmarkReverseHostSplit(b *testing.B) {
	for _, host := range []string{"example.com", "www.example.com", "a.b.c.d.e.f"} {
		b.Run(fmt.Sprintf("%d-labels", strings.Count(host, ".")+1), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				sink = reverseHostSplit(host)
			}
		})
	}
}

var sink string

// FuzzReverseHost checks the fast implementation against the one it replaced.
// These strings become the keys records are stored under, so a disagreement
// would not be a slow store, it would be a lost one.
func FuzzReverseHost(f *testing.F) {
	for _, s := range reverseHostCorpus {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, host string) {
		if got, want := reverseHost(host), reverseHostSplit(host); got != want {
			t.Fatalf("reverseHost(%q) = %q, want %q", host, got, want)
		}
	})
}

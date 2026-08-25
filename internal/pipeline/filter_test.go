package pipeline

import (
	"strings"
	"testing"
	"time"
)

func TestSuffixSetBlocks(t *testing.T) {
	set := NewSuffixSet([]string{"workers.dev", "*.pages.dev", " CHATGPT.site ", "", "."})

	blocked := []string{
		"foo.workers.dev",
		"workers.dev",
		"a.b.workers.dev",
		"tenant.pages.dev",
		"x.chatgpt.site",
	}
	for _, h := range blocked {
		if !set.Blocks(h) {
			t.Errorf("Blocks(%q) = false, want true", h)
		}
	}

	allowed := []string{
		"example.com",
		"notworkers.dev",
		"workers.dev.example.com",
		"dev",
		"pages.dev.co",
	}
	for _, h := range allowed {
		if set.Blocks(h) {
			t.Errorf("Blocks(%q) = true, want false", h)
		}
	}
}

func TestEmptySuffixSetBlocksNothing(t *testing.T) {
	var set SuffixSet
	if set.Blocks("anything.example.com") {
		t.Error("a nil suffix set blocked a host")
	}
	if s := NewSuffixSet([]string{"", "  ", "."}); s != nil {
		t.Errorf("NewSuffixSet of empty entries = %v, want nil", s)
	}
}

func TestParentCapLimitsPerParent(t *testing.T) {
	c := newParentCap(2, time.Hour)
	now := time.Now()

	// The registrable domain itself is always allowed and never charged.
	for i := 0; i < 5; i++ {
		if !c.allow("example.com", now) {
			t.Fatal("the apex was capped")
		}
	}

	if !c.allow("a.example.com", now) || !c.allow("b.example.com", now) {
		t.Fatal("the first two hosts under the cap were rejected")
	}
	if c.allow("c.example.com", now) {
		t.Error("the third host was accepted despite a cap of 2")
	}
	// A different parent has its own budget.
	if !c.allow("a.other.com", now) {
		t.Error("a different parent was charged the first parent's budget")
	}
}

func TestParentCapResetsAfterWindow(t *testing.T) {
	c := newParentCap(1, time.Minute)
	now := time.Now()

	if !c.allow("a.example.com", now) {
		t.Fatal("first host rejected")
	}
	if c.allow("b.example.com", now.Add(30*time.Second)) {
		t.Error("second host accepted inside the window")
	}
	if !c.allow("c.example.com", now.Add(90*time.Second)) {
		t.Error("the window did not reset")
	}
}

func TestNilParentCapAllowsEverything(t *testing.T) {
	var c *parentCap
	if !c.allow("anything.example.com", time.Now()) {
		t.Error("a disabled cap rejected a host")
	}
	if newParentCap(0, time.Hour) != nil {
		t.Error("a cap of 0 should be disabled")
	}
}

func TestParseSuffixList(t *testing.T) {
	raw := `
# a comment
workers.dev
pages.dev   # trailing comment
a.example.com, b.example.com

   # indented comment
`
	got := ParseSuffixList(raw)
	want := []string{"workers.dev", "pages.dev", "a.example.com", "b.example.com"}
	if len(got) != len(want) {
		t.Fatalf("ParseSuffixList = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
	if got := ParseSuffixList(""); got != nil {
		t.Errorf("ParseSuffixList(\"\") = %v, want nil", got)
	}
}

func TestDefaultSkipSuffixes(t *testing.T) {
	entries := DefaultSkipSuffixes()
	if len(entries) < 10 {
		t.Fatalf("built-in blocklist has only %d entries", len(entries))
	}
	set := NewSuffixSet(entries)
	for _, h := range []string{"tenant.workers.dev", "app.pages.dev", "x.vercel.app"} {
		if !set.Blocks(h) {
			t.Errorf("built-in list does not block %q", h)
		}
	}
	if set.Blocks("example.com") {
		t.Error("built-in list blocks example.com")
	}
	for _, e := range entries {
		if strings.ContainsAny(e, " #\t") {
			t.Errorf("entry %q was not cleaned", e)
		}
	}
}

func TestDefaultsAreSane(t *testing.T) {
	if DefaultParentCap <= 0 || DefaultParentWindow <= 0 || DefaultMaxDepth <= 0 {
		t.Error("a default filter is disabled; the CLI advertises them as on")
	}
}

package main

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mvo/ct/internal/source"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestSplitList(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"", nil},
		{",", nil},
		{"   ", nil},
		{"a", []string{"a"}},
		{"a,b", []string{"a", "b"}},
		// A trailing comma is what a shell loop leaves behind, and the
		// entry it implies does not exist.
		{"a,b,", []string{"a", "b"}},
		{" a , b ", []string{"a", "b"}},
		{",,a,,", []string{"a"}},
	}
	for _, c := range cases {
		got := splitList(c.raw)
		if len(got) != len(c.want) {
			t.Errorf("splitList(%q) = %q, want %q", c.raw, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitList(%q) = %q, want %q", c.raw, got, c.want)
				break
			}
		}
	}
}

func TestLoadSkipSuffixesMergesSources(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip.txt")
	body := "# a comment\nfromfile.invalid\n\nalso.invalid, third.invalid # trailing comment\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	set, err := loadSkipSuffixes("inline.invalid, second.invalid,", path, true)
	if err != nil {
		t.Fatalf("loadSkipSuffixes: %v", err)
	}
	for _, host := range []string{
		"tenant.inline.invalid",
		"second.invalid",
		"x.fromfile.invalid",
		"also.invalid",
		"third.invalid",
		// The built-in list is merged in, not replaced.
		"tenant.workers.dev",
	} {
		if !set.Blocks(host) {
			t.Errorf("Blocks(%q) = false, want true", host)
		}
	}
	if set.Blocks("example.com") {
		t.Error("Blocks(\"example.com\") = true, want false")
	}
}

func TestLoadSkipSuffixesWithoutDefaults(t *testing.T) {
	set, err := loadSkipSuffixes("inline.invalid", "", false)
	if err != nil {
		t.Fatalf("loadSkipSuffixes: %v", err)
	}
	if !set.Blocks("tenant.inline.invalid") {
		t.Error("the inline entry did not block")
	}
	if set.Blocks("tenant.workers.dev") {
		t.Error("--default-skip=false still applied the built-in list")
	}
}

// A skip list that cannot be read stops the run. Starting without the
// blocklist that was asked for is the failure this guards.
func TestLoadSkipSuffixesMissingFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.txt")
	set, err := loadSkipSuffixes("", path, true)
	if err == nil {
		t.Fatalf("loadSkipSuffixes with a missing file = %v, want an error", set)
	}
	if set != nil {
		t.Errorf("loadSkipSuffixes returned a set alongside the error: %v", set)
	}
	if !strings.Contains(err.Error(), "read skip list") {
		t.Errorf("error %q does not say which list failed", err)
	}
}

func TestLoadSkipSuffixesEmptyIsNil(t *testing.T) {
	set, err := loadSkipSuffixes("", "", false)
	if err != nil {
		t.Fatalf("loadSkipSuffixes: %v", err)
	}
	if set != nil {
		t.Errorf("loadSkipSuffixes with nothing to skip = %v, want nil", set)
	}
}

func sourceNames(feeds []source.Source) []string {
	names := make([]string, len(feeds))
	for i, f := range feeds {
		names[i] = f.Name()
	}
	return names
}

func TestBuildSourcesSelection(t *testing.T) {
	cases := []struct {
		sources string
		want    []string
	}{
		{"certstream", []string{"certstream"}},
		{"ctlog", []string{"ctlog"}},
		{"both", []string{"certstream", "ctlog"}},
		{"certstream,ctlog", []string{"certstream", "ctlog"}},
		// Naming the same feed twice asks for it once.
		{"both,ctlog", []string{"certstream", "ctlog"}},
		{" certstream , ", []string{"certstream"}},
	}
	for _, c := range cases {
		// An explicit log set keeps discovery, and the network, out of this.
		cfg := feedConfig{sources: c.sources, logURIs: "https://ct.example/log"}
		feeds, err := buildSources(cfg, "ua", nil, discardLogger(), nil)
		if err != nil {
			t.Errorf("buildSources(%q): %v", c.sources, err)
			continue
		}
		got := sourceNames(feeds)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("buildSources(%q) = %q, want %q", c.sources, got, c.want)
		}
	}
}

func TestBuildSourcesRejectsUnknownAndEmpty(t *testing.T) {
	for _, sources := range []string{"", ",", "  ", "ctlogs", "both,nope"} {
		cfg := feedConfig{sources: sources, logURIs: "https://ct.example/log"}
		feeds, err := buildSources(cfg, "ua", nil, discardLogger(), nil)
		if err == nil {
			t.Errorf("buildSources(%q) = %q, want an error", sources, sourceNames(feeds))
		}
	}
}

// --logs names a set explicitly, so nothing goes out to the log list and
// nothing re-reads it later.
func TestBuildSourcesExplicitLogsSkipDiscovery(t *testing.T) {
	cfg := feedConfig{
		sources:    "ctlog",
		logURIs:    "https://a.example/log, https://b.example/log,",
		logRefresh: time.Hour,
		batch:      64,
	}
	feeds, err := buildSources(cfg, "ua", nil, discardLogger(), nil)
	if err != nil {
		t.Fatalf("buildSources: %v", err)
	}
	if len(feeds) != 1 {
		t.Fatalf("buildSources returned %d feeds, want 1", len(feeds))
	}
	ct, ok := feeds[0].(*source.CTLog)
	if !ok {
		t.Fatalf("feed is %T, want *source.CTLog", feeds[0])
	}
	want := []string{"https://a.example/log", "https://b.example/log"}
	if strings.Join(ct.URIs, ",") != strings.Join(want, ",") {
		t.Errorf("URIs = %q, want %q", ct.URIs, want)
	}
	if ct.Discover != nil {
		t.Error("an explicit --logs set still installed a discoverer")
	}
	if ct.BatchSize != cfg.batch {
		t.Errorf("BatchSize = %d, want %d", ct.BatchSize, cfg.batch)
	}
}

// The generation names the re-probe policy a seed ran for. Change the format
// and every existing database walks itself again on the next start.
func TestSeedGenerationFormat(t *testing.T) {
	cases := []struct {
		reprobe time.Duration
		want    string
	}{
		{0, "v1:reprobe=0s"},
		{24 * time.Hour, "v1:reprobe=24h0m0s"},
		{90 * time.Minute, "v1:reprobe=1h30m0s"},
	}
	for _, c := range cases {
		if got := seedGeneration(c.reprobe); got != c.want {
			t.Errorf("seedGeneration(%s) = %q, want %q", c.reprobe, got, c.want)
		}
	}
	if seedGeneration(time.Hour) == seedGeneration(2*time.Hour) {
		t.Error("two re-probe policies share a generation")
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1<<20 - 1, "1024.0 KiB"},
		{1 << 20, "1.0 MiB"},
		{1 << 30, "1.0 GiB"},
		{1 << 40, "1.0 TiB"},
		{1 << 50, "1.0 PiB"},
		{1 << 60, "1.0 EiB"},
		{538 << 20, "538.0 MiB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.n); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestPrintSizes(t *testing.T) {
	var buf bytes.Buffer
	printSizes(&buf, "  ", 4<<20, 2<<20, 8<<20, 8<<20, 1024)
	got := buf.String()
	for _, want := range []string{
		"  in use:  4.0 MiB -> 2.0 MiB",
		"(2.0x smaller)",
		"  on disk: 8.0 MiB -> 8.0 MiB",
		"  4096 B/record -> 2048 B/record",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("printSizes output %q does not contain %q", got, want)
		}
	}
}

// compact reports no record count, and an empty store uses no pages. Neither
// may divide by what it does not have.
func TestPrintSizesWithoutRecords(t *testing.T) {
	var buf bytes.Buffer
	printSizes(&buf, "", 4<<20, 2<<20, 8<<20, 8<<20, 0)
	if strings.Contains(buf.String(), "B/record") {
		t.Errorf("printSizes with no record count reported a per-record size: %q", buf.String())
	}

	buf.Reset()
	printSizes(&buf, "", 0, 0, 32<<10, 32<<10, 10)
	got := buf.String()
	if strings.Contains(got, "smaller") || strings.Contains(got, "B/record") {
		t.Errorf("printSizes over an empty store divided by zero: %q", got)
	}
	if !strings.Contains(got, "in use:  0 B -> 0 B") {
		t.Errorf("printSizes over an empty store = %q", got)
	}
}

func TestWaited(t *testing.T) {
	if got := waited(time.Now().Add(time.Hour)); got != "not due yet" {
		t.Errorf("waited(future) = %q, want %q", got, "not due yet")
	}
	if got := waited(time.Now().Add(-90 * time.Second)); got != "1m30s" {
		t.Errorf("waited(90s ago) = %q, want %q", got, "1m30s")
	}
}

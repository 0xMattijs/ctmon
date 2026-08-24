package source

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

// day is the unit the shard intervals in these tests are written in.
const day = 24 * time.Hour

// usableLog builds one usable, sharded log covering [start, end).
func usableLog(url string, start, end time.Time) *loglist3.Log {
	return &loglist3.Log{
		URL:              url,
		State:            &loglist3.LogStates{Usable: &loglist3.LogState{}},
		TemporalInterval: &loglist3.TemporalInterval{StartInclusive: start, EndExclusive: end},
	}
}

// shardedList is a list of one operator running the shards given.
func shardedList(logs ...*loglist3.Log) *loglist3.LogList {
	return &loglist3.LogList{
		Operators: []*loglist3.Operator{{Name: "Test", Logs: logs}},
	}
}

// TestSelectFollowsTheShardCertificatesLandIn is the point of the lookahead: a
// certificate issued today expires up to a validity period from now and is
// logged to the shard covering that date, so the successor shard is taking
// certificates months before its interval opens.
func TestSelectFollowsTheShardCertificatesLandIn(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	ll := shardedList(
		usableLog("https://ct.example/2026h2", now.Add(-60*day), now.Add(130*day)),
		usableLog("https://ct.example/2027h1", now.Add(130*day), now.Add(311*day)),
	)

	got := selectLogs(ll, now, 200*day)
	want := []string{"https://ct.example/2026h2", "https://ct.example/2027h1"}
	if !slices.Equal(got, want) {
		t.Fatalf("selectLogs = %v, want %v", got, want)
	}
}

// TestSelectStopsAtTheLookahead keeps the window from swallowing every future
// shard on the list. A shard that opens after the longest certificate issued
// today can expire is taking nothing, and following it is a get-sth per poll
// for no entries.
func TestSelectStopsAtTheLookahead(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	ll := shardedList(
		usableLog("https://ct.example/2027h1", now.Add(130*day), now.Add(311*day)),
		usableLog("https://ct.example/2027h2", now.Add(311*day), now.Add(494*day)),
	)

	got := selectLogs(ll, now, 200*day)
	want := []string{"https://ct.example/2027h1"}
	if !slices.Equal(got, want) {
		t.Fatalf("selectLogs = %v, want %v", got, want)
	}
}

// TestSelectDropsAShardThatEnded covers the other edge: whatever a shard took
// while it was open, it takes nothing once its interval has passed.
func TestSelectDropsAShardThatEnded(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	ll := shardedList(
		usableLog("https://ct.example/2026h1", now.Add(-240*day), now.Add(-60*day)),
		usableLog("https://ct.example/2026h2", now.Add(-60*day), now.Add(130*day)),
	)

	got := selectLogs(ll, now, 200*day)
	want := []string{"https://ct.example/2026h2"}
	if !slices.Equal(got, want) {
		t.Fatalf("selectLogs = %v, want %v", got, want)
	}
}

// TestSelectIsHalfOpenAtBothEnds pins the boundaries the interval names:
// StartInclusive is in the window and EndExclusive is out of it, so the two
// shards meeting at an instant are never both live and never both dead.
func TestSelectIsHalfOpenAtBothEnds(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	boundary := now.Add(200 * day)
	ll := shardedList(
		usableLog("https://ct.example/ends-now", now.Add(-day), now),
		usableLog("https://ct.example/opens-at-the-edge", boundary, boundary.Add(180*day)),
	)

	got := selectLogs(ll, now, 200*day)
	want := []string{"https://ct.example/opens-at-the-edge"}
	if !slices.Equal(got, want) {
		t.Fatalf("selectLogs = %v, want %v", got, want)
	}
}

// TestSelectKeepsAnUnshardedLog covers a log with no temporal interval, which
// accepts any NotAfter and so is always current.
func TestSelectKeepsAnUnshardedLog(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	ll := shardedList(&loglist3.Log{
		URL:   "https://ct.example/all",
		State: &loglist3.LogStates{Usable: &loglist3.LogState{}},
	})

	got := selectLogs(ll, now, 200*day)
	want := []string{"https://ct.example/all"}
	if !slices.Equal(got, want) {
		t.Fatalf("selectLogs = %v, want %v", got, want)
	}
}

// TestSelectSkipsLogsThatAreNotUsable keeps the status filter honest: a shard
// whose interval is live is still no use if Chrome has retired it.
func TestSelectSkipsLogsThatAreNotUsable(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	retired := usableLog("https://ct.example/retired", now.Add(-60*day), now.Add(130*day))
	retired.State = &loglist3.LogStates{Retired: &loglist3.LogState{}}
	ll := shardedList(retired,
		usableLog("https://ct.example/2026h2", now.Add(-60*day), now.Add(130*day)))

	got := selectLogs(ll, now, 200*day)
	want := []string{"https://ct.example/2026h2"}
	if !slices.Equal(got, want) {
		t.Fatalf("selectLogs = %v, want %v", got, want)
	}
}

// TestSelectDefaultsTheLookahead means a caller passing nothing gets the
// window the constant describes, not a point filter that misses the successor.
func TestSelectDefaultsTheLookahead(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	next := usableLog("https://ct.example/next", now.Add(DefaultShardLookahead-day), now.Add(400*day))
	ll := shardedList(next)

	if got := selectLogs(ll, now, 0); !slices.Equal(got, []string{"https://ct.example/next"}) {
		t.Fatalf("selectLogs with no lookahead = %v, want the successor shard", got)
	}
}

// TestDiscoverLogsReadsTheList covers the fetch-and-parse path around the
// selection rule, over the wire format the real list is served in.
func TestDiscoverLogsReadsTheList(t *testing.T) {
	now := time.Now()
	body, err := json.Marshal(shardedList(
		usableLog("https://ct.example/current", now.Add(-60*day), now.Add(130*day)),
		usableLog("https://ct.example/ended", now.Add(-240*day), now.Add(-60*day)),
	))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	got, err := DiscoverLogs(context.Background(), srv.Client(), srv.URL, DefaultShardLookahead)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"https://ct.example/current"}) {
		t.Fatalf("DiscoverLogs = %v, want the current shard only", got)
	}
}

// TestDiscoverLogsRefusesAnEmptyResult is what tells a startup that its list
// URL is wrong. Returning no logs and no error would leave the feed silently
// following nothing.
func TestDiscoverLogsRefusesAnEmptyResult(t *testing.T) {
	now := time.Now()
	body, err := json.Marshal(shardedList(
		usableLog("https://ct.example/ended", now.Add(-240*day), now.Add(-60*day)),
	))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	_, err = DiscoverLogs(context.Background(), srv.Client(), srv.URL, DefaultShardLookahead)
	if err == nil || !strings.Contains(err.Error(), "no logs accepting certificates") {
		t.Fatalf("DiscoverLogs error = %v, want a complaint about an empty list", err)
	}
}

// TestDiscoverLogsRejectsABadStatus stops a proxy's error page or a moved URL
// from being parsed as a log list.
func TestDiscoverLogsRejectsABadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := DiscoverLogs(context.Background(), srv.Client(), srv.URL, 0); err == nil {
		t.Fatal("DiscoverLogs accepted a 404 response")
	}
}

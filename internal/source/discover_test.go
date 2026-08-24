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
	if !slices.Equal(got.RFC6962, want) {
		t.Fatalf("selectLogs = %v, want %v", got.RFC6962, want)
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
	if !slices.Equal(got.RFC6962, want) {
		t.Fatalf("selectLogs = %v, want %v", got.RFC6962, want)
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
	if !slices.Equal(got.RFC6962, want) {
		t.Fatalf("selectLogs = %v, want %v", got.RFC6962, want)
	}
}

// TestSelectPinsBothBoundaries fixes which side of each edge is in. A shard
// whose EndExclusive is exactly now is out, because the interval is half-open
// and nothing issued now can expire before it. A shard opening exactly at the
// lookahead is in, because a certificate issued now with the full validity
// period expires exactly then.
//
// Adjacent shards being both live is the point of the lookahead, not a
// violation of it — see TestSelectFollowsTheShardCertificatesLandIn.
func TestSelectPinsBothBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	boundary := now.Add(200 * day)
	ll := shardedList(
		usableLog("https://ct.example/ends-now", now.Add(-day), now),
		usableLog("https://ct.example/opens-at-the-edge", boundary, boundary.Add(180*day)),
	)

	got := selectLogs(ll, now, 200*day)
	want := []string{"https://ct.example/opens-at-the-edge"}
	if !slices.Equal(got.RFC6962, want) {
		t.Fatalf("selectLogs = %v, want %v", got.RFC6962, want)
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
	if !slices.Equal(got.RFC6962, want) {
		t.Fatalf("selectLogs = %v, want %v", got.RFC6962, want)
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
	if !slices.Equal(got.RFC6962, want) {
		t.Fatalf("selectLogs = %v, want %v", got.RFC6962, want)
	}
}

// TestSelectTakesZeroLookaheadLiterally keeps zero meaning what it means on
// every other duration this program takes. Promoting it to the default would
// answer an operator asking for the cheapest window with the widest one there
// is, and double the requests they were trying to avoid.
func TestSelectTakesZeroLookaheadLiterally(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	ll := shardedList(
		usableLog("https://ct.example/open-now", now.Add(-60*day), now.Add(130*day)),
		usableLog("https://ct.example/next", now.Add(130*day), now.Add(311*day)),
	)

	for _, lookahead := range []time.Duration{0, -day} {
		got := selectLogs(ll, now, lookahead)
		want := []string{"https://ct.example/open-now"}
		if !slices.Equal(got.RFC6962, want) {
			t.Errorf("selectLogs with lookahead %v = %v, want %v", lookahead, got.RFC6962, want)
		}
	}
}

// TestSelectAtTheDefaultLookahead is the constant doing its job: at the
// shipped window the successor shard is followed, which is the whole point of
// the change.
func TestSelectAtTheDefaultLookahead(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	ll := shardedList(usableLog("https://ct.example/next",
		now.Add(DefaultShardLookahead-day), now.Add(400*day)))

	got := selectLogs(ll, now, DefaultShardLookahead)
	if !slices.Equal(got.RFC6962, []string{"https://ct.example/next"}) {
		t.Fatalf("selectLogs at the default lookahead = %v, want the successor shard", got.RFC6962)
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
	if !slices.Equal(got.RFC6962, []string{"https://ct.example/current"}) {
		t.Fatalf("DiscoverLogs = %v, want the current shard only", got.RFC6962)
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

// usableTiled builds one usable, sharded Static CT API log covering
// [start, end). The monitoring URL is the one a monitor reads; the submission
// URL is set to something else on purpose, so a test that picked the wrong
// field would say so.
func usableTiled(monitor string, start, end time.Time) *loglist3.TiledLog {
	return &loglist3.TiledLog{
		MonitoringURL:    monitor,
		SubmissionURL:    strings.Replace(monitor, "mon.", "submit.", 1),
		State:            &loglist3.LogStates{Usable: &loglist3.LogState{}},
		TemporalInterval: &loglist3.TemporalInterval{StartInclusive: start, EndExclusive: end},
	}
}

// TestSelectReadsTiledLogsToo is the point of splitting the result: Google's
// v3 list carries two kinds of log per operator, and a monitor that walks only
// the first kind is blind to every log the second holds.
func TestSelectReadsTiledLogsToo(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	ll := &loglist3.LogList{Operators: []*loglist3.Operator{{
		Name: "Test",
		Logs: []*loglist3.Log{usableLog("https://ct.example/2026h2", now.Add(-60*day), now.Add(130*day))},
		TiledLogs: []*loglist3.TiledLog{
			usableTiled("https://mon.ct.example/2026h2/", now.Add(-60*day), now.Add(130*day)),
		},
	}}}

	got := selectLogs(ll, now, 200*day)
	if !slices.Equal(got.RFC6962, []string{"https://ct.example/2026h2"}) {
		t.Errorf("RFC6962 = %v", got.RFC6962)
	}
	if !slices.Equal(got.Tiled, []string{"https://mon.ct.example/2026h2/"}) {
		t.Errorf("Tiled = %v, want the monitoring URL", got.Tiled)
	}
}

// TestSelectJudgesTiledLogsByTheSameRule keeps the two kinds honest against
// each other. Status and the temporal window decide which logs are worth
// following, and they say the same thing whichever protocol the log speaks.
func TestSelectJudgesTiledLogsByTheSameRule(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	retired := usableTiled("https://mon.ct.example/retired/", now.Add(-60*day), now.Add(130*day))
	retired.State = &loglist3.LogStates{Retired: &loglist3.LogState{}}
	ll := &loglist3.LogList{Operators: []*loglist3.Operator{{
		Name: "Test",
		TiledLogs: []*loglist3.TiledLog{
			retired,
			usableTiled("https://mon.ct.example/ended/", now.Add(-240*day), now.Add(-60*day)),
			usableTiled("https://mon.ct.example/too-far-out/", now.Add(311*day), now.Add(494*day)),
			usableTiled("https://mon.ct.example/2027h1/", now.Add(130*day), now.Add(311*day)),
		},
	}}}

	got := selectLogs(ll, now, 200*day)
	if !slices.Equal(got.Tiled, []string{"https://mon.ct.example/2027h1/"}) {
		t.Errorf("Tiled = %v, want only the shard that is live and usable", got.Tiled)
	}
}

// TestSelectKeepsAnOperatorWithOnlyTiledLogs is the trap in
// loglist3.SelectByStatus, which this package deliberately does not use: it
// filters Logs, copies TiledLogs through untouched, and drops any operator
// left holding no usable RFC 6962 log at all. An operator who has moved every
// shard to Static CT — which is the direction the whole ecosystem is going —
// would disappear from the list entirely.
func TestSelectKeepsAnOperatorWithOnlyTiledLogs(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	ll := &loglist3.LogList{Operators: []*loglist3.Operator{{
		Name: "Tiles only",
		TiledLogs: []*loglist3.TiledLog{
			usableTiled("https://mon.ct.example/2026h2/", now.Add(-60*day), now.Add(130*day)),
		},
	}}}

	got := selectLogs(ll, now, 200*day)
	if !slices.Equal(got.Tiled, []string{"https://mon.ct.example/2026h2/"}) {
		t.Errorf("Tiled = %v, want the operator's log", got.Tiled)
	}
}

// TestDiscoverLogsRefusesAnEmptyResult already covers a list with nothing on
// it. This is the other half: a list with no usable RFC 6962 logs left is not
// empty if it still has tiled ones, and failing there would turn the ecosystem
// finishing its move to Static CT into a startup error.
func TestDiscoverLogsAcceptsATiledOnlyList(t *testing.T) {
	now := time.Now()
	body, err := json.Marshal(&loglist3.LogList{Operators: []*loglist3.Operator{{
		Name: "Tiles only",
		TiledLogs: []*loglist3.TiledLog{
			usableTiled("https://mon.ct.example/2026h2/", now.Add(-60*day), now.Add(130*day)),
		},
	}}})
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
	if len(got.RFC6962) != 0 {
		t.Errorf("RFC6962 = %v, want none", got.RFC6962)
	}
	if !slices.Equal(got.Tiled, []string{"https://mon.ct.example/2026h2/"}) {
		t.Errorf("Tiled = %v", got.Tiled)
	}
}

package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mvo/ct/internal/domain"
	"github.com/mvo/ct/internal/probe"
	"github.com/mvo/ct/internal/source"
	"github.com/mvo/ct/internal/store"
)

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// testRig is a pipeline wired to a temp store and an HTTPS server that every
// probe reaches regardless of hostname.
type testRig struct {
	pipe *Pipeline
	db   *store.Store
	body *atomic.Value // string
}

func newRig(t *testing.T) *testRig {
	t.Helper()

	body := &atomic.Value{}
	body.Store("<html>one</html>")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body.Load().(string))
	}))
	t.Cleanup(srv.Close)

	addr := srv.Listener.Addr().String()
	p := probe.New(probe.Options{
		RequestsPerSecond: 1000,
		Burst:             100,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	})

	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	return &testRig{
		// Backfill is set because the pending queue only fills when something
		// is going to drain it, which is the normal configuration.
		pipe: &Pipeline{
			Store: db, Prober: p, Log: discardLog(),
			Workers: 4, Backfill: time.Minute,
		},
		db:   db,
		body: body,
	}
}

// feed runs the pipeline over certs and returns when everything is stored.
func (r *testRig) feed(t *testing.T, certs ...source.Cert) {
	t.Helper()
	in := make(chan source.Cert, len(certs))
	for _, c := range certs {
		in <- c
	}
	close(in)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r.pipe.Run(ctx, in)
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestWildcardStoresApexAndWWW(t *testing.T) {
	rig := newRig(t)
	rig.feed(t, source.Cert{
		CN:     "*.example.test",
		Issuer: "Test CA",
		SeenAt: time.Now().UTC(),
		Source: "unit-test",
		Index:  -1,
	})

	want := hashOf(rig.body.Load().(string))
	for _, host := range []string{"example.test", "www.example.test"} {
		rec, err := rig.db.Get(host)
		if err != nil {
			t.Fatalf("get %s: %v", host, err)
		}
		if rec == nil {
			t.Fatalf("%s was not stored", host)
		}
		if rec.CertName != "*.example.test" || !rec.FromWildcard {
			t.Errorf("%s: cert_name=%q wildcard=%v", host, rec.CertName, rec.FromWildcard)
		}
		if rec.HTTPStatus != 200 {
			t.Errorf("%s: status = %d", host, rec.HTTPStatus)
		}
		if rec.BodyHash != want {
			t.Errorf("%s: hash = %s, want %s", host, rec.BodyHash, want)
		}
		if rec.Issuer != "Test CA" {
			t.Errorf("%s: issuer = %q", host, rec.Issuer)
		}
	}

	if got := rig.pipe.Stats().New.Load(); got != 2 {
		t.Errorf("new = %d, want 2", got)
	}
}

func TestPlainCNStoresOneHost(t *testing.T) {
	rig := newRig(t)
	rig.feed(t, source.Cert{CN: "shop.example.test", SeenAt: time.Now().UTC()})

	if rec, _ := rig.db.Get("shop.example.test"); rec == nil {
		t.Fatal("shop.example.test was not stored")
	}
	if rec, _ := rig.db.Get("www.shop.example.test"); rec != nil {
		t.Error("a www host was invented for a non-wildcard CN")
	}
}

func TestUnusableCNIsSkipped(t *testing.T) {
	rig := newRig(t)
	rig.feed(t,
		source.Cert{CN: "DigiCert Global Root CA", SeenAt: time.Now().UTC()},
		source.Cert{CN: "192.0.2.10", SeenAt: time.Now().UTC()},
	)
	if got := rig.pipe.Stats().Skipped.Load(); got != 2 {
		t.Errorf("skipped = %d, want 2", got)
	}
	n := 0
	rig.db.ForEach(func(*store.Record) error { n++; return nil })
	if n != 0 {
		t.Errorf("%d records stored for unusable CNs", n)
	}
}

func TestReprobeDetectsBodyChange(t *testing.T) {
	rig := newRig(t)
	cert := source.Cert{CN: "change.test", SeenAt: time.Now().UTC()}

	rig.feed(t, cert)
	first := hashOf(rig.body.Load().(string))
	rec, _ := rig.db.Get("change.test")
	if rec.BodyHash != first {
		t.Fatalf("first hash = %s, want %s", rec.BodyHash, first)
	}

	// Serve something else and re-run with re-probing on.
	rig.body.Store("<html>two</html>")
	rig.pipe.Reprobe = time.Nanosecond
	rig.feed(t, cert)

	second := hashOf("<html>two</html>")
	rec, _ = rig.db.Get("change.test")
	if rec.BodyHash != second {
		t.Errorf("second hash = %s, want %s", rec.BodyHash, second)
	}
	if rec.PrevHash != first {
		t.Errorf("prev hash = %s, want %s", rec.PrevHash, first)
	}
	if rec.ChangedAt.IsZero() {
		t.Error("ChangedAt was not set")
	}
	if rec.SeenCount != 2 || rec.ProbeCount != 2 {
		t.Errorf("counts: seen=%d probe=%d, want 2 and 2", rec.SeenCount, rec.ProbeCount)
	}
	if got := rig.pipe.Stats().Changed.Load(); got != 1 {
		t.Errorf("changed = %d, want 1", got)
	}
}

func TestKnownHostIsNotReprobedByDefault(t *testing.T) {
	rig := newRig(t)
	cert := source.Cert{CN: "stable.test", SeenAt: time.Now().UTC()}
	rig.feed(t, cert)
	rig.feed(t, cert)

	rec, _ := rig.db.Get("stable.test")
	if rec.ProbeCount != 1 {
		t.Errorf("probe count = %d, want 1", rec.ProbeCount)
	}
	if rec.SeenCount != 2 {
		t.Errorf("seen count = %d, want 2", rec.SeenCount)
	}
}

func TestNoProbeStoresWithoutFetching(t *testing.T) {
	rig := newRig(t)
	rig.pipe.NoProbe = true
	rig.feed(t, source.Cert{CN: "quiet.test", SeenAt: time.Now().UTC()})

	rec, _ := rig.db.Get("quiet.test")
	if rec == nil {
		t.Fatal("host was not stored")
	}
	if rec.Probed || rec.BodyHash != "" {
		t.Errorf("host was probed despite NoProbe: %+v", rec)
	}
}

func TestDuplicateHostsAreSquashed(t *testing.T) {
	rig := newRig(t)
	cert := source.Cert{CN: "dup.test", SeenAt: time.Now().UTC()}
	rig.feed(t, cert, cert, cert)

	if got := rig.pipe.Stats().Dup.Load(); got != 2 {
		t.Errorf("dup = %d, want 2", got)
	}
	rec, _ := rig.db.Get("dup.test")
	if rec.SeenCount != 1 {
		t.Errorf("seen count = %d, want 1 (duplicates never reached the store)", rec.SeenCount)
	}
}

func TestDeferredProbeStillStoresTheDomain(t *testing.T) {
	rig := newRig(t)
	full := make(chan string) // unbuffered with no reader: every send is shed

	rig.pipe.record(context.Background(), nameSeen{
		name: domain.Name{Host: "shed.test"},
		cert: source.Cert{CN: "shed.test", SeenAt: time.Now().UTC()},
	}, full)

	rec, err := rig.db.Get("shed.test")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if rec == nil {
		t.Fatal("domain was lost when the probe queue was full")
	}
	if rec.Probed {
		t.Error("record claims it was probed")
	}
	if got := rig.pipe.Stats().Deferred.Load(); got != 1 {
		t.Errorf("deferred = %d, want 1", got)
	}
}

// queue records a host and puts it on the pending queue, the way record does.
func queue(t *testing.T, db *store.Store, host string, at time.Time, fn func(*store.Record)) {
	t.Helper()
	err := db.UpdateWithQueue(host, func(r *store.Record, _ bool) (bool, time.Time) {
		if fn != nil {
			fn(r)
		}
		return true, at
	})
	if err != nil {
		t.Fatal(err)
	}
}

// hosts names the hosts in a batch of queue entries.
func hosts(items []store.Pending) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.Host
	}
	return out
}

// drain collects the hosts a sweep queued.
func drain(ch chan store.Pending) []string {
	close(ch)
	var got []string
	for item := range ch {
		got = append(got, item.Host)
	}
	return got
}

func TestSweepQueuesPendingHosts(t *testing.T) {
	rig := newRig(t)

	// Two hosts recorded but never probed, one already done. All three are on
	// the queue: the fast path leaves an entry behind even when it probes the
	// host itself, and dropping those is the sweep's job.
	now := time.Now().UTC()
	queue(t, rig.db, "pending-a.test", now.Add(-2*time.Minute), nil)
	queue(t, rig.db, "pending-b.test", now.Add(-time.Minute), nil)
	queue(t, rig.db, "done.test", now.Add(-3*time.Minute), func(r *store.Record) {
		r.Probed = true
		r.ProbedAt = now
		r.BodyHash = hashOf("abc")
	})

	probes := make(chan store.Pending, 8)
	rig.pipe.sweep(context.Background(), probes)

	got := drain(probes)
	if len(got) != 2 || got[0] != "pending-a.test" || got[1] != "pending-b.test" {
		t.Errorf("sweep queued %v, want the two pending hosts", got)
	}
	if n := rig.pipe.Stats().Backfilled.Load(); n != 2 {
		t.Errorf("backfilled = %d, want 2", n)
	}
	// The probed host's entry is gone rather than left to come round again.
	if n, _, err := rig.db.PendingStats(); err != nil {
		t.Fatal(err)
	} else if n != 2 {
		t.Errorf("queue holds %d entries, want the 2 still owed a probe", n)
	}
}

// The old sweep scanned the domain bucket from the top every time, so the
// backlog drained in reversed-hostname order and names late in that order
// waited behind every earlier one. The queue is ordered by how long a host has
// waited, which is the order that has anything to do with the monitor's job.
func TestSweepTakesTheLongestWaitingFirst(t *testing.T) {
	rig := newRig(t)
	now := time.Now().UTC()
	// Alphabetically first, queued last.
	queue(t, rig.db, "aaa.test", now.Add(-time.Minute), nil)
	queue(t, rig.db, "zzz.test", now.Add(-time.Hour), nil)
	rig.pipe.BackfillBatch = 1

	probes := make(chan store.Pending, 4)
	rig.pipe.sweep(context.Background(), probes)

	if got := drain(probes); len(got) != 1 || got[0] != "zzz.test" {
		t.Errorf("sweep queued %v, want the host that has waited longest", got)
	}
}

// A host that is not due yet stays put, which is what holds a deferred probe
// back and what spaces out re-probes.
func TestSweepLeavesHostsThatAreNotDue(t *testing.T) {
	rig := newRig(t)
	queue(t, rig.db, "later.test", time.Now().UTC().Add(time.Hour), nil)

	probes := make(chan store.Pending, 4)
	rig.pipe.sweep(context.Background(), probes)

	if got := drain(probes); len(got) != 0 {
		t.Errorf("sweep queued %v, want nothing due yet", got)
	}
}

func TestSweepRespectsBatchLimit(t *testing.T) {
	rig := newRig(t)
	now := time.Now().UTC()
	for i, h := range []string{"a.test", "b.test", "c.test"} {
		queue(t, rig.db, h, now.Add(-time.Duration(i)*time.Minute), nil)
	}
	rig.pipe.BackfillBatch = 2

	probes := make(chan store.Pending, 8)
	rig.pipe.sweep(context.Background(), probes)

	if n := len(drain(probes)); n != 2 {
		t.Errorf("sweep queued %d hosts, want the 2-host batch limit", n)
	}
}

func TestSweepReprobesStaleHosts(t *testing.T) {
	rig := newRig(t)
	stale := func() {
		queue(t, rig.db, "old.test", time.Now().UTC().Add(-time.Minute), func(r *store.Record) {
			r.Probed = true
			r.ProbedAt = time.Now().Add(-time.Hour).UTC()
			r.BodyHash = hashOf("abc")
		})
	}

	stale()
	probes := make(chan store.Pending, 4)
	rig.pipe.sweep(context.Background(), probes) // Reprobe is 0: nothing is stale
	if got := drain(probes); len(got) != 0 {
		t.Fatalf("sweep queued %v with re-probing disabled", got)
	}

	stale()
	rig.pipe.Reprobe = time.Minute
	probes = make(chan store.Pending, 4)
	rig.pipe.sweep(context.Background(), probes)
	if got := drain(probes); len(got) != 1 || got[0] != "old.test" {
		t.Errorf("sweep queued %v, want [old.test]", got)
	}
}

// fixedResolver answers every lookup with the same address, so a test can
// drive the per-address budget without a nameserver.
type fixedResolver []netip.Addr

func (r fixedResolver) Lookup(context.Context, string) ([]netip.Addr, error) {
	return r, nil
}

func (fixedResolver) Healthy() bool { return true }

// A deferred probe writes nothing about the host and puts it back on the queue
// for later: nothing was asked, so there is nothing to record.
func TestDeferredProbeRequeuesInsteadOfRecording(t *testing.T) {
	rig := newRig(t)
	rig.pipe.DeferBackoff = time.Millisecond
	rig.pipe.Prober = probe.New(probe.Options{
		PerIPRPS:   1,
		PerIPBurst: 1,
		Resolver:   fixedResolver{netip.MustParseAddr("192.0.2.1")},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial refused by the test")
		},
	})
	queue(t, rig.db, "busy.test", time.Now().UTC().Add(-time.Hour), nil)

	rig.pipe.probe(context.Background(), "busy.test") // spends the burst
	rig.pipe.probe(context.Background(), "busy.test")
	if n := rig.pipe.Stats().Throttled.Load(); n != 1 {
		t.Errorf("throttled = %d, want 1", n)
	}
	if n := rig.pipe.Stats().Probed.Load(); n != 1 {
		t.Errorf("probed = %d, want only the probe that went through", n)
	}
	// The deferral left no mark on the record: nothing was asked of the host.
	rec, err := rig.db.Get("busy.test")
	if err != nil {
		t.Fatal(err)
	}
	if rec.ProbeCount != 1 {
		t.Errorf("probe_count = %d, want 1", rec.ProbeCount)
	}

	// The host is back on the queue, and the deferral left no mark on it.
	time.Sleep(5 * time.Millisecond)
	got, err := rig.db.PendingLease(time.Now().UTC(), 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("a deferred host was dropped rather than queued again")
	}
}

// The record and its queue entry are written together, so a host that wants a
// probe is always one the queue knows about — whatever happens next.
func TestRecordQueuesEveryHostThatWantsAProbe(t *testing.T) {
	rig := newRig(t)
	// A full fresh queue is the case that used to lose work: the host stayed
	// unprobed and only a scan of the whole store would find it again.
	full := make(chan string)
	rig.pipe.record(context.Background(), nameSeen{
		name: domain.Name{Host: "shed.test", From: "shed.test", Origin: domain.OriginCN},
		cert: source.Cert{CN: "shed.test", SeenAt: time.Now().UTC()},
	}, full)

	if n := rig.pipe.Stats().Deferred.Load(); n != 1 {
		t.Errorf("deferred = %d, want the shed probe counted", n)
	}
	got, err := rig.db.PendingLease(time.Now().UTC().Add(time.Second), 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Host != "shed.test" {
		t.Errorf("queue holds %v, want [shed.test]", hosts(got))
	}
}

// With re-probing on, finishing a probe schedules the next one. Nothing else
// does: without this a host would be fetched once and never looked at again.
func TestProbeSchedulesTheNextOne(t *testing.T) {
	rig := newRig(t)
	rig.pipe.Reprobe = time.Hour
	// Recorded but not queued, so the only entry afterwards is the one the
	// probe itself schedules.
	if err := rig.db.Update("seen.test", func(*store.Record, bool) bool { return true }); err != nil {
		t.Fatal(err)
	}

	rig.pipe.probe(context.Background(), "seen.test")

	n, oldest, err := rig.db.PendingStats()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("queue holds %d entries after a probe, want the one re-probe", n)
	}
	if wait := time.Until(oldest); wait < 30*time.Minute {
		t.Errorf("next probe due in %v, want about the one-hour re-probe interval", wait)
	}
}

// Without a sweep nothing takes entries out of the queue, so nothing should
// put them in: the bucket would otherwise grow by every hostname ever seen.
func TestNoBackfillMeansNoQueue(t *testing.T) {
	rig := newRig(t)
	rig.pipe.Backfill = 0

	rig.pipe.record(context.Background(), nameSeen{
		name: domain.Name{Host: "unswept.test", From: "unswept.test", Origin: domain.OriginCN},
		cert: source.Cert{CN: "unswept.test", SeenAt: time.Now().UTC()},
	}, make(chan string, 1))

	if rec, err := rig.db.Get("unswept.test"); err != nil || rec == nil {
		t.Fatalf("host = %v, %v; want it recorded regardless", rec, err)
	}
	if n, _, err := rig.db.PendingStats(); err != nil {
		t.Fatal(err)
	} else if n != 0 {
		t.Errorf("queue holds %d entries with the sweep off, want none", n)
	}
}

// A result that never reached the store leaves the record saying unprobed. The
// probe reports itself unsettled so the caller keeps the lease: releasing it
// would drop the host from the queue as well, and nothing would look at it
// again.
func TestProbeIsUnsettledWhenTheStoreWriteFails(t *testing.T) {
	rig := newRig(t)
	queue(t, rig.db, "host.test", time.Now().UTC().Add(-time.Hour), nil)

	// A closed store fails every write, which is the shape of the case worth
	// worrying about.
	if err := rig.db.Close(); err != nil {
		t.Fatal(err)
	}
	if rig.pipe.probe(context.Background(), "host.test") {
		t.Error("probe called itself settled after the store write failed")
	}
}

// A record that has been deleted is settled, not failed: it was removed on
// purpose, so its queue entry should go too rather than come round for ever.
func TestProbeSettlesAHostWhoseRecordIsGone(t *testing.T) {
	rig := newRig(t)
	if !rig.pipe.probe(context.Background(), "never-recorded.test") {
		t.Error("probe of an absent record was unsettled, want the entry released")
	}
}

func TestMaxDepthDropsDeepHosts(t *testing.T) {
	rig := newRig(t)
	rig.pipe.MaxDepth = 1
	rig.pipe.NoProbe = true
	rig.feed(t,
		source.Cert{CN: "example.test", SeenAt: time.Now().UTC()},
		source.Cert{CN: "www.example.test", SeenAt: time.Now().UTC()},
		source.Cert{CN: "deep.sub.example.test", SeenAt: time.Now().UTC()},
		source.Cert{CN: "a.b.c.example.test", SeenAt: time.Now().UTC()},
	)

	for _, host := range []string{"example.test", "www.example.test"} {
		if rec, _ := rig.db.Get(host); rec == nil {
			t.Errorf("%s (within the depth limit) was dropped", host)
		}
	}
	for _, host := range []string{"deep.sub.example.test", "a.b.c.example.test"} {
		if rec, _ := rig.db.Get(host); rec != nil {
			t.Errorf("%s was stored despite exceeding the depth limit", host)
		}
	}
	if got := rig.pipe.Stats().TooDeep.Load(); got != 2 {
		t.Errorf("too_deep = %d, want 2", got)
	}
}

func TestMaxDepthCountsBelowTheRegistrableDomain(t *testing.T) {
	rig := newRig(t)
	rig.pipe.MaxDepth = 1
	rig.pipe.NoProbe = true
	// Four labels, but only one level of nesting under example.co.uk.
	rig.feed(t, source.Cert{CN: "www.example.co.uk", SeenAt: time.Now().UTC()})

	if rec, _ := rig.db.Get("www.example.co.uk"); rec == nil {
		t.Error("www.example.co.uk was dropped; depth counted dots, not nesting")
	}
}

func TestWildcardExpansionRespectsMaxDepth(t *testing.T) {
	rig := newRig(t)
	rig.pipe.MaxDepth = 1
	rig.pipe.NoProbe = true
	// The apex sits at depth 1 and is kept; the www form would be depth 2.
	rig.feed(t, source.Cert{CN: "*.sub.example.test", SeenAt: time.Now().UTC()})

	if rec, _ := rig.db.Get("sub.example.test"); rec == nil {
		t.Error("wildcard apex was dropped")
	}
	if rec, _ := rig.db.Get("www.sub.example.test"); rec != nil {
		t.Error("www form was stored despite exceeding the depth limit")
	}
}

func TestPublicSuffixIsNeverStored(t *testing.T) {
	rig := newRig(t)
	rig.pipe.NoProbe = true // MaxDepth stays 0: no limit
	rig.feed(t, source.Cert{CN: "*.co.uk", SeenAt: time.Now().UTC()})

	if rec, _ := rig.db.Get("co.uk"); rec != nil {
		t.Error("co.uk was stored, but a public suffix is not an owned domain")
	}
	if rec, _ := rig.db.Get("www.co.uk"); rec == nil {
		t.Error("www.co.uk is registrable and should have been stored")
	}
}

func TestSANsAreStored(t *testing.T) {
	rig := newRig(t)
	rig.pipe.NoProbe = true
	rig.feed(t, source.Cert{
		CN:     "example.test",
		SANs:   []string{"example.test", "api.example.test", "*.eu.example.test"},
		SeenAt: time.Now().UTC(),
	})

	cases := []struct{ host, origin, from string }{
		{"example.test", domain.OriginCN, "example.test"},
		{"api.example.test", domain.OriginSAN, "api.example.test"},
		{"eu.example.test", domain.OriginSAN, "*.eu.example.test"},
		{"www.eu.example.test", domain.OriginSAN, "*.eu.example.test"},
	}
	for _, c := range cases {
		rec, _ := rig.db.Get(c.host)
		if rec == nil {
			t.Errorf("%s was not stored", c.host)
			continue
		}
		if rec.Origin != c.origin || rec.CertName != c.from {
			t.Errorf("%s: origin=%q cert_name=%q, want %q/%q",
				c.host, rec.Origin, rec.CertName, c.origin, c.from)
		}
	}
	if got := rig.pipe.Stats().FromSAN.Load(); got != 3 {
		t.Errorf("from_san = %d, want 3", got)
	}
}

func TestSANOnlyCertificateIsStored(t *testing.T) {
	rig := newRig(t)
	rig.pipe.NoProbe = true
	rig.feed(t, source.Cert{CN: "", SANs: []string{"nocn.test"}, SeenAt: time.Now().UTC()})

	rec, _ := rig.db.Get("nocn.test")
	if rec == nil {
		t.Fatal("a certificate with no CN produced no record")
	}
	if rec.Origin != domain.OriginSAN {
		t.Errorf("origin = %q, want san", rec.Origin)
	}
}

func TestIgnoreSANs(t *testing.T) {
	rig := newRig(t)
	rig.pipe.NoProbe = true
	rig.pipe.IgnoreSANs = true
	rig.feed(t, source.Cert{
		CN:     "example.test",
		SANs:   []string{"api.example.test"},
		SeenAt: time.Now().UTC(),
	})

	if rec, _ := rig.db.Get("example.test"); rec == nil {
		t.Error("the CN was dropped")
	}
	if rec, _ := rig.db.Get("api.example.test"); rec != nil {
		t.Error("a SAN was stored with IgnoreSANs set")
	}
}

func TestMaxSANs(t *testing.T) {
	rig := newRig(t)
	rig.pipe.NoProbe = true
	rig.pipe.MaxSANs = 2
	rig.feed(t, source.Cert{
		CN:     "example.test",
		SANs:   []string{"a.example.test", "b.example.test", "c.example.test", "d.example.test"},
		SeenAt: time.Now().UTC(),
	})

	for _, h := range []string{"a.example.test", "b.example.test"} {
		if rec, _ := rig.db.Get(h); rec == nil {
			t.Errorf("%s was dropped despite fitting the SAN limit", h)
		}
	}
	for _, h := range []string{"c.example.test", "d.example.test"} {
		if rec, _ := rig.db.Get(h); rec != nil {
			t.Errorf("%s was stored past the SAN limit", h)
		}
	}
	if got := rig.pipe.Stats().SANsCut.Load(); got != 2 {
		t.Errorf("sans_cut = %d, want 2", got)
	}
}

func TestSkipSuffixDropsPlatformTenants(t *testing.T) {
	rig := newRig(t)
	rig.pipe.NoProbe = true
	rig.pipe.Skip = NewSuffixSet([]string{"workers.dev"})
	rig.feed(t,
		source.Cert{CN: "tenant.workers.dev", SeenAt: time.Now().UTC()},
		source.Cert{CN: "example.test", SeenAt: time.Now().UTC()},
	)

	if rec, _ := rig.db.Get("tenant.workers.dev"); rec != nil {
		t.Error("a host under a skipped parent was stored")
	}
	if rec, _ := rig.db.Get("example.test"); rec == nil {
		t.Error("an unrelated host was dropped")
	}
	if got := rig.pipe.Stats().Blocked.Load(); got != 1 {
		t.Errorf("blocked = %d, want 1", got)
	}
}

func TestParentCapStopsFloodButKeepsKnownHosts(t *testing.T) {
	rig := newRig(t)
	rig.pipe.NoProbe = true

	// A host already in the store must survive the cap.
	if err := rig.db.Update("known.flood.test", func(r *store.Record, _ bool) bool { return true }); err != nil {
		t.Fatal(err)
	}

	rig.pipe.ParentCap = 2
	rig.pipe.ParentWindow = time.Hour
	rig.feed(t,
		source.Cert{CN: "a.flood.test", SeenAt: time.Now().UTC()},
		source.Cert{CN: "b.flood.test", SeenAt: time.Now().UTC()},
		source.Cert{CN: "c.flood.test", SeenAt: time.Now().UTC()},
		source.Cert{CN: "known.flood.test", SeenAt: time.Now().UTC()},
		source.Cert{CN: "a.other.test", SeenAt: time.Now().UTC()},
	)

	// Writers run concurrently, so which of the three loses is not fixed —
	// only that exactly two of them fit the cap of 2.
	stored := 0
	for _, h := range []string{"a.flood.test", "b.flood.test", "c.flood.test"} {
		if rec, _ := rig.db.Get(h); rec != nil {
			stored++
		}
	}
	if stored != 2 {
		t.Errorf("%d of 3 new hosts stored under a cap of 2, want 2", stored)
	}
	if rec, _ := rig.db.Get("a.other.test"); rec == nil {
		t.Error("a different parent was charged the flooded parent's budget")
	}
	known, _ := rig.db.Get("known.flood.test")
	if known == nil || known.SeenCount != 1 || known.LastSeen.IsZero() {
		t.Errorf("a known host was blocked by the cap: %+v", known)
	}
	if got := rig.pipe.Stats().Capped.Load(); got != 1 {
		t.Errorf("capped = %d, want 1", got)
	}
}

// Repeat only fires for a host the recent set has already forgotten: while the
// set still remembers it, a second sighting is a Dup and never reaches the
// store. One writer keeps the two sightings of a.test strictly ordered.
func TestRepeatCountsHostsTheRecentSetHasForgotten(t *testing.T) {
	rig := newRig(t)
	rig.pipe.NoProbe = true
	rig.pipe.Writers = 1
	rig.pipe.RecentHosts = 2

	now := time.Now().UTC()
	cert := func(cn string) source.Cert { return source.Cert{CN: cn, SeenAt: now} }
	// a and b fill the set; c empties it and takes the first slot; a is then
	// unknown again and reaches the store, which does remember it.
	rig.feed(t, cert("a.test"), cert("b.test"), cert("c.test"), cert("a.test"))

	s := rig.pipe.Stats()
	if got := s.Repeat.Load(); got != 1 {
		t.Errorf("repeat = %d, want 1", got)
	}
	if got := s.New.Load(); got != 3 {
		t.Errorf("new = %d, want 3", got)
	}
	if got := s.Dup.Load(); got != 0 {
		t.Errorf("dup = %d, want 0", got)
	}
	rec, _ := rig.db.Get("a.test")
	if rec.SeenCount != 2 {
		t.Errorf("seen count = %d, want 2", rec.SeenCount)
	}
}

// hostRecorder is a TLS server that remembers the Host header of every
// request, which is the order the probers actually fetched things in.
func hostRecorder(t *testing.T) (addr string, order func() []string) {
	t.Helper()
	var (
		mu   sync.Mutex
		seen []string
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Host)
		mu.Unlock()
		io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// A worker takes a fresh discovery ahead of a backlog that is already full.
// With one worker the order of requests is the scheduling decision and
// nothing else.
func TestFreshDiscoveriesJumpTheBacklog(t *testing.T) {
	addr, order := hostRecorder(t)
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	p := &Pipeline{
		Store: db,
		Log:   discardLog(),
		Prober: probe.New(probe.Options{
			RequestsPerSecond: 1000, Burst: 100,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		}),
	}

	backlog := make(chan store.Pending, 64)
	for i := 0; i < 20; i++ {
		backlog <- store.Pending{Host: fmt.Sprintf("old%02d.test", i)}
	}
	fresh := make(chan string, 4)
	fresh <- "brand-new.test"
	close(fresh)
	close(backlog)

	p.probeFreshFirst(context.Background(), fresh, backlog)

	got := order()
	if len(got) != 21 {
		t.Fatalf("fetched %d hosts, want all 21", len(got))
	}
	if got[0] != "brand-new.test" {
		t.Errorf("fetched %q first, want brand-new.test ahead of the backlog (order: %v)", got[0], got[:5])
	}
}

// Both queues drain and the worker returns, whichever closes first.
func TestProbeFreshFirstDrainsBothQueues(t *testing.T) {
	addr, order := hostRecorder(t)
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := &Pipeline{
		Store: db, Log: discardLog(),
		Prober: probe.New(probe.Options{
			RequestsPerSecond: 1000, Burst: 100,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		}),
	}

	fresh := make(chan string, 2)
	backlog := make(chan store.Pending, 2)
	fresh <- "a.test"
	backlog <- store.Pending{Host: "b.test"}
	close(fresh)
	close(backlog)

	done := make(chan struct{})
	go func() { defer close(done); p.probeFreshFirst(context.Background(), fresh, backlog) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("probeFreshFirst did not return after both queues closed")
	}
	if n := len(order()); n != 2 {
		t.Errorf("fetched %d hosts, want both", n)
	}
}

func TestBacklogWorkersAlwaysReservesOne(t *testing.T) {
	for workers, want := range map[int]int{1: 1, 2: 1, 3: 1, 4: 1, 8: 2, 16: 4, 48: 12} {
		if got := backlogWorkers(workers); got != want {
			t.Errorf("backlogWorkers(%d) = %d, want %d", workers, got, want)
		}
	}
}

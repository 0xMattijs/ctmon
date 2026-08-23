package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mvo/ct/internal/probe"
	"github.com/mvo/ct/internal/source"
	"github.com/mvo/ct/internal/store"
)

// errStore is a Store whose chosen calls fail. A real store will not fail on
// request, so the paths that decide what happens to a discovery when the disk
// fills had no way of being exercised at all before Store was an interface.
type errStore struct {
	Store // everything not named below is the real thing
	fail  error
	on    map[string]bool
}

func newErrStore(real Store, on ...string) *errStore {
	set := make(map[string]bool, len(on))
	for _, name := range on {
		set[name] = true
	}
	return &errStore{Store: real, fail: errors.New("disk is full"), on: set}
}

func (e *errStore) Get(host string) (*store.Record, error) {
	if e.on["Get"] {
		return nil, e.fail
	}
	return e.Store.Get(host)
}

func (e *errStore) UpdateWithQueue(host string, fn func(*store.Record, bool) (bool, time.Time)) error {
	if e.on["UpdateWithQueue"] {
		return e.fail
	}
	return e.Store.UpdateWithQueue(host, fn)
}

func (e *errStore) Enqueue(host string, due time.Time) error {
	if e.on["Enqueue"] {
		return e.fail
	}
	return e.Store.Enqueue(host, due)
}

func (e *errStore) PendingLease(now time.Time, limit int, lease time.Duration) ([]store.Pending, error) {
	if e.on["PendingLease"] {
		return nil, e.fail
	}
	return e.Store.PendingLease(now, limit, lease)
}

func (e *errStore) PendingDone(keys ...[]byte) error {
	if e.on["PendingDone"] {
		return e.fail
	}
	return e.Store.PendingDone(keys...)
}

// A store that cannot be written to must show up in the counters. Everything
// here logs and carries on, which is right for one bad host and wrong as the
// only trace of a full disk: without the counter a run discovering nothing
// reads exactly like a quiet hour.
func TestStoreFailuresAreCounted(t *testing.T) {
	for _, tc := range []struct {
		name string
		on   string
		run  func(*testRig)
	}{
		{"write", "UpdateWithQueue", func(rig *testRig) {
			rig.feed(t, source.Cert{CN: "example.test", SeenAt: time.Now().UTC()})
		}},
		{"read for the parent cap", "Get", func(rig *testRig) {
			rig.pipe.ParentCap = 1
			rig.feed(t, source.Cert{CN: "example.test", SeenAt: time.Now().UTC()})
		}},
		{"sweep lease", "PendingLease", func(rig *testRig) {
			rig.pipe.sweep(context.Background(), make(chan store.Pending, 1))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newRig(t)
			rig.pipe.Store = newErrStore(rig.db, tc.on)
			tc.run(rig)
			if n := rig.pipe.Stats().StoreErrors.Load(); n == 0 {
				t.Errorf("a failing %s left store_errors at 0", tc.on)
			}
		})
	}
}

// A store that will not take the record must not leave the host counted as a
// discovery: "new" says a hostname was stored, and nothing was.
func TestAFailedWriteIsNotCountedAsADiscovery(t *testing.T) {
	rig := newRig(t)
	rig.pipe.Store = newErrStore(rig.db, "UpdateWithQueue")
	rig.feed(t, source.Cert{CN: "example.test", SeenAt: time.Now().UTC()})

	st := rig.pipe.Stats()
	if n := st.New.Load(); n != 0 {
		t.Errorf("new = %d after a failed write, want 0", n)
	}
	if n := st.StoreErrors.Load(); n != 1 {
		t.Errorf("store_errors = %d, want 1", n)
	}
}

// A probe that could not be re-queued is not settled, so the caller keeps the
// lease and the host comes round again rather than going missing.
func TestAHostThatCannotBeRequeuedKeepsItsLease(t *testing.T) {
	rig := newRig(t)
	rig.pipe.Store = newErrStore(rig.db, "Enqueue")
	rig.pipe.Prober = deferringProber{}

	if rig.pipe.probe(context.Background(), "busy.test") {
		t.Error("probe reported the host settled after the requeue failed")
	}
	if n := rig.pipe.Stats().StoreErrors.Load(); n != 1 {
		t.Errorf("store_errors = %d, want 1", n)
	}
}

// deferringProber defers every probe, which is what puts a host back on the
// queue instead of writing a result about it.
type deferringProber struct{}

func (deferringProber) Probe(context.Context, string) probe.Result {
	return probe.Result{Deferred: true, DeferReason: probe.DeferAddressBudget}
}

func (deferringProber) ResolverHealthy() bool { return true }

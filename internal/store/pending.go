package store

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The pending queue is the list of hosts waiting for a probe, ordered by when
// the probe is due.
//
// It replaces a scan of the domain bucket. That scan restarted at the top of
// the keyspace every sweep, and because keys are reversed hostnames the
// backlog drained in TLD-alphabetical order: on a live store of 2.1M names,
// .ai, .app, .at, .au, .be and .biz were 82-97% probed while .com — 42% of the
// store — sat at 3.1%, because newly discovered names kept refilling the
// prefix the scan had already passed. A queue ordered by due time has no such
// frontier: the oldest waiting host is the next one out, whatever it is
// called.
//
// Entries are leased rather than deleted when they come out, the way a work
// queue with a visibility timeout does. A process that dies holding a host
// leaves an entry that becomes due again, so a crash costs a delay rather than
// a hostname that is never probed.

// pendingLeaseKey is the fixed-width prefix of a pending key: the due time as
// big-endian nanoseconds, so byte order is time order.
const pendingLeaseKey = 8

// Pending is one host taken off the queue, together with the key holding its
// lease. Finish the work by passing the key back to PendingDone.
type Pending struct {
	Key  []byte
	Host string
}

// pendingKey encodes a due time and host into a queue key.
func pendingKey(due time.Time, host string) []byte {
	nanos := due.UnixNano()
	if nanos < 0 {
		// A zero or absurdly old time sorts first, which is what a caller
		// asking for "as soon as possible" means.
		nanos = 0
	}
	k := make([]byte, pendingLeaseKey+len(host))
	binary.BigEndian.PutUint64(k, uint64(nanos))
	copy(k[pendingLeaseKey:], host)
	return k
}

// pendingDue reads the due time back out of a queue key.
func pendingDue(k []byte) time.Time {
	if len(k) < pendingLeaseKey {
		return time.Time{}
	}
	return time.Unix(0, int64(binary.BigEndian.Uint64(k))).UTC()
}

// enqueue adds host to the queue inside an existing transaction.
//
// Callers must pass a due time computed outside the transaction: bolt may run
// a batched transaction more than once, and a time read inside would land on a
// different key each attempt and leave a duplicate entry behind.
func enqueue(tx *bolt.Tx, host string, due time.Time) error {
	return tx.Bucket(bucketPending).Put(pendingKey(due, host), nil)
}

// Enqueue queues host for a probe at due. Queuing a host that is already
// queued at a different time adds a second entry; the extra is dropped when it
// comes due and the record turns out not to need a probe.
func (s *Store) Enqueue(host string, due time.Time) error {
	return s.batch(func(tx *bolt.Tx) error { return enqueue(tx, host, due) })
}

// PendingLease takes up to limit hosts that are due at or before now and holds
// them for lease, during which they will not come out again. Pass each
// returned key to PendingDone once the host has been dealt with, or let the
// lease expire and the host comes back.
func (s *Store) PendingLease(now time.Time, limit int, lease time.Duration) ([]Pending, error) {
	if limit <= 0 {
		return nil, nil
	}
	var out []Pending
	err := s.batch(func(tx *bolt.Tx) error {
		out = out[:0]
		b := tx.Bucket(bucketPending)
		c := b.Cursor()
		// Rewriting keys while the cursor walks them would be undefined, so
		// collect first and move afterwards.
		type held struct {
			old  []byte
			host string
		}
		var take []held
		// A host can hold more than one entry: record queues it again every
		// time a certificate names it before the first probe lands. They all
		// have to go, but the host is handed out once — two leases for one
		// host collapse onto the same new key, so the second probe would run
		// against a lease the first had already released.
		seen := make(map[string]bool)
		for k, _ := c.First(); k != nil && len(seen) < limit; k, _ = c.Next() {
			if len(k) <= pendingLeaseKey {
				// Not a key this package wrote. Leave it alone rather than
				// guess at what it means.
				continue
			}
			if pendingDue(k).After(now) {
				// Keys are in due order, so the first one in the future ends
				// the batch.
				break
			}
			host := string(k[pendingLeaseKey:])
			take = append(take, held{old: append([]byte{}, k...), host: host})
			seen[host] = true
		}
		until := now.Add(lease)
		handed := make(map[string]bool, len(seen))
		for _, h := range take {
			if err := b.Delete(h.old); err != nil {
				return err
			}
			if handed[h.host] {
				// A duplicate of one already leased. Dropping its key is the
				// whole point; there is nothing more to hand out.
				continue
			}
			handed[h.host] = true
			key := pendingKey(until, h.host)
			if err := b.Put(key, nil); err != nil {
				return err
			}
			out = append(out, Pending{Key: key, Host: h.host})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("lease pending: %w", err)
	}
	return out, nil
}

// PendingDone drops a leased entry. Keys that have already gone are not an
// error: a lease can expire and be taken by someone else.
func (s *Store) PendingDone(keys ...[]byte) error {
	if len(keys) == 0 {
		return nil
	}
	return s.batch(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPending)
		for _, k := range keys {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// PendingStats reports how many hosts are queued and when the oldest of them
// came due. A backlog is normal; a backlog whose oldest entry keeps getting
// older is probing that cannot keep up.
func (s *Store) PendingStats() (count int, oldest time.Time, err error) {
	err = s.view(func(tx *bolt.Tx) error {
		// Absent only on a database a read-only handle opened without being
		// able to create it. See OpenReadOnly.
		b := tx.Bucket(bucketPending)
		if b == nil {
			return nil
		}
		count = b.Stats().KeyN
		if k, _ := b.Cursor().First(); k != nil {
			oldest = pendingDue(k)
		}
		return nil
	})
	return count, oldest, err
}

// seedChunk is how many records one seeding transaction walks. Seeding a
// store that predates the queue touches every record, and a single
// transaction over millions of them would hold the whole write set in memory.
// It is a variable so a test can span chunks without writing twenty thousand
// records to do it.
var seedChunk = 20000

// SeedPending fills the queue from records the queue does not know about:
// those written before it existed, those a change of re-probe policy has
// brought back into scope, and those a run with the sweep off recorded without
// queuing.
//
// generation names the policy being seeded for. Seeding runs when what the
// store last finished differs from it, which is what stops "--reprobe 24h"
// from being ignored on a database first seeded without it. It also runs when
// MarkUnqueued has been called since the last seed, whatever the generation.
//
// A seed that is interrupted resumes. The cursor is committed with each chunk,
// so a run killed part way through picks up where it stopped instead of
// walking the records it has already queued a second time. A MarkUnqueued in
// between drops that cursor and the next seed starts from the top, because
// what it has to collect is spread over the records the walk had already
// passed.
//
// due decides, per record, whether a probe is wanted and when it is due.
// progress, if given, is called after each chunk so a long seed can say so.
func (s *Store) SeedPending(generation string, due func(*Record) (time.Time, bool), progress func(scanned, queued int)) (queued int, ran bool, err error) {
	after, wanted, err := s.seedState(generation)
	if err != nil || !wanted {
		return 0, false, err
	}

	scanned := 0
	for {
		n := 0
		err := s.update(func(tx *bolt.Tx) error {
			c := tx.Bucket(bucketDomains).Cursor()
			k, v := c.First()
			if after != nil {
				// Seek lands on the last key of the previous chunk when it is
				// still there, and on the one after it when it is not.
				if k, v = c.Seek(after); k != nil && bytes.Equal(k, after) {
					k, v = c.Next()
				}
			}
			for ; k != nil && n < seedChunk; k, v = c.Next() {
				n++
				after = append(after[:0], k...)
				host := reverseHost(string(k))
				rec := &Record{}
				if err := s.decode(host, v, rec); err != nil {
					return fmt.Errorf("decode %s: %w", host, err)
				}
				at, want := due(rec)
				if !want {
					continue
				}
				if err := enqueue(tx, host, at); err != nil {
					return err
				}
				queued++
			}
			if n == 0 {
				return nil
			}
			return tx.Bucket(bucketMeta).Put(keySeedAt, seedProgress(generation, after))
		})
		if err != nil {
			return queued, true, fmt.Errorf("seed pending: %w", err)
		}
		scanned += n
		if progress != nil {
			progress(scanned, queued)
		}
		if n < seedChunk {
			break
		}
	}
	return queued, true, s.finishSeed(generation)
}

// seedState reports where a seed for generation should start, and whether one
// is needed at all.
func (s *Store) seedState(generation string) (after []byte, wanted bool, err error) {
	err = s.view(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		if meta.Get(keyUnqueued) == nil && string(meta.Get(keySeeded)) == generation {
			return nil
		}
		wanted = true
		// A cursor from an interrupted seed is only good for the generation
		// that wrote it. Whether the walk it belongs to was making up for an
		// unqueued run does not come into it: MarkUnqueued throws the cursor
		// away, so a cursor that is still here belongs to a walk that started
		// after the last mark, and everything that mark is about is still
		// ahead of it.
		if at := meta.Get(keySeedAt); at != nil {
			if gen, cursor, ok := bytes.Cut(at, []byte{0}); ok && string(gen) == generation {
				after = append([]byte{}, cursor...)
			}
		}
		return nil
	})
	return after, wanted, err
}

// seedProgress encodes an in-flight seed's generation and cursor.
func seedProgress(generation string, after []byte) []byte {
	out := make([]byte, 0, len(generation)+1+len(after))
	out = append(out, generation...)
	out = append(out, 0)
	return append(out, after...)
}

func (s *Store) finishSeed(generation string) error {
	return s.update(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		if err := meta.Put(keySeeded, []byte(generation)); err != nil {
			return err
		}
		if err := meta.Delete(keySeedAt); err != nil {
			return err
		}
		// The walk that just finished is the one the marker was asking for.
		return meta.Delete(keyUnqueued)
	})
}

// MarkUnqueued records that this run stores discoveries without queuing them,
// so the next run that sweeps fills the queue from the records again.
//
// A run with the sweep off writes records nothing in the queue points at: a
// host shed because every worker was busy, or turned away by an address
// budget, is recorded unprobed and never scheduled. The generation names the
// re-probe policy and nothing else, so a later swept run under the same policy
// would skip the seed and leave those hosts waiting for a certificate to name
// them again. The marker is what turns that skip back into a walk, once.
//
// It is written at the start of such a run rather than the end, because a run
// killed outright leaves the same records behind as one that exits cleanly.
func (s *Store) MarkUnqueued() error {
	return s.update(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		// Any interrupted seed's cursor is void from here. The records this
		// run is about to write are scattered across the whole keyspace, most
		// of them behind wherever that walk stopped, so resuming it would
		// step over them — and the walk clears the marker when it finishes,
		// so nothing would look for them again.
		if err := meta.Delete(keySeedAt); err != nil {
			return err
		}
		return meta.Put(keyUnqueued, []byte{1})
	})
}

// Unqueued reports whether a run left records the queue was never told about.
// The next seed to finish clears it.
func (s *Store) Unqueued() (bool, error) {
	var yes bool
	err := s.view(func(tx *bolt.Tx) error {
		// Absent only on a database a read-only handle opened without being
		// able to create it. See OpenReadOnly.
		if b := tx.Bucket(bucketMeta); b != nil {
			yes = b.Get(keyUnqueued) != nil
		}
		return nil
	})
	return yes, err
}

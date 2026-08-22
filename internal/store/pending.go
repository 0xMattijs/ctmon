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
		for k, _ := c.First(); k != nil && len(take) < limit; k, _ = c.Next() {
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
			take = append(take, held{
				old:  append([]byte{}, k...),
				host: string(k[pendingLeaseKey:]),
			})
		}
		until := now.Add(lease)
		for _, h := range take {
			if err := b.Delete(h.old); err != nil {
				return err
			}
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
		b := tx.Bucket(bucketPending)
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

// SeedPending fills the queue from records written before the queue existed,
// which is what makes an existing database usable without re-discovering
// everything. It runs once: the store remembers that it has seeded and does
// nothing on later calls.
//
// due decides, per record, whether a probe is wanted and when it is due.
// progress, if given, is called after each chunk so a long seed can say so.
func (s *Store) SeedPending(due func(*Record) (time.Time, bool), progress func(scanned, queued int)) (queued int, ran bool, err error) {
	done, err := s.pendingSeeded()
	if err != nil || done {
		return 0, false, err
	}

	var after []byte
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
			return nil
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
	return queued, true, s.markPendingSeeded()
}

func (s *Store) pendingSeeded() (bool, error) {
	var ok bool
	err := s.view(func(tx *bolt.Tx) error {
		ok = tx.Bucket(bucketMeta).Get(keySeeded) != nil
		return nil
	})
	return ok, err
}

func (s *Store) markPendingSeeded() error {
	return s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(keySeeded, []byte{1})
	})
}

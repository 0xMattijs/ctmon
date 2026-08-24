package store

import (
	"bytes"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Pruning is the only thing here that removes a record. Everything else in the
// store grows it: names are written once and updated forever, and compaction
// returns the slack between records without dropping any.
//
// That is the right default for a discovery tool — a hostname seen once is
// evidence, and evidence you threw away is not evidence you can go back to.
// But it leaves an operator no answer to the questions that eventually arrive:
// a platform that turned out to be shared hosting and is now on --skip-suffix,
// with however many thousand of its tenants already recorded; a backlog full
// of names that have never resolved and never will; a store that has grown
// past what the disk it is on can hold.
//
// So this is deliberately narrow. A prune walks a scope, tests each record
// against a predicate, and deletes what matches. It does not decide what is
// worth keeping — the command does that, from flags an operator typed — and it
// counts without deleting when asked, because deleting discovered hostnames is
// not undoable.

// pruneChunk is how many records one prune transaction walks. Deleting is a
// write per key, and a single transaction over millions of them would hold the
// whole write set in memory. It is a variable so a test can span chunks
// without writing twenty thousand records to do it.
var pruneChunk = 20000

// PruneOptions says what to remove.
type PruneOptions struct {
	// Under limits the walk to this parent and the hosts beneath it. Empty
	// walks the whole store.
	Under string

	// Match reports whether a record in scope should go. A nil Match takes
	// every record in scope, which is the whole store when Under is empty
	// too — so a caller that means to keep something has to say so.
	Match func(*Record) bool

	// DryRun counts what would go and deletes nothing.
	DryRun bool
}

// PruneResult reports what a prune did, or in a dry run what it would have
// done.
//
// Pending is left at zero by a dry run. The queue is not indexed by host — its
// keys are ordered by due time — so the entries belonging to a record are
// found by noticing that the record has gone, which in a dry run it has not.
// Nothing is lost by that: every entry pointing at a deleted record goes, so
// the number is a consequence of Deleted rather than a separate decision.
type PruneResult struct {
	// Scanned is how many records the walk looked at, which is the whole
	// store unless Under narrowed it.
	Scanned int
	// Deleted is how many of them matched and went, or in a dry run how many
	// would have. The dry run makes the same pass and asks the same
	// question, so the two numbers are the same number and not an estimate
	// of it.
	Deleted int
	// Pending is how many queue entries were dropped for want of a record.
	Pending int
}

// Prune removes the records in scope that match, together with the queue
// entries left pointing at them.
//
// The walk runs in chunks that each commit before the next begins, so an
// interrupted prune leaves the store consistent — it has simply deleted fewer
// records than it was asked to. Re-running it finishes the job, since the
// records it already removed are no longer there to match.
//
// It is the caller's business to hold the database while this runs. bolt's
// exclusive lock does that much: a prune opens the file for writing, so it
// cannot start while a run has it.
func (s *Store) Prune(opts PruneOptions) (PruneResult, error) {
	var res PruneResult
	scope, err := scopeUnder(opts.Under)
	if err != nil {
		return res, fmt.Errorf("prune: %w", err)
	}
	match := opts.Match
	if match == nil {
		match = func(*Record) bool { return true }
	}

	// after is the last key the previous chunk looked at, matched or not. A
	// chunk resumes from it the way SeedPending does: Seek lands on that key
	// when it survived and on the one past it when it was deleted, and both
	// are the right place to carry on from.
	var after []byte
	for {
		scanned, deleted, done := 0, 0, false
		work := func(tx *bolt.Tx) error {
			b := tx.Bucket(bucketDomains)
			c := b.Cursor()

			var k, v []byte
			switch {
			case after != nil:
				if k, v = c.Seek(after); k != nil && bytes.Equal(k, after) {
					k, v = c.Next()
				}
			case scope.prefix != nil:
				// Reversed keys put a whole domain in one run, so a scoped
				// prune starts at that run rather than at the top of the
				// store.
				k, v = c.Seek(scope.prefix)
			default:
				k, v = c.First()
			}

			// Collected first and deleted afterwards, because rewriting keys
			// while the cursor is walking them is undefined.
			var doomed [][]byte
			for ; k != nil && scanned < pruneChunk; k, v = c.Next() {
				in, past := scope.test(k)
				if past {
					done = true
					break
				}
				if !in {
					continue
				}
				scanned++
				after = append(after[:0], k...)
				host := reverseHost(string(k))
				rec := &Record{}
				if err := s.decode(host, v, rec); err != nil {
					return fmt.Errorf("decode %s: %w", host, err)
				}
				if !match(rec) {
					continue
				}
				deleted++
				if !opts.DryRun {
					doomed = append(doomed, append([]byte{}, k...))
				}
			}
			if k == nil {
				done = true
			}
			for _, key := range doomed {
				if err := b.Delete(key); err != nil {
					return err
				}
			}
			return nil
		}

		run := s.update
		if opts.DryRun {
			run = s.view
		}
		if err := run(work); err != nil {
			return res, fmt.Errorf("prune: %w", err)
		}
		res.Scanned += scanned
		res.Deleted += deleted
		if done {
			break
		}
	}

	if opts.DryRun {
		return res, nil
	}
	// Reconciled on every prune that may write, not only on one that deleted
	// something. A prune interrupted between the record walk and this pass —
	// the wide window, since this pass is the slow half — leaves orphaned
	// entries behind, and running it again is how an operator expects to
	// finish the job. Gating on res.Deleted would make the second run find
	// nothing left to delete and stop before reaching the entries the first
	// one orphaned.
	//
	// The cost is a walk of the whole queue even when nothing matched. That
	// is the price of the guarantee, on a command run deliberately and
	// rarely.
	n, err := s.pruneQueue()
	res.Pending = n
	return res, err
}

// pruneQueue drops queue entries that no longer have a record.
//
// This is reconciliation rather than bookkeeping, and it is why Prune does not
// have to remember which hosts it deleted. The queue is keyed by due time, so
// there is no way to seek to one host's entries; but an entry whose record has
// gone is meaningless on its face, and the sweep already knows it — wantsProbe
// drops such an entry on sight. Leaving them would work, then. It would also
// mean a prune of a million records left a million entries behind for the next
// run to walk past one lease at a time, which is a slower way of arriving at
// the same place.
//
// It cleans up entries orphaned by earlier prunes too, since it cannot tell
// them apart and there is no reason to.
func (s *Store) pruneQueue() (int, error) {
	dropped := 0
	var after []byte
	for {
		n, gone := 0, 0
		err := s.update(func(tx *bolt.Tx) error {
			n, gone = 0, 0
			domains, pending := tx.Bucket(bucketDomains), tx.Bucket(bucketPending)
			c := pending.Cursor()
			k, _ := c.First()
			if after != nil {
				if k, _ = c.Seek(after); k != nil && bytes.Equal(k, after) {
					k, _ = c.Next()
				}
			}
			var doomed [][]byte
			for ; k != nil && n < pruneChunk; k, _ = c.Next() {
				n++
				after = append(after[:0], k...)
				if len(k) <= pendingLeaseKey {
					// Not a key this package wrote. Leave it alone rather
					// than guess at what it means.
					continue
				}
				host := string(k[pendingLeaseKey:])
				if domains.Get([]byte(reverseHost(host))) != nil {
					continue
				}
				doomed = append(doomed, append([]byte{}, k...))
			}
			for _, key := range doomed {
				if err := pending.Delete(key); err != nil {
					return err
				}
			}
			gone = len(doomed)
			return nil
		})
		// Counted after the transaction returns, not inside it: a chunk that
		// built its list and then failed to commit deleted nothing, and the
		// error it returns travels with a number the caller may print.
		dropped += gone
		if err != nil {
			return dropped, fmt.Errorf("prune queue: %w", err)
		}
		if n < pruneChunk {
			return dropped, nil
		}
	}
}

// Unseen matches records no certificate has named since cutoff.
//
// LastSeen moves every time a certificate carries the host, so this is
// "nothing has been issued for this name in a while" and not "nobody has
// looked at it in a while". A name whose certificates are still being renewed
// never matches, however long ago it was first seen.
func Unseen(cutoff time.Time) func(*Record) bool {
	return func(r *Record) bool { return r.LastSeen.Before(cutoff) }
}

// Failed matches records that were probed, have never returned a body, and
// have been in that state since before cutoff.
//
// Probed rules out a host merely waiting its turn in a backlog. An empty
// BodyHash rules out one that answered once and has since started failing,
// whose last good hash is the thing worth keeping. The two times rule out the
// rest.
//
// Both times are needed, and neither is the one the rule really wants. A
// record does not store when it started failing, so this approximates it from
// the ends: discovered before the cutoff, and last tried before it too. On
// FirstSeen alone a host discovered months ago but only now reaching the front
// of a deep queue would be deleted an hour after its first probe returned a
// transient "no such host" — the backlog delay, not the host, being what aged
// it past the cutoff. Measured on a live store the two agree exactly today,
// with the probe landing a median of 0.4 hours after discovery; they come
// apart as the queue does.
//
// Under --reprobe the rule narrows rather than widens, because ProbedAt keeps
// moving forward and a chronically failing host stops matching. That is the
// safe direction for a rule that deletes, and it is the reason to prefer this
// over the looser reading.
func Failed(cutoff time.Time) func(*Record) bool {
	return func(r *Record) bool {
		return r.Probed && r.ProbeError != "" && r.BodyHash == "" &&
			r.FirstSeen.Before(cutoff) && r.ProbedAt.Before(cutoff)
	}
}

// All matches a record only when every one of match does. A caller that gave
// no predicates gets one that takes everything, which is what an unfiltered
// scope means.
func All(match ...func(*Record) bool) func(*Record) bool {
	return func(r *Record) bool {
		for _, fn := range match {
			if !fn(r) {
				return false
			}
		}
		return true
	}
}

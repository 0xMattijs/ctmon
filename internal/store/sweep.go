package store

import (
	"encoding/binary"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// Sweeping is forgetting for the dictionaries, and it exists for the same
// reason pruning does: until records could be deleted, nothing here could ever
// stop being referenced.
//
// A dictionary entry is written the first time a record needs it and never
// removed. That was invisible while the store only grew. It stops being
// invisible the moment a prune takes the last record using a vocabulary — the
// entries stay, `stats` goes on counting them, and the number on the line that
// exists to show how well the interning is working starts describing a
// vocabulary that is not in the store.
//
// The rule most likely to be run is the one that shows it worst. --failed-since
// deletes exactly the records carrying a probe error, so on a live store it
// orphaned 7,240 of 7,250 error shapes at a stroke, and compaction preserved
// every one of them.

// SweepResult reports what a sweep dropped, per dictionary.
type SweepResult struct {
	Sources int
	Issuers int
	Errors  int
	// Bytes is what the dropped entries occupied, keys included.
	Bytes int64
}

// Total is how many entries went, across all three dictionaries.
func (r SweepResult) Total() int { return r.Sources + r.Issuers + r.Errors }

// SweepDicts drops dictionary entries that no record refers to any more.
//
// Ids do not have to be renumbered, which is what makes this cheap. Nothing
// indexes them densely — a record stores the id and name(id) looks it up — so
// an unreferenced entry can simply go, and no record is re-encoded. The cost
// is one walk of the records to find out which ids are still spoken for.
//
// Reusing a freed id later is safe by construction: an id is only freed when
// no record refers to it, so nothing can be looking at the name it used to
// have. The in-memory tables are updated in step with the file, because a
// forgotten name left marked durable would be interned again without being
// written, and the next open would load a record pointing at an entry that is
// not there.
//
// The caller must hold the database. Any record written between the walk and
// the delete could refer to an id the walk did not see, so this belongs in a
// command that owns the file — prune does — and not beside a running feed.
func (s *Store) SweepDicts() (SweepResult, error) {
	var res SweepResult

	// The ids come from the decoder rather than from re-interning what it
	// produced. Asking which entry a record's text "would" intern to today is
	// the wrong question, and dangerously so: a record written under an older
	// layout expands from a differently-shaped template, so the lookup misses,
	// the entry it actually points at looks unused, and the sweep deletes the
	// only copy of its error. Reading the id the record holds cannot be wrong
	// about that, whatever the layout was.
	keep := map[*dict]map[uint32]bool{
		s.sources: {0: true},
		s.issuers: {0: true},
		s.errors:  {0: true},
	}
	err := s.view(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDomains).ForEach(func(k, v []byte) error {
			host := reverseHost(string(k))
			var (
				rec Record
				ids recordIDs
			)
			if err := s.decodeIDs(host, v, &rec, &ids); err != nil {
				return fmt.Errorf("decode %s: %w", host, err)
			}
			keep[s.sources][ids.source] = true
			keep[s.issuers][ids.issuer] = true
			if ids.hasErr {
				keep[s.errors][ids.errShape] = true
			}
			return nil
		})
	})
	if err != nil {
		return res, fmt.Errorf("sweep dictionaries: %w", err)
	}

	// Collected under the transaction, applied to memory only once it has
	// committed. intern/confirm splits the same way and for the same reason: a
	// write that rolls back must not leave the tables describing a file that
	// does not agree with them. Getting it wrong here is worse than there —
	// a name forgotten in memory but still in the file decodes as empty on
	// every surviving record that points at it, and re-interning allocates a
	// second id for a name that already has one.
	forgotten := map[*dict][]uint32{}
	err = s.update(func(tx *bolt.Tx) error {
		clear(forgotten)
		for _, d := range []*dict{s.sources, s.issuers, s.errors} {
			ids, bytes, err := d.forget(tx, keep[d])
			if err != nil {
				return err
			}
			forgotten[d] = ids
			switch d {
			case s.sources:
				res.Sources = len(ids)
			case s.issuers:
				res.Issuers = len(ids)
			case s.errors:
				res.Errors = len(ids)
			}
			res.Bytes += bytes
		}
		return nil
	})
	if err != nil {
		return SweepResult{}, fmt.Errorf("sweep dictionaries: %w", err)
	}
	for d, ids := range forgotten {
		d.forgotten(ids)
	}
	return res, nil
}

// forget deletes the bucket entries whose id is not in keep, and reports which
// ids went so the caller can drop them from the tables once the transaction
// has committed.
//
// The walk is over the in-memory names rather than the bucket, so that the two
// cannot drift apart. They can already disagree: encode interns a name and may
// then fail on a later field, and the rolled-back transaction leaves the name
// in the tables with no bucket entry behind it. Walking the bucket would miss
// such an id — it has no key to find — while still dropping it from ids, and
// the phantom left in names would inflate the count stats prints, which is the
// number this whole sweep exists to make honest.
//
// next is deliberately left where it is. Lowering it would hand the next new
// name an id that was just freed, which is safe but pointlessly confusing to
// anyone reading the bucket; a reopened database recomputes it from what
// survived anyway.
func (d *dict) forget(tx *bolt.Tx, keep map[uint32]bool) (doomed []uint32, bytes int64, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	b := tx.Bucket(d.bucket)
	var key [4]byte
	for id := range d.names {
		if keep[id] {
			continue
		}
		doomed = append(doomed, id)
		if b == nil {
			continue
		}
		binary.BigEndian.PutUint32(key[:], id)
		v := b.Get(key[:])
		if v == nil {
			// In the tables but never durable — an interning whose
			// transaction rolled back. There is nothing to delete, and the
			// caller still has to forget it.
			continue
		}
		bytes += int64(len(key) + len(v))
		if err := b.Delete(key[:]); err != nil {
			return nil, bytes, err
		}
	}
	return doomed, bytes, nil
}

// forgotten drops ids from the in-memory tables, after the transaction that
// removed them from the file has committed.
func (d *dict) forgotten(ids []uint32) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, id := range ids {
		if name, ok := d.names[id]; ok {
			delete(d.ids, name)
		}
		delete(d.names, id)
		delete(d.persisted, id)
	}
}

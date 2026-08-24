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

	// Collected as ids rather than names, because that is what the records
	// hold and what the buckets are keyed by. A name is only needed to look
	// the id up, and the in-memory tables already have that map.
	keep := map[*dict]map[uint32]bool{
		s.sources: {0: true},
		s.issuers: {0: true},
		s.errors:  {0: true},
	}
	err := s.ForEach(func(r *Record) error {
		mark(keep[s.sources], s.sources, r.Source)
		mark(keep[s.issuers], s.issuers, r.Issuer)
		// The record carries the error with its host substituted back in, so
		// it has to be templatized again to name the entry it came from — the
		// same call encode makes on the way in.
		if r.ProbeError != "" {
			mark(keep[s.errors], s.errors, templatize(r.Host, r.ProbeError))
		}
		return nil
	})
	if err != nil {
		return res, fmt.Errorf("sweep dictionaries: %w", err)
	}

	err = s.update(func(tx *bolt.Tx) error {
		for _, d := range []*dict{s.sources, s.issuers, s.errors} {
			dropped, bytes, err := d.forget(tx, keep[d])
			if err != nil {
				return err
			}
			switch d {
			case s.sources:
				res.Sources = dropped
			case s.issuers:
				res.Issuers = dropped
			case s.errors:
				res.Errors = dropped
			}
			res.Bytes += bytes
		}
		return nil
	})
	if err != nil {
		return SweepResult{}, fmt.Errorf("sweep dictionaries: %w", err)
	}
	return res, nil
}

// mark notes the id a name interns to, if the dictionary knows it. A name it
// does not know cannot be holding an entry down.
func mark(keep map[uint32]bool, d *dict, name string) {
	if name == "" {
		return
	}
	d.mu.Lock()
	id, ok := d.ids[name]
	d.mu.Unlock()
	if ok {
		keep[id] = true
	}
}

// forget drops every entry whose id is not in keep, from the bucket and from
// the in-memory tables together.
//
// next is deliberately left where it is. Lowering it would hand the next new
// name an id that was just freed, which is safe but pointlessly confusing to
// anyone reading the bucket; a reopened database recomputes it from what
// survived anyway.
func (d *dict) forget(tx *bolt.Tx, keep map[uint32]bool) (dropped int, bytes int64, err error) {
	b := tx.Bucket(d.bucket)
	if b == nil {
		return 0, 0, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	// Collected first and deleted afterwards, because rewriting keys while the
	// cursor walks them is undefined.
	var doomed [][]byte
	c := b.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if len(k) != 4 {
			// Not a key this package wrote. Leave it alone rather than guess
			// at what it means.
			continue
		}
		if keep[binary.BigEndian.Uint32(k)] {
			continue
		}
		doomed = append(doomed, append([]byte{}, k...))
		bytes += int64(len(k) + len(v))
	}
	for _, k := range doomed {
		if err := b.Delete(k); err != nil {
			return dropped, bytes, err
		}
		id := binary.BigEndian.Uint32(k)
		delete(d.names, id)
		delete(d.persisted, id)
		dropped++
	}
	// ids is keyed by name, so it is cleared by walking what is left rather
	// than by looking each dropped id up backwards.
	for name, id := range d.ids {
		if name != "" && !keep[id] {
			delete(d.ids, name)
		}
	}
	return dropped, bytes, nil
}

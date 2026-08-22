package store

import (
	"fmt"
	"os"

	bolt "go.etcd.io/bbolt"
)

// Snapshot writes a consistent copy of the database to path and returns its
// size.
//
// This is the only way to read a store while a run holds it. bolt gives the
// writer an exclusive lock on the file, and opening read-only asks for a
// shared one, which conflicts — so no second process gets in at all, not even
// to read. Copying the file from outside does not work either: cp reads it
// over several seconds while it changes underneath, and the result is a tree
// holding pages from two different eras, which walks into cycles.
//
// From inside the process there is no such problem. A bolt read transaction
// is a consistent view by construction, so the copy it writes is a database
// that opens cleanly.
//
// Writers are not blocked for the duration. bolt's MVCC lets the read
// transaction proceed against the pages it started with while new writes
// allocate new ones, which does mean the file cannot reuse freed pages until
// the snapshot finishes.
func (s *Store) Snapshot(path string) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Write beside the target and rename, so a reader finds either the
	// previous snapshot or this one, never a half-written file.
	tmp := path + ".writing"
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", tmp, err)
	}

	var n int64
	err = s.db.View(func(tx *bolt.Tx) error {
		var werr error
		n, werr = tx.WriteTo(f)
		return werr
	})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return 0, fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return 0, fmt.Errorf("swap in %s: %w", path, err)
	}
	return n, nil
}

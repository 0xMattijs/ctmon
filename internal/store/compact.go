package store

import (
	"errors"
	"fmt"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Compaction rewrites a database into full pages.
//
// bolt never shrinks a file, and live writes arrive in random key order, so it
// splits leaves at about half full and the file drifts toward twice the size of
// the records it holds. Replaying the whole tree in key order gives the slack
// back. The interned dictionaries survive: the copy preserves their ids
// verbatim, so the in-memory tables still describe the new file.
//
// There are two ways to ask for it, and they differ only in what happens to the
// result. CompactInPlace swaps the new file over the old one, which is what a
// long-running monitor wants; CompactTo writes it beside the original and
// leaves the choice to whoever is reading the report.

// compactTxSize bounds how much one compaction transaction copies, which
// bounds its peak memory on a large store.
const compactTxSize = 64 << 20

// CompactResult reports what a compaction reclaimed. Bytes come in two
// flavors: what the pages hold, and what the file occupies. bolt grows its file
// in large steps and keeps freed pages for reuse, so the file is the bigger and
// lazier number.
type CompactResult struct {
	OldUsed  int64
	NewUsed  int64
	OldBytes int64
	NewBytes int64
}

// compactInto rewrites src into a new database at path and reports how many
// bytes of pages the result holds. A failure leaves no file behind.
//
// This is the whole of compaction. Both entry points below are this plus a
// decision about where the result goes.
func compactInto(path string, src *bolt.DB) (used int64, err error) {
	dst, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", path, err)
	}
	defer func() {
		if err != nil {
			os.Remove(path)
		}
	}()
	if err = bolt.Compact(dst, src, compactTxSize); err != nil {
		dst.Close()
		return 0, fmt.Errorf("compact: %w", err)
	}
	// Measured through the open handle, before it is closed: reopening the file
	// just to size it is the same number for more work.
	used = usedBytes(dst)
	if err = dst.Close(); err != nil {
		return 0, err
	}
	return used, nil
}

// CompactInPlace rewrites the database into full pages and swaps the result in.
//
// Every other store call blocks for the duration, which on a large store is
// seconds. The original file is replaced by an atomic rename, so an interrupted
// compaction leaves either the old database or the new one, never a partial
// write.
func (s *Store) CompactInPlace() (CompactResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res := CompactResult{OldUsed: s.usedBytes()}
	if info, err := os.Stat(s.path); err == nil {
		res.OldBytes = info.Size()
	}

	tmp := s.path + ".compacting"
	// A leftover from a killed compaction is garbage: the real database is
	// still at s.path, and this file was never swapped in.
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return res, err
	}
	newUsed, err := compactInto(tmp, s.db)
	if err != nil {
		return res, err
	}
	res.NewUsed = newUsed

	// From here the handle is closed, so every path has to reopen one.
	if err := s.db.Close(); err != nil {
		os.Remove(tmp)
		return res, s.reopen(err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return res, s.reopen(fmt.Errorf("swap in %s: %w", tmp, err))
	}
	if info, err := os.Stat(s.path); err == nil {
		res.NewBytes = info.Size()
	}
	return res, s.reopen(nil)
}

// reopen restores the handle after a swap. It reports cause, the failure that
// led here, unless reopening failed too — then the caller needs both.
func (s *Store) reopen(cause error) error {
	db, err := bolt.Open(s.path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return errors.Join(cause, fmt.Errorf("reopen %s: %w", s.path, err))
	}
	s.db = db
	return cause
}

// CompactTo rewrites the store at srcPath into a new file at dstPath. The
// source is only read, and dstPath must not exist.
func CompactTo(srcPath, dstPath string) (CompactResult, error) {
	var res CompactResult

	if _, err := os.Stat(dstPath); err == nil {
		return res, fmt.Errorf("%s already exists", dstPath)
	} else if !os.IsNotExist(err) {
		return res, err
	}
	info, err := os.Stat(srcPath)
	if err != nil {
		return res, err
	}
	res.OldBytes = info.Size()
	res.OldUsed = usedBytesAt(srcPath)

	src, err := bolt.Open(srcPath, 0o600, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return res, fmt.Errorf("open %s: %w", srcPath, err)
	}
	defer src.Close()

	if res.NewUsed, err = compactInto(dstPath, src); err != nil {
		return res, err
	}
	if info, err := os.Stat(dstPath); err == nil {
		res.NewBytes = info.Size()
	}
	return res, nil
}

// usedBytes reports how many bytes of pages a database holds.
func usedBytes(db *bolt.DB) int64 {
	var n int64
	_ = db.View(func(tx *bolt.Tx) error {
		n = tx.Size()
		return nil
	})
	return n
}

// usedBytes reports how many bytes of pages this store holds.
func (s *Store) usedBytes() int64 { return usedBytes(s.db) }

// usedBytesAt opens a database read-only just to measure it. It returns 0 if
// the file cannot be read, since this only ever feeds a progress report.
func usedBytesAt(path string) int64 {
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return 0
	}
	defer db.Close()
	return usedBytes(db)
}

// Package store persists discovered domains and CT log positions in bbolt.
package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketDomains = []byte("domains")
	bucketLogPos  = []byte("logpos")
	bucketMeta    = []byte("meta")
	bucketPending = []byte("pending")

	bucketSources = "dict_sources"
	bucketIssuers = "dict_issuers"
	bucketErrors  = "dict_errors"

	keyFormat = []byte("format")
	keySeeded = []byte("pending_seeded")
)

// ErrLegacyFormat says the database predates the packed record format.
var ErrLegacyFormat = errors.New("database uses the old JSON record format; run \"ctmon migrate\"")

// Record is everything known about one discovered hostname.
type Record struct {
	Host string `json:"host"`
	// CertName is the certificate name this host was derived from, and
	// Origin says whether that name was the Common Name or a SAN.
	CertName     string    `json:"cert_name"`
	Origin       string    `json:"origin"`
	FromWildcard bool      `json:"from_wildcard"`
	Source       string    `json:"source"`
	Issuer       string    `json:"issuer,omitempty"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	SeenCount    int       `json:"seen_count"`

	// Probe results for https://<host>/.
	Probed     bool      `json:"probed"`
	ProbedAt   time.Time `json:"probed_at,omitzero"`
	HTTPStatus int       `json:"http_status,omitempty"`
	FinalURL   string    `json:"final_url,omitempty"`
	BodySize   int64     `json:"body_size,omitempty"`
	BodyHash   string    `json:"body_hash,omitempty"`
	PrevHash   string    `json:"prev_body_hash,omitempty"`
	ChangedAt  time.Time `json:"changed_at,omitzero"`
	ProbeCount int       `json:"probe_count,omitempty"`
	ProbeError string    `json:"probe_error,omitempty"`
}

// Store is a bbolt-backed domain store. It is safe for concurrent use.
//
// Records are keyed by reversed hostname and stored in a packed binary form;
// see codec.go. Values drawn from small vocabularies — the log a name came
// from, the issuing CA, the shape of a probe error — are interned into
// dictionaries rather than repeated in every record.
type Store struct {
	// mu guards the db handle itself, not the data: compaction swaps in a
	// new file, and every other call has to be out of the way when it does.
	// bolt handles concurrency within a handle.
	mu   sync.RWMutex
	db   *bolt.DB
	path string

	sources *dict
	issuers *dict
	errors  *dict
}

// Open opens or creates the database at path.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	s := &Store{
		db:      db,
		path:    path,
		sources: newDict(bucketSources),
		issuers: newDict(bucketIssuers),
		errors:  newDict(bucketErrors),
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketDomains, bucketLogPos, bucketMeta, bucketPending} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		if err := checkFormat(tx); err != nil {
			return err
		}
		for _, d := range []*dict{s.sources, s.issuers, s.errors} {
			if err := d.load(tx); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		if errors.Is(err, ErrLegacyFormat) {
			return nil, err
		}
		return nil, fmt.Errorf("init %s: %w", path, err)
	}
	return s, nil
}

// view and batch run a transaction against the current handle. Taking the
// read lock here rather than inside bolt keeps a compaction from swapping the
// handle out from under a call already in flight.
func (s *Store) view(fn func(*bolt.Tx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db.View(fn)
}

func (s *Store) batch(fn func(*bolt.Tx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db.Batch(fn)
}

// update is batch's uncoalesced sibling, for the writes that are already one
// big transaction and would gain nothing from being merged with another.
func (s *Store) update(fn func(*bolt.Tx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db.Update(fn)
}

// checkFormat stamps the format version on a new database and refuses one
// written by an older version rather than misreading it.
func checkFormat(tx *bolt.Tx) error {
	meta := tx.Bucket(bucketMeta)
	switch v := meta.Get(keyFormat); {
	case v == nil:
		if tx.Bucket(bucketDomains).Stats().KeyN > 0 {
			return ErrLegacyFormat
		}
		return meta.Put(keyFormat, []byte{formatVersion})
	case len(v) == 1 && v[0] == formatVersion:
		return nil
	case len(v) == 1 && v[0] < formatVersion:
		return ErrLegacyFormat
	default:
		return fmt.Errorf("unknown record format %v", v)
	}
}

// Close flushes and closes the database.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

// Get returns the record for host, or nil if the host is unknown.
func (s *Store) Get(host string) (*Record, error) {
	var rec *Record
	err := s.view(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketDomains).Get([]byte(reverseHost(host)))
		if raw == nil {
			return nil
		}
		rec = &Record{}
		return s.decode(host, raw, rec)
	})
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// Update applies fn to the record for host, creating it if absent, and writes
// the result back in a single transaction. fn reports whether the record
// changed; when it returns false the write is skipped.
//
// Update uses bolt's batching, so concurrent callers coalesce into shared
// transactions.
func (s *Store) Update(host string, fn func(rec *Record, existed bool) bool) error {
	return s.UpdateWithQueue(host, func(rec *Record, existed bool) (bool, time.Time) {
		return fn(rec, existed), time.Time{}
	})
}

// UpdateWithQueue is Update plus a pending-queue entry written in the same
// transaction: fn returns the time a probe is due, and a zero time queues
// nothing. Doing both at once is the point — a record that wants a probe and a
// queue entry that says so cannot come apart, whatever happens next.
//
// fn must not read the clock to build that time. bolt may run a batched
// transaction more than once, and a due time that differs between attempts
// leaves a duplicate entry in the queue.
func (s *Store) UpdateWithQueue(host string, fn func(rec *Record, existed bool) (write bool, due time.Time)) error {
	var fresh []freshID
	err := s.batch(func(tx *bolt.Tx) error {
		// bolt may run this more than once if the batch retries, so
		// everything here must be safe to repeat. Dictionary ids are
		// allocated once in memory and rewritten idempotently.
		fresh = fresh[:0]

		b := tx.Bucket(bucketDomains)
		key := []byte(reverseHost(host))
		rec := &Record{Host: host}
		existed := false
		if raw := b.Get(key); raw != nil {
			if err := s.decode(host, raw, rec); err != nil {
				return fmt.Errorf("decode %s: %w", host, err)
			}
			existed = true
		}
		write, due := fn(rec, existed)
		if !write {
			return nil
		}
		raw, ids, err := s.encode(tx, rec)
		if err != nil {
			return fmt.Errorf("encode %s: %w", host, err)
		}
		fresh = ids
		if err := b.Put(key, raw); err != nil {
			return err
		}
		if due.IsZero() {
			return nil
		}
		return enqueue(tx, host, due)
	})
	if err != nil {
		return err
	}
	for _, f := range fresh {
		f.d.confirm(f.id)
	}
	return nil
}

// ForEach calls fn for every record. Records arrive in reversed-hostname
// order, so all names under one domain arrive together. Returning an error
// from fn stops the walk and returns that error.
func (s *Store) ForEach(fn func(*Record) error) error {
	return s.view(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDomains).ForEach(func(k, v []byte) error {
			return s.emit(k, v, fn)
		})
	})
}

// ForEachUnder calls fn for parent and every host beneath it. Reversed keys
// make this a range scan over one contiguous run of the tree rather than a
// walk of the whole store.
func (s *Store) ForEachUnder(parent string, fn func(*Record) error) error {
	prefix := []byte(reverseHost(strings.ToLower(strings.Trim(parent, "."))))
	if len(prefix) == 0 {
		return s.ForEach(fn)
	}
	under := append(append([]byte{}, prefix...), '.')

	return s.view(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketDomains).Cursor()
		for k, v := c.Seek(prefix); k != nil; k, v = c.Next() {
			switch {
			case bytes.Equal(k, prefix):
			case bytes.HasPrefix(k, under):
			default:
				if bytes.Compare(k, under) > 0 {
					return nil
				}
				continue
			}
			if err := s.emit(k, v, fn); err != nil {
				return err
			}
		}
		return nil
	})
}

// emit decodes one stored pair and hands it to fn.
func (s *Store) emit(k, v []byte, fn func(*Record) error) error {
	host := reverseHost(string(k))
	rec := &Record{}
	if err := s.decode(host, v, rec); err != nil {
		return fmt.Errorf("decode %s: %w", host, err)
	}
	return fn(rec)
}

// Stats summarizes the store.
type Stats struct {
	Domains   int
	Sources   int
	Issuers   int
	ErrorKind int
	Bytes     int64
	Probed    int
	WithHash  int
	Wildcards int
	Errors    int
	Changed   int
	Pending   int
	Oldest    time.Time
	Logs      map[string]uint64
}

// Stats walks the store and returns aggregate counts.
func (s *Store) Stats() (Stats, error) {
	st := Stats{Logs: map[string]uint64{}}
	err := s.ForEach(func(r *Record) error {
		st.Domains++
		if r.Probed {
			st.Probed++
		}
		if r.BodyHash != "" {
			st.WithHash++
		}
		if r.FromWildcard {
			st.Wildcards++
		}
		if r.ProbeError != "" {
			st.Errors++
		}
		if r.PrevHash != "" {
			st.Changed++
		}
		return nil
	})
	if err != nil {
		return st, err
	}
	st.Sources, st.Issuers, st.ErrorKind = s.sources.len(), s.issuers.len(), s.errors.len()
	if st.Pending, st.Oldest, err = s.PendingStats(); err != nil {
		return st, err
	}
	err = s.view(func(tx *bolt.Tx) error {
		st.Bytes = tx.Size()
		return tx.Bucket(bucketLogPos).ForEach(func(k, v []byte) error {
			if len(v) == 8 {
				st.Logs[string(k)] = be64(v)
			}
			return nil
		})
	})
	return st, err
}

// be64 reads a big-endian uint64.
func be64(b []byte) uint64 { return binary.BigEndian.Uint64(b) }

// LogPos returns the next unread index for a CT log, and whether a position
// was stored at all.
func (s *Store) LogPos(uri string) (uint64, bool, error) {
	var (
		pos uint64
		ok  bool
	)
	err := s.view(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketLogPos).Get([]byte(uri))
		if len(v) == 8 {
			pos, ok = binary.BigEndian.Uint64(v), true
		}
		return nil
	})
	return pos, ok, err
}

// SetLogPos records the next unread index for a CT log.
func (s *Store) SetLogPos(uri string, pos uint64) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], pos)
	return s.batch(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketLogPos).Put([]byte(uri), buf[:])
	})
}

// compactTxSize bounds how much one compaction transaction copies, which
// bounds its peak memory on a large store.
const compactTxSize = 64 << 20

// Compact rewrites the database into full pages and swaps the result in.
//
// bolt never shrinks a file, and random inserts leave leaf pages about 70%
// full, so a long-running store drifts to roughly twice the size of the
// records it holds. Compaction rewrites every page in key order and gives the
// slack back. The interned dictionaries survive: the copy preserves their ids
// verbatim, so the in-memory tables still describe the new file.
//
// Every other store call blocks for the duration, which on a large store is
// seconds. The original file is replaced by an atomic rename, so an
// interrupted compaction leaves either the old database or the new one, never
// a partial write.
func (s *Store) Compact() (CompactResult, error) {
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
	dst, err := bolt.Open(tmp, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return res, fmt.Errorf("create %s: %w", tmp, err)
	}
	if err := bolt.Compact(dst, s.db, compactTxSize); err != nil {
		dst.Close()
		os.Remove(tmp)
		return res, fmt.Errorf("compact: %w", err)
	}
	_ = dst.View(func(tx *bolt.Tx) error {
		res.NewUsed = tx.Size()
		return nil
	})
	if err := dst.Close(); err != nil {
		os.Remove(tmp)
		return res, err
	}

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

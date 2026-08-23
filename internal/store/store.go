// Package store persists discovered domains and CT log positions in bbolt.
package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
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
	keySeedAt = []byte("pending_seed_cursor")
)

// ErrLegacyFormat says the database predates the packed record format.
var ErrLegacyFormat = errors.New("database uses the old JSON record format; run \"ctmon migrate\"")

// ErrNoDatabase says the path does not name a database that already exists.
var ErrNoDatabase = errors.New("no such database")

// ErrLocked says another process holds the database. In practice that process
// is a run, which keeps bolt's exclusive lock for as long as it lives. What to
// do about it depends on the platform, so the command says that part.
var ErrLocked = errors.New("database is held by another process")

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
	s := newStore(db, path)
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketDomains, bucketLogPos, bucketMeta, bucketPending} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		if err := checkFormat(tx); err != nil {
			return err
		}
		return s.loadDicts(tx)
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

// OpenReadOnly opens an existing database for reading, and refuses to create
// one. The commands that only report on a store want this: a mistyped --db
// path should say so, not conjure an empty database and print zeros about it.
//
// The handle takes a shared lock, so it also refuses a database a run is
// holding rather than waiting on it, with ErrLocked.
func OpenReadOnly(path string) (*Store, error) {
	switch fi, err := os.Stat(path); {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%s: %w", path, ErrNoDatabase)
	case err != nil:
		return nil, err
	case fi.IsDir() || fi.Size() == 0:
		// bolt would try to initialize an empty file even read-only, and
		// fail on the write with something unhelpful.
		return nil, fmt.Errorf("open %s: %w", path, bolt.ErrInvalid)
	}
	// A run holds the write lock for as long as it runs, so waiting on it is
	// waiting for nothing. The timeout is only long enough to ride out the
	// moment a compaction swaps one handle for another.
	db, err := openReadOnly(path, time.Second)
	if err != nil {
		if errors.Is(err, bolt.ErrTimeout) {
			return nil, fmt.Errorf("%s: %w", path, ErrLocked)
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	s := newStore(db, path)
	err = db.View(func(tx *bolt.Tx) error {
		// Open creates the four buckets; a read-only handle cannot. Only
		// domains says the file is a store of ours — a database old enough to
		// predate the format stamp has no meta bucket either, and that is
		// formatOf's business to report, not a reason to disown the file.
		if tx.Bucket(bucketDomains) == nil {
			return ErrNoDatabase
		}
		if _, err := formatOf(tx); err != nil {
			return err
		}
		return s.loadDicts(tx)
	})
	if err != nil {
		db.Close()
		switch {
		case errors.Is(err, ErrNoDatabase):
			return nil, fmt.Errorf("%s: not a ctmon database", path)
		case errors.Is(err, ErrLegacyFormat):
			return nil, err
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return s, nil
}

// openReadOnly opens a database for reading only.
//
// PreLoadFreelist is what the size reports need. bolt fills in
// DB.Stats().FreePageN when it loads the freelist, and a read-only handle
// loads it only on request; a writable one always does. Without it usedBytes
// cannot tell an allocated page from a free one. The cost is reading the
// freelist the file already carries.
//
// Reading it during the open is also what the recover is for. bolt reports a
// freelist page it cannot parse by panicking, and a damaged store has one. A
// command asked to report on such a file should say it cannot read it, not
// print a stack trace, and usedBytesAt promises to return 0 rather than fail
// at all. The half-built handle goes with the panic — one descriptor, on a
// path that ends in the command reporting the error and exiting.
//
// It is a shield, not a guarantee. bolt is not safe against a damaged file
// generally: a page id past the end of a truncated one is a read into the
// mapping's hole, which is a SIGBUS no recover can catch, and the reads these
// commands go on to do would hit the same thing a moment later. What this
// catches is the case the freelist adds — a page inside the file that is not
// the freelist bolt was promised.
func openReadOnly(path string, timeout time.Duration) (db *bolt.DB, err error) {
	defer func() {
		if r := recover(); r != nil {
			db, err = nil, fmt.Errorf("unreadable freelist, the file is truncated or corrupt: %v", r)
		}
	}()
	return bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, PreLoadFreelist: true, Timeout: timeout})
}

// newStore wraps an open handle. The dictionaries start empty and are filled
// by loadDicts inside the transaction that opens the database.
func newStore(db *bolt.DB, path string) *Store {
	return &Store{
		db:      db,
		path:    path,
		sources: newDict(bucketSources),
		issuers: newDict(bucketIssuers),
		errors:  newDict(bucketErrors),
	}
}

// loadDicts reads the interning dictionaries into memory.
func (s *Store) loadDicts(tx *bolt.Tx) error {
	for _, d := range []*dict{s.sources, s.issuers, s.errors} {
		if err := d.load(tx); err != nil {
			return err
		}
	}
	return nil
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
	stamped, err := formatOf(tx)
	if err != nil || stamped {
		return err
	}
	return tx.Bucket(bucketMeta).Put(keyFormat, []byte{formatVersion})
}

// formatOf refuses a database this build would misread, and reports whether
// the version it checked was actually stamped. An unstamped database is
// either brand new or predates the stamp, and only the second is a problem;
// the domains bucket tells the two apart.
//
// It is checkFormat without the write, because a read-only handle has to make
// the same judgement and cannot stamp anything.
func formatOf(tx *bolt.Tx) (stamped bool, err error) {
	// A database with no meta bucket at all predates the stamp too. Open
	// creates the bucket before it asks, so only a read-only handle gets
	// here with one missing.
	var v []byte
	if meta := tx.Bucket(bucketMeta); meta != nil {
		v = meta.Get(keyFormat)
	}
	switch {
	case v == nil:
		if tx.Bucket(bucketDomains).Stats().KeyN > 0 {
			return false, ErrLegacyFormat
		}
		return false, nil
	case len(v) == 1 && v[0] == formatVersion:
		return true, nil
	case len(v) == 1 && v[0] < formatVersion:
		return false, ErrLegacyFormat
	default:
		return false, fmt.Errorf("unknown record format %v", v)
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
//
// It is UpdateWithQueue for a caller with nothing to queue. The pipeline
// always has something to say about a probe, so it takes the other one; this
// is the form for a change to a record on its own.
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
		// Host is set here and not left to decode, which is what fills it in
		// everywhere else: a record being created for the first time never
		// reaches decode, and fn would see a hostname-less record.
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
//
// Bytes is what the file occupies on disk. Used is what its pages hold: bolt
// grows the file in large steps and keeps freed pages for reuse, so Bytes is
// the bigger and lazier number and the gap between the two is slack the store
// can fill without growing.
type Stats struct {
	Domains   int
	Sources   int
	Issuers   int
	ErrorKind int
	Bytes     int64
	Used      int64
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
	// Measured outside the transaction below, because usedBytes opens one of
	// its own and nesting two read transactions on one handle can deadlock
	// against a writer waiting between them.
	st.Used = s.usedBytes()
	// Sized through the path the handle was opened from, which is not quite
	// the same thing as the file it holds: a snapshot lands by renaming a new
	// file over that path, and this handle goes on reading the one it opened.
	// So the stat can describe a different file, or find none at all, and a
	// size is not worth failing a whole stats run over. The high-water mark is
	// the closest number left when it fails.
	if info, err := os.Stat(s.path); err == nil {
		st.Bytes = info.Size()
	}

	err = s.view(func(tx *bolt.Tx) error {
		if st.Bytes == 0 {
			st.Bytes = tx.Size()
		}
		// Absent only on a database a read-only handle opened without being
		// able to create it. See OpenReadOnly.
		b := tx.Bucket(bucketLogPos)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
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
		b := tx.Bucket(bucketLogPos)
		if b == nil {
			return nil
		}
		v := b.Get([]byte(uri))
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

// GetAll returns the records for hosts that exist, keyed by hostname, in one
// read transaction. Hosts with no record are simply absent from the result.
//
// It exists for the backfill sweep, which asks about a whole batch at once and
// was paying for a transaction per host to do it.
func (s *Store) GetAll(hosts []string) (map[string]*Record, error) {
	out := make(map[string]*Record, len(hosts))
	err := s.view(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDomains)
		for _, host := range hosts {
			raw := b.Get([]byte(reverseHost(host)))
			if raw == nil {
				continue
			}
			rec := &Record{}
			if err := s.decode(host, raw, rec); err != nil {
				return fmt.Errorf("decode %s: %w", host, err)
			}
			out[host] = rec
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

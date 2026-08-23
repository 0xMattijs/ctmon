package store

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// legacyRecord is the version-1 JSON record, kept only so old databases can be
// read once and rewritten.
type legacyRecord struct {
	Host string `json:"host"`
	// Databases written before SAN support used "cn"; later ones use
	// "cert_name" and "origin".
	CN           string    `json:"cn"`
	CertName     string    `json:"cert_name"`
	Origin       string    `json:"origin"`
	FromWildcard bool      `json:"from_wildcard"`
	Source       string    `json:"source"`
	Issuer       string    `json:"issuer"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	SeenCount    int       `json:"seen_count"`
	Probed       bool      `json:"probed"`
	ProbedAt     time.Time `json:"probed_at"`
	HTTPStatus   int       `json:"http_status"`
	FinalURL     string    `json:"final_url"`
	BodySize     int64     `json:"body_size"`
	BodyHash     string    `json:"body_hash"`
	PrevHash     string    `json:"prev_body_hash"`
	ChangedAt    time.Time `json:"changed_at"`
	ProbeCount   int       `json:"probe_count"`
	ProbeError   string    `json:"probe_error"`
}

func (l *legacyRecord) record(host string) *Record {
	cert := l.CertName
	if cert == "" {
		cert = l.CN
	}
	return &Record{
		Host:         host,
		CertName:     cert,
		Origin:       l.Origin,
		FromWildcard: l.FromWildcard,
		Source:       l.Source,
		Issuer:       l.Issuer,
		FirstSeen:    l.FirstSeen,
		LastSeen:     l.LastSeen,
		SeenCount:    l.SeenCount,
		Probed:       l.Probed,
		ProbedAt:     l.ProbedAt,
		HTTPStatus:   l.HTTPStatus,
		FinalURL:     l.FinalURL,
		BodySize:     l.BodySize,
		BodyHash:     l.BodyHash,
		PrevHash:     l.PrevHash,
		ChangedAt:    l.ChangedAt,
		ProbeCount:   l.ProbeCount,
		ProbeError:   l.ProbeError,
	}
}

// MigrateResult reports what a migration moved. Bytes come in two flavors:
// what the pages hold, and what the file occupies. bolt grows its file in
// large steps and keeps freed pages for reuse, so the file is the bigger and
// lazier number.
type MigrateResult struct {
	Records  int
	Skipped  int
	LogPos   int
	OldUsed  int64
	NewUsed  int64
	OldBytes int64
	NewBytes int64
}

// migrateChunk is how many records are rewritten per transaction. Big enough
// to amortize the commit, small enough that a huge store does not need a
// transaction the size of itself.
const migrateChunk = 100000

// Migrate rewrites a version-1 JSON database into a new packed one. It reads
// the old file and never writes to it, so the original stays usable if
// anything goes wrong. newPath must not exist.
func Migrate(oldPath, newPath string) (MigrateResult, error) {
	var res MigrateResult

	if _, err := os.Stat(newPath); err == nil {
		return res, fmt.Errorf("%s already exists", newPath)
	} else if !os.IsNotExist(err) {
		return res, err
	}
	info, err := os.Stat(oldPath)
	if err != nil {
		return res, err
	}
	res.OldBytes = info.Size()
	res.OldUsed = usedBytesAt(oldPath)

	old, err := bolt.Open(oldPath, 0o600, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return res, fmt.Errorf("open %s: %w", oldPath, err)
	}
	defer old.Close()
	if err := requireLegacy(old, oldPath); err != nil {
		return res, err
	}

	dst, err := Open(newPath)
	if err != nil {
		return res, err
	}
	// Migrate refuses to start when the target exists, so a destination left
	// behind by a failed run would block the retry. Take it away again.
	done := false
	defer func() {
		dst.Close()
		if !done {
			os.Remove(newPath)
		}
	}()

	// Records first, in chunks: read a batch out of the old store, then write
	// it to the new one in a single transaction.
	var chunk []*Record
	flush := func() error {
		if len(chunk) == 0 {
			return nil
		}
		if err := dst.putAll(chunk); err != nil {
			return err
		}
		res.Records += len(chunk)
		chunk = chunk[:0]
		return nil
	}

	err = old.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDomains)
		if b == nil {
			return fmt.Errorf("%s has no domains bucket", oldPath)
		}
		return b.ForEach(func(k, v []byte) error {
			var l legacyRecord
			if err := json.Unmarshal(v, &l); err != nil {
				res.Skipped++
				return nil
			}
			host := string(k)
			if l.Host != "" {
				host = l.Host
			}
			chunk = append(chunk, l.record(host))
			if len(chunk) >= migrateChunk {
				return flush()
			}
			return nil
		})
	})
	if err != nil {
		return res, err
	}
	if err := flush(); err != nil {
		return res, err
	}
	// Every record unreadable means this is not the database we think it is.
	// Reporting that as a successful migration of zero records, and then
	// inviting the operator to move the empty result over the original, is how
	// a migration tool eats a store.
	if res.Records == 0 && res.Skipped > 0 {
		return res, fmt.Errorf("%s: none of its %d records are version-1 JSON", oldPath, res.Skipped)
	}

	// Then the log positions, so a migrated monitor resumes where it stopped.
	err = old.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketLogPos)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			if len(v) != 8 {
				return nil
			}
			res.LogPos++
			return dst.SetLogPos(string(k), be64(v))
		})
	})
	if err != nil {
		return res, err
	}

	if err := dst.db.Sync(); err != nil {
		return res, err
	}
	if info, err := os.Stat(newPath); err == nil {
		res.NewBytes = info.Size()
	}
	res.NewUsed = dst.usedBytes()
	done = true
	return res, nil
}

// requireLegacy refuses a source that is not a version-1 JSON database.
//
// Pointed at a packed database, Migrate reads every value as JSON, fails on
// every one, and writes an empty result. Catching it here costs one read and
// happens before anything is created.
func requireLegacy(db *bolt.DB, path string) error {
	return db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		if meta == nil {
			return nil // predates the format stamp, so it is version 1
		}
		switch v := meta.Get(keyFormat); {
		case v == nil, len(v) == 1 && v[0] < formatVersion:
			return nil
		case len(v) == 1 && v[0] == formatVersion:
			return fmt.Errorf("%s is already in the packed format", path)
		default:
			return fmt.Errorf("%s uses unknown record format %v", path, v)
		}
	})
}

// putAll writes records in one transaction. It is only used by migration,
// where the records are already complete and need no read-modify-write.
//
// Records are written in key order into near-full pages. A bulk load knows its
// keys in advance, so it has no reason to leave every leaf half empty the way
// bolt does for random inserts.
func (s *Store) putAll(recs []*Record) error {
	type entry struct {
		key string
		rec *Record
	}
	entries := make([]entry, len(recs))
	for i, rec := range recs {
		entries[i] = entry{key: reverseHost(rec.Host), rec: rec}
	}
	slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.key, b.key) })

	var fresh []freshID
	err := s.db.Update(func(tx *bolt.Tx) error {
		fresh = fresh[:0]
		b := tx.Bucket(bucketDomains)
		b.FillPercent = 0.95
		for _, e := range entries {
			raw, ids, err := s.encode(tx, e.rec)
			if err != nil {
				return fmt.Errorf("encode %s: %w", e.rec.Host, err)
			}
			fresh = append(fresh, ids...)
			if err := b.Put([]byte(e.key), raw); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, f := range fresh {
		f.d.confirm(f.id)
	}
	return nil
}

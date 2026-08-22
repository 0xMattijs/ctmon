package store

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
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
	res.OldUsed = usedBytes(oldPath)

	old, err := bolt.Open(oldPath, 0o600, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return res, fmt.Errorf("open %s: %w", oldPath, err)
	}
	defer old.Close()

	dst, err := Open(newPath)
	if err != nil {
		return res, err
	}
	defer dst.Close()

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
	return res, nil
}

// usedBytes reports how many bytes of pages a store holds.
func (s *Store) usedBytes() int64 {
	var n int64
	_ = s.db.View(func(tx *bolt.Tx) error {
		n = tx.Size()
		return nil
	})
	return n
}

// usedBytes opens a database read-only just to measure it. It returns 0 if the
// file cannot be read, since this only ever feeds a progress report.
func usedBytes(path string) int64 {
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return 0
	}
	defer db.Close()
	var n int64
	_ = db.View(func(tx *bolt.Tx) error {
		n = tx.Size()
		return nil
	})
	return n
}

// putAll writes records in one transaction. It is only used by migration,
// where the records are already complete and need no read-modify-write.
//
// Records are written in key order into near-full pages. A bulk load knows its
// keys in advance, so it has no reason to leave every leaf half empty the way
// bolt does for random inserts.
func (s *Store) putAll(recs []*Record) error {
	keys := make(map[*Record]string, len(recs))
	for _, rec := range recs {
		keys[rec] = reverseHost(rec.Host)
	}
	sort.Slice(recs, func(i, j int) bool { return keys[recs[i]] < keys[recs[j]] })

	var fresh []freshID
	err := s.db.Update(func(tx *bolt.Tx) error {
		fresh = fresh[:0]
		b := tx.Bucket(bucketDomains)
		b.FillPercent = 0.95
		for _, rec := range recs {
			raw, ids, err := s.encode(tx, rec)
			if err != nil {
				return fmt.Errorf("encode %s: %w", rec.Host, err)
			}
			fresh = append(fresh, ids...)
			if err := b.Put([]byte(keys[rec]), raw); err != nil {
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

// CompactResult reports what a compaction reclaimed.
type CompactResult struct {
	OldUsed  int64
	NewUsed  int64
	OldBytes int64
	NewBytes int64
}

// Compact rewrites a store into a new file with full pages.
//
// Live writes arrive in random key order, so bolt splits leaves at half full
// and the file drifts toward twice the size it needs. Compaction replays the
// whole tree in key order into fresh, full pages. The source is only read.
func Compact(srcPath, dstPath string) (CompactResult, error) {
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
	res.OldUsed = usedBytes(srcPath)

	src, err := bolt.Open(srcPath, 0o600, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return res, fmt.Errorf("open %s: %w", srcPath, err)
	}
	defer src.Close()

	dst, err := bolt.Open(dstPath, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return res, fmt.Errorf("create %s: %w", dstPath, err)
	}
	// One transaction per 64 MiB keeps peak memory bounded on a large store.
	if err := bolt.Compact(dst, src, 64<<20); err != nil {
		dst.Close()
		return res, fmt.Errorf("compact: %w", err)
	}
	if err := dst.Close(); err != nil {
		return res, err
	}

	if info, err := os.Stat(dstPath); err == nil {
		res.NewBytes = info.Size()
	}
	res.NewUsed = usedBytes(dstPath)
	return res, nil
}

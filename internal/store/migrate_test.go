package store

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// rawLen returns the encoded size of one stored record.
func (s *Store) rawLen(t *testing.T, host string) int {
	t.Helper()
	n := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		n = len(tx.Bucket(bucketDomains).Get([]byte(reverseHost(host))))
		return nil
	})
	if err != nil {
		t.Fatalf("rawLen: %v", err)
	}
	return n
}

// writeLegacyDB builds a version-1 database: JSON values keyed by hostname,
// with no format marker.
func writeLegacyDB(t *testing.T, path string, records map[string]string) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	defer db.Close()

	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketDomains, bucketLogPos, bucketMeta} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		b := tx.Bucket(bucketDomains)
		for host, raw := range records {
			if err := b.Put([]byte(host), []byte(raw)); err != nil {
				return err
			}
		}
		var pos [8]byte
		binary.BigEndian.PutUint64(pos[:], 4242)
		return tx.Bucket(bucketLogPos).Put([]byte("https://ct.example/logs/x"), pos[:])
	})
	if err != nil {
		t.Fatalf("write legacy db: %v", err)
	}
}

func TestMigrate(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.db")
	newPath := filepath.Join(dir, "new.db")

	writeLegacyDB(t, oldPath, map[string]string{
		"example.com": `{"host":"example.com","cert_name":"*.example.com","origin":"cn",
			"from_wildcard":true,"source":"https://ct.example/logs/x","issuer":"WE1",
			"first_seen":"2026-08-21T20:49:54.235102251Z","last_seen":"2026-08-21T20:52:00Z",
			"seen_count":3,"probed":true,"probed_at":"2026-08-21T20:50:09Z","http_status":200,
			"final_url":"https://example.com/","body_size":1503,
			"body_hash":"bd9b4042f1bdcd9a99a5ea9bc85660dab95b11111e636daeb70a876056d5e52f",
			"probe_count":1}`,
		"www.example.com": `{"host":"www.example.com","cn":"*.example.com","first_seen":"2026-08-21T20:49:54Z"}`,
		"broken.example":  `{not json`,
	})

	res, err := Migrate(oldPath, newPath)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if res.Records != 2 {
		t.Errorf("migrated %d records, want 2", res.Records)
	}
	if res.Skipped != 1 {
		t.Errorf("skipped %d records, want 1", res.Skipped)
	}
	if res.LogPos != 1 {
		t.Errorf("migrated %d log positions, want 1", res.LogPos)
	}

	s, err := Open(newPath)
	if err != nil {
		t.Fatalf("open migrated db: %v", err)
	}
	defer s.Close()

	rec, err := s.Get("example.com")
	if err != nil || rec == nil {
		t.Fatalf("get after migrate: %v", err)
	}
	if rec.CertName != "*.example.com" || !rec.FromWildcard || rec.SeenCount != 3 {
		t.Errorf("record lost fields in migration: %+v", rec)
	}
	if rec.BodyHash != "bd9b4042f1bdcd9a99a5ea9bc85660dab95b11111e636daeb70a876056d5e52f" {
		t.Errorf("body hash changed: %q", rec.BodyHash)
	}
	if rec.HTTPStatus != 200 || rec.BodySize != 1503 || rec.FinalURL != "https://example.com/" {
		t.Errorf("probe fields lost: %+v", rec)
	}
	// Sub-second precision is traded away for four-byte timestamps.
	if want := time.Date(2026, 8, 21, 20, 49, 54, 0, time.UTC); !rec.FirstSeen.Equal(want) {
		t.Errorf("first_seen = %v, want %v", rec.FirstSeen, want)
	}

	// The pre-SAN "cn" field lands in cert_name.
	rec, err = s.Get("www.example.com")
	if err != nil || rec == nil {
		t.Fatalf("get www: %v", err)
	}
	if rec.CertName != "*.example.com" {
		t.Errorf("legacy cn field lost: %+v", rec)
	}

	pos, ok, err := s.LogPos("https://ct.example/logs/x")
	if err != nil || !ok || pos != 4242 {
		t.Errorf("log position = %d, %v, %v; want 4242, true, nil", pos, ok, err)
	}
}

func TestMigrateRefusesExistingTarget(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.db")
	newPath := filepath.Join(dir, "new.db")
	writeLegacyDB(t, oldPath, map[string]string{"a.test": `{"host":"a.test"}`})

	s, err := Open(newPath)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	if _, err := Migrate(oldPath, newPath); err == nil {
		t.Fatal("migrate overwrote an existing file")
	} else if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMigrateLeavesOriginalUsable(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.db")
	writeLegacyDB(t, oldPath, map[string]string{"a.test": `{"host":"a.test","seen_count":9}`})

	before, err := bolt.Open(oldPath, 0o600, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	before.Close()

	if _, err := Migrate(oldPath, filepath.Join(dir, "new.db")); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// The original still reads as a legacy database.
	if _, err := Open(oldPath); err == nil {
		t.Error("the original was rewritten in place")
	}
}

func TestCompactShrinksARandomlyWrittenStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "live.db")

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Write in an order that has nothing to do with key order, the way a live
	// feed does, so bolt leaves its pages half empty. Writers run concurrently
	// because bolt batches by waiting: a lone writer pays the batch delay on
	// every call.
	const records = 2000
	now := time.Now().UTC()
	hosts := make([]string, records)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%04d.%s.example.com", (i*7919)%records, []string{"a", "bb", "ccc"}[i%3])
	}

	var wg sync.WaitGroup
	errs := make(chan error, records)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < len(hosts); i += 8 {
				err := s.Update(hosts[i], func(r *Record, _ bool) bool {
					r.FirstSeen, r.LastSeen, r.SeenCount = now, now, 1
					r.Source, r.Issuer = "https://ct.example/logs/x", "Test CA"
					return true
				})
				if err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	res, err := CompactTo(path, filepath.Join(dir, "packed.db"))
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	if res.NewBytes >= res.OldBytes {
		t.Errorf("compaction did not shrink the store: %d -> %d", res.OldBytes, res.NewBytes)
	}

	// Every record must survive, unchanged.
	packed, err := Open(filepath.Join(dir, "packed.db"))
	if err != nil {
		t.Fatalf("open compacted: %v", err)
	}
	defer packed.Close()

	seen := map[string]bool{}
	if err := packed.ForEach(func(r *Record) error { seen[r.Host] = true; return nil }); err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		if !seen[h] {
			t.Fatalf("%s was lost in compaction", h)
		}
	}

	rec, err := packed.Get(hosts[0])
	if err != nil || rec == nil {
		t.Fatalf("record lost in compaction: %v", err)
	}
	if rec.Source != "https://ct.example/logs/x" || rec.Issuer != "Test CA" {
		t.Errorf("dictionaries did not survive compaction: %+v", rec)
	}
}

func TestCompactRefusesExistingTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	if _, err := CompactTo(path, path); err == nil {
		t.Error("compact overwrote an existing file")
	}
}

// A packed database read as JSON yields nothing. Migrate has to say so, rather
// than report a successful migration of zero records and leave an empty file
// the command then offers to move over the original.
func TestMigrateRefusesAPackedDatabase(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "packed.db")
	dst := filepath.Join(dir, "out.db")

	s, err := Open(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"a.example.com", "example.org"} {
		if err := s.Update(host, func(r *Record, existed bool) bool {
			r.FirstSeen, r.LastSeen, r.SeenCount = time.Now(), time.Now(), 1
			return true
		}); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	if _, err := Migrate(src, dst); err == nil {
		t.Fatal("Migrate accepted a packed database")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("refused migration left %s behind", dst)
	}
}

// A database whose records are neither packed nor valid JSON must not migrate
// to an empty store either.
func TestMigrateRefusesAnUnreadableDatabase(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "junk.db")
	dst := filepath.Join(dir, "out.db")

	db, err := bolt.Open(src, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte("domains"))
		if err != nil {
			return err
		}
		return b.Put([]byte("com.example"), []byte("not json"))
	})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	if _, err := Migrate(src, dst); err == nil {
		t.Fatal("Migrate accepted a database with no readable records")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("refused migration left %s behind", dst)
	}
}

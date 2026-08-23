package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestOpenReadOnlyRefusesAPathWithNoDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "typo.dbb")

	s, err := OpenReadOnly(path)
	if err == nil {
		s.Close()
		t.Fatal("OpenReadOnly on a missing file succeeded; want an error")
	}
	if !errors.Is(err, ErrNoDatabase) {
		t.Errorf("err = %v; want ErrNoDatabase", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("OpenReadOnly created %s; it must leave no file behind", path)
	}
}

func TestOpenReadOnlyReadsAnExistingStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	err = w.Update("example.com", func(r *Record, _ bool) bool {
		r.Probed, r.BodyHash = true, digest("body")
		return true
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := w.SetLogPos("https://ct.example/logs/x", 9); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer s.Close()

	rec, err := s.Get("example.com")
	if err != nil || rec == nil {
		t.Fatalf("Get = %v, %v; want the record", rec, err)
	}
	if rec.BodyHash != digest("body") {
		t.Errorf("BodyHash = %q, want the stored digest", rec.BodyHash)
	}
	st, err := s.Stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if st.Domains != 1 || st.Probed != 1 {
		t.Errorf("stats = %+v; want 1 domain, 1 probed", st)
	}
	if st.Logs["https://ct.example/logs/x"] != 9 {
		t.Errorf("log positions = %v", st.Logs)
	}
	if st.Sources != 0 || st.Issuers != 0 {
		t.Errorf("dictionaries = %d sources, %d issuers; want the stored ones", st.Sources, st.Issuers)
	}
}

// The dictionaries have to survive the trip, because a record's source and
// issuer are ids until one of them names it.
func TestOpenReadOnlyLoadsDictionaries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	err = w.Update("example.com", func(r *Record, _ bool) bool {
		r.Source, r.Issuer = "https://ct.example/logs/x", "Example CA"
		return true
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	w.Close()

	s, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer s.Close()

	rec, err := s.Get("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Source != "https://ct.example/logs/x" || rec.Issuer != "Example CA" {
		t.Errorf("record = %q / %q; want the interned names back", rec.Source, rec.Issuer)
	}
}

func TestOpenReadOnlyRefusesWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	w.Close()

	s, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer s.Close()

	if err := s.SetLogPos("https://ct.example/logs/x", 1); err == nil {
		t.Error("SetLogPos on a read-only store succeeded; want an error")
	}
}

func TestOpenReadOnlyRefusesADatabaseAWriterHolds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer w.Close()

	// A shared lock cannot be had while the writer holds an exclusive one, so
	// this waits out bolt's timeout rather than returning at once.
	s, err := OpenReadOnly(path)
	if err == nil {
		s.Close()
		t.Fatal("OpenReadOnly on a held database succeeded; want an error")
	}
	if !strings.Contains(err.Error(), "SIGUSR1") {
		t.Errorf("err = %v; want it to point at the snapshot", err)
	}
}

func TestOpenReadOnlyRefusesAFileThatIsNotADatabase(t *testing.T) {
	dir := t.TempDir()
	cases := map[string][]byte{
		"empty.db": nil,
		"junk.db":  []byte("this is not a bolt database\n"),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			s, err := OpenReadOnly(path)
			if err == nil {
				s.Close()
				t.Fatal("OpenReadOnly succeeded; want an error")
			}
			if !errors.Is(err, bolt.ErrInvalid) {
				t.Errorf("err = %v; want bolt.ErrInvalid", err)
			}
		})
	}
}

// A bolt database that is not this program's still opens, and has to be told
// apart by what is inside it.
func TestOpenReadOnlyRefusesAForeignBoltDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "other.db")
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("something else"))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err := OpenReadOnly(path)
	if err == nil {
		s.Close()
		t.Fatal("OpenReadOnly on a foreign database succeeded; want an error")
	}
	if !strings.Contains(err.Error(), "not a ctmon database") {
		t.Errorf("err = %v; want it to say the file is not a ctmon database", err)
	}
}

func TestOpenReadOnlyRefusesTheLegacyFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	writeLegacyDB(t, path, map[string]string{
		"example.com": `{"host":"example.com","seen_count":1}`,
	})

	s, err := OpenReadOnly(path)
	if err == nil {
		s.Close()
		t.Fatal("OpenReadOnly on a legacy database succeeded; want an error")
	}
	if !errors.Is(err, ErrLegacyFormat) {
		t.Errorf("err = %v; want ErrLegacyFormat", err)
	}
}

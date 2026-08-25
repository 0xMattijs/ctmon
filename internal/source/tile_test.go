package source

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestTileIndexPathSplitsEveryThousand fixes the path encoding against the
// example in the Static CT API, which is the only place the rule is written
// down. Getting it wrong does not fail loudly: it asks for a tile that exists
// at a different index and reads somebody else's entries.
func TestTileIndexPathSplitsEveryThousand(t *testing.T) {
	for _, tc := range []struct {
		n    uint64
		want string
	}{
		{0, "000"},
		{7, "007"},
		{999, "999"},
		{1000, "x001/000"},
		{1234067, "x001/x234/067"},
	} {
		if got := tileIndexPath(tc.n); got != tc.want {
			t.Errorf("tileIndexPath(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

// TestDataTilePathMarksOnlyPartialTiles keeps the suffix off a full tile. The
// two are different resources, and a full tile asked for by its partial name
// is a 404 on every log that has moved past it.
func TestDataTilePathMarksOnlyPartialTiles(t *testing.T) {
	if got, want := dataTilePath(1234067, tileWidth), "tile/data/x001/x234/067"; got != want {
		t.Errorf("full tile path = %q, want %q", got, want)
	}
	if got, want := dataTilePath(2449577, 47), "tile/data/x002/x449/577.p/47"; got != want {
		t.Errorf("partial tile path = %q, want %q", got, want)
	}
}

// TestParseCheckpointReadsTheSize covers the shape a real checkpoint arrives
// in: three header lines, extension lines a monitor does not need, a blank
// line, and more than one signature — logs sign with several keys, and
// Sunlight adds a deliberately unparseable "grease" line to keep clients from
// depending on there being exactly one.
func TestParseCheckpointReadsTheSize(t *testing.T) {
	cp, err := parseCheckpoint([]byte(strings.Join([]string{
		"log.sycamore.ct.letsencrypt.org/2026h2",
		"627091759",
		"fWc5XVUtlOMH14jBCs3jLuguenkmfI/6dm4DGO1adNE=",
		"an extension line this does not read",
		"",
		"— log.sycamore.ct.letsencrypt.org/2026h2 tDM3ZIGjWbxp0OenGg9N+SkFhfKYkcbLGMDgG/H72g==",
		"— grease.invalid r8v4kbJFfNicoEYftQmK6GnVdw==",
		"",
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	if cp.Size != 627091759 {
		t.Errorf("size = %d, want 627091759", cp.Size)
	}
	if cp.Origin != "log.sycamore.ct.letsencrypt.org/2026h2" {
		t.Errorf("origin = %q", cp.Origin)
	}
}

// TestParseCheckpointRejectsWhatIsNotOne is why the signature block is checked
// at all. Nothing here verifies a signature, so the only job left for it is to
// tell a checkpoint apart from the other things an HTTP GET can return — and a
// truncated body or a proxy's error page can easily start with three lines
// that parse. Reading one as a tree of zero entries would leave the log
// silently unread.
func TestParseCheckpointRejectsWhatIsNotOne(t *testing.T) {
	good := "origin\n42\nfWc5XVUtlOMH14jBCs3jLuguenkmfI/6dm4DGO1adNE=\n\n— origin AAAA\n"
	for _, tc := range []struct{ name, body string }{
		{"empty", ""},
		{"header only", "origin\n42\nfWc5XVUtlOMH14jBCs3jLuguenkmfI/6dm4DGO1adNE=\n"},
		{"no signature after the blank line", "origin\n42\nfWc5XVUtlOMH14jBCs3jLuguenkmfI/6dm4DGO1adNE=\n\n"},
		{"two header lines", "origin\n42\n\n— origin AAAA\n"},
		{"size is not a number", "origin\nlots\nfWc5XVUtlOMH14jBCs3jLuguenkmfI/6dm4DGO1adNE=\n\n— origin AAAA\n"},
		{"root hash is the wrong length", "origin\n42\nAAAA\n\n— origin AAAA\n"},
		{"no origin", "\n42\nfWc5XVUtlOMH14jBCs3jLuguenkmfI/6dm4DGO1adNE=\n\n— origin AAAA\n"},
	} {
		if _, err := parseCheckpoint([]byte(tc.body)); err == nil {
			t.Errorf("%s: parseCheckpoint accepted it", tc.name)
		}
	}
	if _, err := parseCheckpoint([]byte(good)); err != nil {
		t.Errorf("parseCheckpoint rejected a good checkpoint: %v", err)
	}
}

// TestParseDataTileReadsARealTile is the one test that can say the framing is
// right, because it is the only one not written against this package's own
// idea of the format. testdata/datatile.bin is the first two entries of tile 0
// of Let's Encrypt's sycamore2026h2 log, byte for byte: an ordinary
// certificate followed by a precertificate, which between them exercise every
// branch in parseDataTile.
//
// Both are that log's own merge-delay monitoring certificates, which is why
// there is a real name in the assertions and no real subscriber behind it.
func TestParseDataTileReadsARealTile(t *testing.T) {
	body, err := os.ReadFile("testdata/datatile.bin")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parseDataTile(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("read %d entries, want 2", len(entries))
	}
	if entries[0].precert {
		t.Error("entry 0 read as a precertificate, want an ordinary certificate")
	}
	if !entries[1].precert {
		t.Error("entry 1 read as an ordinary certificate, want a precertificate")
	}

	// The lengths have to be right as well as the count: an entry framed one
	// field short still leaves 2 entries and a certificate that will not parse.
	feed := &TiledLog{Log: discardLog()}
	for i, e := range entries {
		cert, ok := feed.parseEntry("https://log.example", int64(i), e)
		if !ok {
			t.Fatalf("entry %d carried no usable certificate", i)
		}
		if want := "flowers-to-the-world.com"; cert.CN != want {
			t.Errorf("entry %d CN = %q, want %q", i, cert.CN, want)
		}
		if len(cert.SANs) != 2 || cert.SANs[0] != "flowers-to-the-world.com" {
			t.Errorf("entry %d SANs = %v", i, cert.SANs)
		}
		if cert.Issuer != "Merge Delay Intermediate 1" {
			t.Errorf("entry %d issuer = %q", i, cert.Issuer)
		}
		if cert.Index != int64(i) {
			t.Errorf("entry %d index = %d", i, cert.Index)
		}
	}
}

// TestParseDataTileRefusesABrokenTile keeps a framing error from being read as
// a short tile. Entries are found only in order, so a wrong length puts every
// entry after it at the wrong offset; stopping where the numbers stop adding
// up returns fewer entries and no error, and the follow loop would take that
// as the log having served less than it promised and move on past the gap.
func TestParseDataTileRefusesABrokenTile(t *testing.T) {
	whole, err := os.ReadFile("testdata/datatile.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseDataTile(whole[:len(whole)-1]); err == nil {
		t.Error("parseDataTile accepted a tile with its last entry cut short")
	}
	if _, err := parseDataTile(whole[:20]); err == nil {
		t.Error("parseDataTile accepted a tile cut off inside its first entry")
	}

	// An entry type nothing knows how to frame is unreadable for the same
	// reason: there is no way to tell how long it is, so there is no way to
	// find the entry after it.
	bad := append([]byte(nil), whole...)
	bad[9] = 9
	if _, err := parseDataTile(bad); err == nil {
		t.Error("parseDataTile accepted an unknown entry type")
	}
}

// TestParseDataTileSkipsNothingOnAnUnparsableCertificate keeps the two kinds
// of failure apart. A certificate ct-go cannot read is an ordinary day in CT
// and costs one entry; the tile around it still frames, and the entries after
// it are still delivered.
func TestParseDataTileSkipsNothingOnAnUnparsableCertificate(t *testing.T) {
	tile := append(x509Leaf([]byte("not a certificate")), x509Leaf(testCertDER(t))...)
	entries, err := parseDataTile(tile)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("read %d entries, want 2", len(entries))
	}
	feed := &TiledLog{Log: discardLog()}
	if _, ok := feed.parseEntry("https://log.example", 0, entries[0]); ok {
		t.Error("parseEntry accepted a certificate that is not one")
	}
	if _, ok := feed.parseEntry("https://log.example", 1, entries[1]); !ok {
		t.Error("parseEntry dropped the good certificate after the bad one")
	}
}

// TestRetryAfterReadsBothSpellings covers what RFC 9110 allows in the header,
// and the clamps around it. A log that answers 429 and asks for no wait would
// otherwise have the follower spinning against it.
func TestRetryAfterReadsBothSpellings(t *testing.T) {
	const fallback = 30 * time.Second
	if got := retryAfter("120", fallback); got.Seconds() != 120 {
		t.Errorf("delta-seconds = %v, want 2m", got)
	}
	if got := retryAfter("", fallback); got != fallback {
		t.Errorf("absent header = %v, want the poll interval %v", got, fallback)
	}
	if got := retryAfter("soon", fallback); got != fallback {
		t.Errorf("unparseable header = %v, want the poll interval %v", got, fallback)
	}
	if got := retryAfter("Mon, 24 Aug 2020 13:55:47 GMT", fallback); got.Seconds() != 1 {
		t.Errorf("date in the past = %v, want the one-second floor", got)
	}
	if got := retryAfter("86400", fallback); got != maxThrottleWait {
		t.Errorf("a day = %v, want the %v cap", got, maxThrottleWait)
	}
}

package source

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testCertDER is one ordinary certificate to put in synthetic tiles. What is
// in it barely matters — these tests are about the loop around the entries,
// not the entries — beyond it carrying a name, so that a certificate reaching
// the channel proves the whole path ran.
func testCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tile.example"},
		DNSNames:     []string{"tile.example"},
		NotBefore:    time.Unix(1_700_000_000, 0),
		NotAfter:     time.Unix(1_800_000_000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// x509Leaf frames der as one TileLeaf holding an ordinary certificate: a
// TimestampedEntry with no extensions, and an empty issuer chain after it.
func x509Leaf(der []byte) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint64(b, 1_700_000_000_000) // timestamp
	b = binary.BigEndian.AppendUint16(b, entryTypeX509)
	b = append(b, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
	b = append(b, der...)
	b = binary.BigEndian.AppendUint16(b, 0) // extensions
	b = binary.BigEndian.AppendUint16(b, 0) // certificate_chain
	return b
}

// fakeTiled is a Static CT log serving a checkpoint and data tiles out of a
// list of leaves, with the two answers a real one gives that are not entries:
// a tile it has not published yet, and a refusal to be read this fast.
type fakeTiled struct {
	mu sync.Mutex
	// leaves are the framed entries, one per index.
	leaves [][]byte
	// withheld are tile paths answered as absent, as a log whose checkpoint
	// has run ahead of its storage does.
	withheld map[string]bool
	// throttle is how many more tile requests to refuse with 429.
	throttle int
	// size overrides what the checkpoint reports, so a test can have leaves
	// the log has not counted yet.
	size uint64
	// overserve answers every tile with everything it holds, ignoring the
	// width that was asked for, as a log serving a full tile for a partial
	// request does.
	overserve bool
	// checkpoints and tiles count what was asked for.
	checkpoints int
	tiles       []string
}

func (f *fakeTiled) serve(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/checkpoint", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.checkpoints++
		size := f.size
		if size == 0 {
			size = uint64(len(f.leaves))
		}
		fmt.Fprintf(w, "log.example/test\n%d\n%s\n\n— log.example/test AAAA\n",
			size, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	})
	mux.HandleFunc("/tile/data/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		n, width, err := parseDataTileRequest(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		f.mu.Lock()
		defer f.mu.Unlock()
		f.tiles = append(f.tiles, path)
		if f.throttle > 0 {
			f.throttle--
			w.Header().Set("Retry-After", "1")
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		if f.withheld[path] {
			http.Error(w, "not published", http.StatusNotFound)
			return
		}
		base := n * tileWidth
		if base+uint64(width) > uint64(len(f.leaves)) {
			http.Error(w, "past the tree", http.StatusNotFound)
			return
		}
		end := base + uint64(width)
		if f.overserve {
			end = min(base+tileWidth, uint64(len(f.leaves)))
		}
		for _, leaf := range f.leaves[base:end] {
			w.Write(leaf)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// parseDataTileRequest reads back what dataTilePath wrote, so the fixture
// answers the paths the feed actually asks for rather than a second guess at
// what they should be.
func parseDataTileRequest(path string) (n uint64, width int, err error) {
	rest, ok := strings.CutPrefix(path, "tile/data/")
	if !ok {
		return 0, 0, fmt.Errorf("not a data tile: %q", path)
	}
	width = tileWidth
	if idx, w, partial := strings.Cut(rest, ".p/"); partial {
		if width, err = strconv.Atoi(w); err != nil {
			return 0, 0, fmt.Errorf("bad partial width in %q", path)
		}
		rest = idx
	}
	digits := strings.ReplaceAll(strings.ReplaceAll(rest, "x", ""), "/", "")
	n, err = strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("bad tile index in %q", path)
	}
	return n, width, nil
}

func (f *fakeTiled) publish(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.withheld, path)
}

func (f *fakeTiled) tilesAsked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.tiles...)
}

// tiledOf is a TiledLog wired to uri and paced fast enough for a test to
// watch it.
func tiledOf(uri string, pos Positions) *TiledLog {
	return &TiledLog{
		URIs:              []string{uri},
		Positions:         pos,
		PollInterval:      5 * time.Millisecond,
		RequestsPerSecond: 1000,
		Log:               discardLog(),
	}
}

// runTiled starts feed and stops it when the test ends, collecting whatever it
// emits.
func runTiled(t *testing.T, feed *TiledLog) *certs {
	t.Helper()
	got := &certs{}
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan Cert, 4096)
	go func() {
		for c := range out {
			got.add(c)
		}
	}()
	done := make(chan error, 1)
	go func() { done <- feed.Run(ctx, out) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Run did not return after cancellation")
		}
	})
	return got
}

// certs collects what a feed emitted.
type certs struct {
	mu sync.Mutex
	c  []Cert
}

func (g *certs) add(c Cert) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.c = append(g.c, c)
}

func (g *certs) all() []Cert {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]Cert(nil), g.c...)
}

func (g *certs) len() int { return len(g.all()) }

// tileOf builds a log of n identical entries.
func tileOf(t *testing.T, n int) [][]byte {
	t.Helper()
	leaf := x509Leaf(testCertDER(t))
	leaves := make([][]byte, n)
	for i := range leaves {
		leaves[i] = leaf
	}
	return leaves
}

// TestTiledStartsAtTheTip is the default a discovery tool wants: a log seen
// for the first time is read from where it is now, not from its history.
func TestTiledStartsAtTheTip(t *testing.T) {
	log := &fakeTiled{leaves: tileOf(t, 300)}
	uri := log.serve(t)
	pos := newPositions()

	got := runTiled(t, tiledOf(uri, pos))

	waitFor(t, "the log to be picked up", func() bool { return pos.seen(uri) })
	if p := pos.get(uri); p != 300 {
		t.Errorf("start position = %d, want the tree size 300", p)
	}
	// Give it room to read entries it should not be reading.
	time.Sleep(50 * time.Millisecond)
	if n := got.len(); n != 0 {
		t.Errorf("emitted %d certificates from a log it joined at the tip", n)
	}
	if asked := log.tilesAsked(); len(asked) != 0 {
		t.Errorf("fetched %v, want no tiles at all", asked)
	}
}

// TestTiledFromStartReadsEveryEntry walks a log that is 300 entries long, so
// the read crosses a tile boundary: one full tile of 256 and one partial tile
// of 44, which are different resources with different names.
func TestTiledFromStartReadsEveryEntry(t *testing.T) {
	log := &fakeTiled{leaves: tileOf(t, 300)}
	uri := log.serve(t)
	pos := newPositions()

	feed := tiledOf(uri, pos)
	feed.FromStart = true
	got := runTiled(t, feed)

	waitFor(t, "the whole log to be read", func() bool { return got.len() == 300 })
	if p := pos.get(uri); p != 300 {
		t.Errorf("position after reading = %d, want 300", p)
	}
	for i, c := range got.all() {
		if c.Index != int64(i) {
			t.Fatalf("certificate %d carries index %d", i, c.Index)
		}
		if c.Source != uri {
			t.Fatalf("certificate %d names source %q, want %q", i, c.Source, uri)
		}
	}
	want := []string{"tile/data/000", "tile/data/001.p/44"}
	if asked := log.tilesAsked(); len(asked) < 2 || asked[0] != want[0] || asked[1] != want[1] {
		t.Errorf("fetched %v, want %v first", asked, want)
	}
}

// TestTiledResumesInsideATile is what makes a restart cheap. Positions are
// leaf indexes and tiles are 256 entries wide, so a stored position almost
// never lands on a tile boundary: the tile holding it has to be fetched whole
// and read from the middle.
func TestTiledResumesInsideATile(t *testing.T) {
	log := &fakeTiled{leaves: tileOf(t, 300)}
	uri := log.serve(t)
	pos := newPositions()
	pos.SetLogPos(uri, 100)

	got := runTiled(t, tiledOf(uri, pos))

	waitFor(t, "the rest of the log to be read", func() bool { return got.len() == 200 })
	if first := got.all()[0]; first.Index != 100 {
		t.Errorf("first certificate is index %d, want 100", first.Index)
	}
	if p := pos.get(uri); p != 300 {
		t.Errorf("position after reading = %d, want 300", p)
	}
}

// TestTiledWaitsForATileTheLogHasNotPublished covers the gap between a
// checkpoint and the storage behind it. A log counts an entry in its tree
// before every edge serving its tiles has the tile holding it, and a monitor
// that treated the 404 as a failure would tear down the follower and back off
// for a gap that closes in seconds.
//
// The 5s floor on that backoff is what this asserts against: the entries have
// to arrive faster than a restarted follower could deliver them.
func TestTiledWaitsForATileTheLogHasNotPublished(t *testing.T) {
	log := &fakeTiled{
		leaves:   tileOf(t, 300),
		withheld: map[string]bool{"tile/data/001.p/44": true},
	}
	uri := log.serve(t)
	pos := newPositions()

	feed := tiledOf(uri, pos)
	feed.FromStart = true
	got := runTiled(t, feed)

	waitFor(t, "the published tile to be read", func() bool { return got.len() == 256 })
	log.publish("tile/data/001.p/44")

	start := time.Now()
	waitFor(t, "the rest to arrive once the log publishes it", func() bool { return got.len() == 300 })
	if waited := time.Since(start); waited > 3*time.Second {
		t.Errorf("took %v to notice the tile, which is a follower that restarted", waited)
	}
}

// TestTiledWaitsOutARateLimit is the other refusal that is not a failure.
// Tiles come off ordinary object storage and operators put ordinary rate
// limits in front of it; a log that says "not this fast, come back in a
// second" is asking for a second, not for the exponential backoff a failed
// follower would give it.
func TestTiledWaitsOutARateLimit(t *testing.T) {
	log := &fakeTiled{leaves: tileOf(t, 100), throttle: 1}
	uri := log.serve(t)
	pos := newPositions()

	feed := tiledOf(uri, pos)
	feed.FromStart = true
	got := runTiled(t, feed)

	start := time.Now()
	waitFor(t, "the log to be read after the refusal", func() bool { return got.len() == 100 })
	waited := time.Since(start)
	if waited < time.Second {
		t.Errorf("read the log after %v, ignoring a Retry-After of 1s", waited)
	}
	if waited > 4*time.Second {
		t.Errorf("took %v, which is longer than the log asked for", waited)
	}
}

// TestTiledMaxLagSkipsToTheTip is the same deliberate data loss the RFC 6962
// poller offers, for the same reason: a log this far ahead is serving history
// that reached the store through another log hours ago, and no client is going
// to read its way out of the gap.
func TestTiledMaxLagSkipsToTheTip(t *testing.T) {
	log := &fakeTiled{leaves: tileOf(t, 5000)}
	uri := log.serve(t)
	pos := newPositions()
	pos.SetLogPos(uri, 0) // a known log, hopelessly behind

	feed := tiledOf(uri, pos)
	feed.MaxLag = 1000
	got := runTiled(t, feed)

	waitFor(t, "the position to be skipped forward", func() bool { return pos.get(uri) == 5000 })
	time.Sleep(50 * time.Millisecond)
	if n := got.len(); n != 0 {
		t.Errorf("emitted %d certificates from a log it skipped past", n)
	}
}

// TestTiledKeepsOneLogPerPrefix pins the position key. Monitoring URLs are
// listed with a trailing slash and named without one about as often, and
// positions are keyed by the string: two spellings of one log would read it
// twice, write each other's positions, and — through the refresh — stop and
// start the same follower forever.
func TestTiledKeepsOneLogPerPrefix(t *testing.T) {
	log := &fakeTiled{leaves: tileOf(t, 300)}
	uri := log.serve(t)
	pos := newPositions()

	feed := tiledOf(uri+"/", pos)
	feed.URIs = append(feed.URIs, uri)
	runTiled(t, feed)

	waitFor(t, "the log to be picked up", func() bool { return pos.seen(uri) })
	if pos.seen(uri + "/") {
		t.Error("stored a position under the trailing-slash spelling as well")
	}
	// One follower, so one checkpoint per poll rather than two.
	time.Sleep(50 * time.Millisecond)
	if p := pos.get(uri); p != 300 {
		t.Errorf("position = %d, want the tree size 300 from a single reader", p)
	}
}

// TestTiledRefusesToStartWithoutWhatItNeeds keeps a misconfiguration from
// looking like a quiet log.
func TestTiledRefusesToStartWithoutWhatItNeeds(t *testing.T) {
	out := make(chan Cert)
	if err := (&TiledLog{URIs: []string{"https://log.example"}}).Run(context.Background(), out); err == nil {
		t.Error("ran without a Positions store")
	}
	if err := (&TiledLog{Positions: newPositions()}).Run(context.Background(), out); err == nil {
		t.Error("ran without any logs")
	}
}

// TestTiledIgnoresWhatTheCheckpointDidNotCount covers a log answering a
// partial-tile request with the whole tile, which is a thing logs do and is
// not an error.
//
// Reading it whole would put the position past the size the checkpoint gave,
// and the next pass reads a position past the tree as the tree having shrunk:
// it warns, rewinds to the tip, and does it again on every poll. The entries
// beyond the checkpoint are real, but taking them costs a permanent false
// alarm on a log that is behaving.
func TestTiledIgnoresWhatTheCheckpointDidNotCount(t *testing.T) {
	log := &fakeTiled{leaves: tileOf(t, 300), size: 280, overserve: true}
	uri := log.serve(t)
	pos := newPositions()

	feed := tiledOf(uri, pos)
	feed.FromStart = true
	got := runTiled(t, feed)

	waitFor(t, "the counted entries to be read", func() bool { return pos.get(uri) == 280 })
	// Long enough for a rewind-and-reread cycle to show up as extra entries.
	time.Sleep(100 * time.Millisecond)
	if p := pos.get(uri); p != 280 {
		t.Errorf("position = %d, want the 280 the checkpoint counted", p)
	}
	if n := got.len(); n != 280 {
		t.Errorf("emitted %d certificates, want the 280 the checkpoint counted", n)
	}
}

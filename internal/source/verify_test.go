package source

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
)

// testLog is a log that can sign what it serves, so these tests can check the
// checking rather than only that something was called.
type testLog struct {
	origin string
	priv   *ecdsa.PrivateKey
	key    []byte // SPKI DER, as the log list carries it
}

func newTestLog(t *testing.T, origin string) *testLog {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &testLog{origin: origin, priv: priv, key: der}
}

// entry is this log as the log list hands it over, read at uri.
func (l *testLog) entry(uri string) Log {
	return Log{URI: uri, Key: l.key, Origin: l.origin}
}

func (l *testLog) verifier(t *testing.T) *ct.SignatureVerifier {
	t.Helper()
	v, err := verifierFor(l.key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The signing helpers below panic rather than calling t.Fatal, because the
// fake logs call them from the goroutine serving a request: t.Fatal there
// stops that goroutine and leaves the test waiting for an answer that is never
// coming. Nothing they do can fail on a key this package generated, so a panic
// is the right shape for "this cannot happen" — and net/http turns one into a
// failed request rather than a hang.

// testTimestamp is when every head in these tests claims to have been signed.
// It is covered by the signature, so it has to survive the round trip; the
// value itself means nothing.
const testTimestamp = uint64(1_787_000_000_000)

// sign signs a tree head the way both protocols do — the RFC 6962
// TreeHeadSignature, over the version, the type, the timestamp, the size and
// the root hash.
func (l *testLog) sign(size uint64, root [32]byte) ct.DigitallySigned {
	input, err := ct.SerializeSTHSignatureInput(ct.SignedTreeHead{
		Version:        ct.V1,
		Timestamp:      testTimestamp,
		TreeSize:       size,
		SHA256RootHash: root,
	})
	if err != nil {
		panic(err)
	}
	h := sha256.Sum256(input)
	sig, err := ecdsa.SignASN1(rand.Reader, l.priv, h[:])
	if err != nil {
		panic(err)
	}
	return ct.DigitallySigned{
		Algorithm: tls.SignatureAndHashAlgorithm{Hash: tls.SHA256, Signature: tls.ECDSA},
		Signature: sig,
	}
}

// sth is the tree head an RFC 6962 log would answer get-sth with.
func (l *testLog) sth(size uint64, root [32]byte) *ct.SignedTreeHead {
	return &ct.SignedTreeHead{
		Version:           ct.V1,
		Timestamp:         testTimestamp,
		TreeSize:          size,
		SHA256RootHash:    root,
		TreeHeadSignature: l.sign(size, root),
	}
}

// noteLine is the signature line this log adds to a checkpoint of that size
// and root hash.
func (l *testLog) noteLine(size uint64, root [32]byte) string {
	ds, err := tls.Marshal(tls.DigitallySigned(l.sign(size, root)))
	if err != nil {
		panic(err)
	}
	id := noteKeyID(l.origin, l.key)
	payload := append([]byte(nil), id[:]...)
	payload = binary.BigEndian.AppendUint64(payload, testTimestamp)
	payload = append(payload, ds...)
	return noteSigPrefix + l.origin + " " + base64.StdEncoding.EncodeToString(payload)
}

// checkpointOf is the note this log serves at /checkpoint, with the company a
// real one keeps: a grease line no client can parse, and a witness
// cosignature under a name that is not the log's.
//
// The log's own line is last on purpose. Nothing may depend on its position.
func (l *testLog) checkpointOf(size uint64, root [32]byte) string {
	return strings.Join([]string{
		l.origin,
		strconv.FormatUint(size, 10),
		base64.StdEncoding.EncodeToString(root[:]),
		"",
		noteSigPrefix + "grease.invalid " + base64.StdEncoding.EncodeToString([]byte("not a signature at all")),
		noteSigPrefix + "witness.example " + base64.StdEncoding.EncodeToString(make([]byte, 40)),
		l.noteLine(size, root),
		"",
	}, "\n")
}

// testRoot is a root hash to sign. Nothing checks a tree against it yet, so
// what matters is only that the same 32 bytes go in and come out.
var testRoot = sha256.Sum256([]byte("a tree"))

// TestNoteKeyIDMatchesALiveLog pins the key id derivation against a log that
// exists, because every part of it is a convention this code cannot check for
// itself: the origin is the submission prefix without its scheme, the 0x05
// names the signature type, and the log id is the hash of the key rather than
// the key.
//
// Get any of those wrong and nothing fails loudly — the key id simply matches
// no line in the checkpoint, and every log on the list looks like a log that
// did not sign. So this is a value from outside: the key Let's Encrypt
// publishes for Sycamore 2026h2, and the key id its checkpoint really carries.
func TestNoteKeyIDMatchesALiveLog(t *testing.T) {
	const (
		origin = "log.sycamore.ct.letsencrypt.org/2026h2"
		keyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwR1FtiiMbpvxR+sIeiZ5JSCIDIdT" +
			"APh7OrpdchcrCcyNVDvNUq358pqJx2qdyrOI+EjGxZ7UiPcN3bL3Q99FqA=="
		want = "aee62413"
	)
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		t.Fatal(err)
	}
	id := noteKeyID(origin, key)
	if got := hex.EncodeToString(id[:]); got != want {
		t.Errorf("noteKeyID = %s, want %s", got, want)
	}
}

// TestNoteOriginIsTheSubmissionPrefix covers the other half of that
// derivation. The monitoring URL a tiled log is read at is a different host
// for most operators, so an origin taken from it signs nothing.
func TestNoteOriginIsTheSubmissionPrefix(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"https://log.sycamore.ct.letsencrypt.org/2026h2/", "log.sycamore.ct.letsencrypt.org/2026h2"},
		{"https://tuscolo2026h2.sunlight.geomys.org/", "tuscolo2026h2.sunlight.geomys.org"},
		{"https://luoshu2027.trustasia.com/luoshu2027/", "luoshu2027.trustasia.com/luoshu2027"},
		{"http://local.example/log", "local.example/log"},
	} {
		if got := noteOrigin(c.in); got != c.want {
			t.Errorf("noteOrigin(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestVerifyCheckpointAcceptsTheLogsOwnLine is the ordinary case, and the
// point of it is the company the signature keeps: a grease line that decodes
// to nothing, a cosignature from a witness, and the log's own line last.
func TestVerifyCheckpointAcceptsTheLogsOwnLine(t *testing.T) {
	lg := newTestLog(t, "log.example/2026h2")
	cp := parsed(t, lg.checkpointOf(4321, testRoot))

	if err := verifyCheckpoint(lg.verifier(t), cp, lg.origin, lg.key); err != nil {
		t.Fatalf("verifyCheckpoint: %v", err)
	}
}

// TestVerifyCheckpointRefusesAChangedSize is what the whole exercise is for. A
// log's size is what the follower acts on, so a size that is not the one that
// was signed has to be refused rather than followed.
func TestVerifyCheckpointRefusesAChangedSize(t *testing.T) {
	lg := newTestLog(t, "log.example/2026h2")
	note := lg.checkpointOf(4321, testRoot)
	tampered := strings.Replace(note, "\n4321\n", "\n9999\n", 1)
	if tampered == note {
		t.Fatal("the fixture did not carry the size this test rewrites")
	}
	cp := parsed(t, tampered)

	err := verifyCheckpoint(lg.verifier(t), cp, lg.origin, lg.key)
	if !errors.Is(err, errUntrusted) {
		t.Fatalf("verifyCheckpoint = %v, want errUntrusted", err)
	}
}

// TestVerifyCheckpointRefusesAChangedRootHash covers the other signed field.
// Nothing checks entries against the root hash yet, but the signature covers
// it, so a rewritten one is a rewritten checkpoint.
func TestVerifyCheckpointRefusesAChangedRootHash(t *testing.T) {
	lg := newTestLog(t, "log.example/2026h2")
	cp := parsed(t, lg.checkpointOf(4321, testRoot))
	cp.RootHash[0]++

	err := verifyCheckpoint(lg.verifier(t), cp, lg.origin, lg.key)
	if !errors.Is(err, errUntrusted) {
		t.Fatalf("verifyCheckpoint = %v, want errUntrusted", err)
	}
}

// TestVerifyCheckpointRefusesALogThatDidNotSign is the failure that would go
// unnoticed if lines were picked by position or by the name in front of them:
// a checkpoint carrying signatures, none of them the log's.
func TestVerifyCheckpointRefusesALogThatDidNotSign(t *testing.T) {
	lg := newTestLog(t, "log.example/2026h2")
	other := newTestLog(t, "someone.else.example/2026h2")
	note := strings.Join([]string{
		lg.origin,
		"4321",
		base64.StdEncoding.EncodeToString(testRoot[:]),
		"",
		noteSigPrefix + "grease.invalid " + base64.StdEncoding.EncodeToString([]byte("nonsense")),
		// Signed under the log's name, by somebody who is not the log.
		strings.Replace(other.noteLine(4321, testRoot), other.origin, lg.origin, 1),
		"",
	}, "\n")
	cp := parsed(t, note)

	err := verifyCheckpoint(lg.verifier(t), cp, lg.origin, lg.key)
	if !errors.Is(err, errUntrusted) {
		t.Fatalf("verifyCheckpoint = %v, want errUntrusted", err)
	}
}

// TestVerifyCheckpointRefusesAnotherLogsCheckpoint is the answer to a
// misconfigured or misredirected monitoring URL: a perfectly good checkpoint,
// correctly signed, from the wrong log.
func TestVerifyCheckpointRefusesAnotherLogsCheckpoint(t *testing.T) {
	lg := newTestLog(t, "log.example/2026h2")
	cp := parsed(t, lg.checkpointOf(4321, testRoot))

	err := verifyCheckpoint(lg.verifier(t), cp, "log.example/2027h1", lg.key)
	if !errors.Is(err, errUntrusted) {
		t.Fatalf("verifyCheckpoint = %v, want errUntrusted", err)
	}
}

// TestVerifyAcceptsALogWithNoKey is what --logs and --tiled-logs rest on: a
// log named on the command line has no key, and is followed without being
// checked rather than refused.
func TestVerifyAcceptsALogWithNoKey(t *testing.T) {
	v, err := verifierFor(nil)
	if err != nil {
		t.Fatalf("verifierFor(nil) = %v", err)
	}
	if v != nil {
		t.Fatal("verifierFor(nil) built a verifier")
	}
	lg := newTestLog(t, "log.example/2026h2")
	// A checkpoint signed by somebody else entirely, which is exactly what an
	// unchecked log is allowed to serve.
	cp := parsed(t, newTestLog(t, "other.example/2026h2").checkpointOf(1, testRoot))
	if err := verifyCheckpoint(v, cp, lg.origin, nil); err != nil {
		t.Errorf("verifyCheckpoint with no key = %v, want nil", err)
	}
	if err := verifySTH(v, lg.sth(1, testRoot)); err != nil {
		t.Errorf("verifySTH with no key = %v, want nil", err)
	}
}

// TestVerifierForRefusesAKeyItCannotRead separates "no key was given" from "a
// key was given and this cannot use it". The first is a choice; the second
// means nothing the log says can be checked, and is treated as the log being
// untrustworthy rather than as a bad flag, because the effect is the same.
func TestVerifierForRefusesAKeyItCannotRead(t *testing.T) {
	if _, err := verifierFor([]byte("not a key")); !errors.Is(err, errUntrusted) {
		t.Fatalf("verifierFor = %v, want errUntrusted", err)
	}
}

// TestVerifySTHRefusesAChangedSize is the RFC 6962 half of the same promise.
func TestVerifySTHRefusesAChangedSize(t *testing.T) {
	lg := newTestLog(t, "")
	sth := lg.sth(4321, testRoot)
	if err := verifySTH(lg.verifier(t), sth); err != nil {
		t.Fatalf("verifySTH on an untouched head: %v", err)
	}
	sth.TreeSize = 9999
	if err := verifySTH(lg.verifier(t), sth); !errors.Is(err, errUntrusted) {
		t.Fatalf("verifySTH = %v, want errUntrusted", err)
	}
}

// TestNoteSignatureStepsOverWhatItCannotRead pins the tolerance the greasing
// is there to demand. A line that is not base64, one too short to hold a key
// id, and one that is not a signature line at all all have to be walked past
// rather than reported — the log's own line is behind them.
func TestNoteSignatureStepsOverWhatItCannotRead(t *testing.T) {
	lg := newTestLog(t, "log.example/2026h2")
	block := strings.Join([]string{
		"this is not a signature line",
		noteSigPrefix + "no.base64.example !!!!not base64!!!!",
		noteSigPrefix + "tooshort.example AAA=",
		noteSigPrefix + "nospaceafterthedash",
		lg.noteLine(7, testRoot),
	}, "\n")

	if _, ok := noteSignature(block, noteKeyID(lg.origin, lg.key)); !ok {
		t.Fatal("noteSignature did not find the log's line behind the unreadable ones")
	}
}

// TestParseNoteSignatureRefusesWhatIsNotOne keeps a line that happens to carry
// the right key id from being read as a signature it is not.
func TestParseNoteSignatureRefusesWhatIsNotOne(t *testing.T) {
	lg := newTestLog(t, "log.example/2026h2")
	good, ok := noteSignature(lg.checkpointOf(7, testRoot), noteKeyID(lg.origin, lg.key))
	if !ok {
		t.Fatal("the fixture carries no signature from the log")
	}
	for _, c := range []struct {
		name string
		sig  []byte
	}{
		{"too short for a timestamp", good[:4]},
		{"nothing after the timestamp", good[:8]},
		{"trailing bytes", append(append([]byte(nil), good...), 0)},
	} {
		if _, _, err := parseRFC6962NoteSignature(c.sig); err == nil {
			t.Errorf("%s: parsed without error", c.name)
		}
	}
}

// parsed reads a checkpoint the way the feed does, failing the test if it will
// not parse at all.
func parsed(t *testing.T, note string) checkpoint {
	t.Helper()
	cp, err := parseCheckpoint([]byte(note))
	if err != nil {
		t.Fatalf("parseCheckpoint: %v", err)
	}
	return cp
}

// TestVerifyCheckpointNamesAMissingOrigin covers a log list that carries a key
// for a tiled log and no submission URL to derive the origin from. Nothing can
// be checked without it, and the refusal is permanent, so the line that
// reports it has to point at the list rather than at the log — "want \"\"" sends
// whoever reads it looking at the checkpoint.
func TestVerifyCheckpointNamesAMissingOrigin(t *testing.T) {
	lg := newTestLog(t, "log.example/2026h2")
	cp := parsed(t, lg.checkpointOf(4321, testRoot))

	err := verifyCheckpoint(lg.verifier(t), cp, "", lg.key)
	if !errors.Is(err, errUntrusted) {
		t.Fatalf("verifyCheckpoint = %v, want errUntrusted", err)
	}
	if !strings.Contains(err.Error(), "submission URL") {
		t.Errorf("error is %q; it does not say the log list is what is missing something", err)
	}
}

package source

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
)

// This file is what ctmon checks about what a log tells it.
//
// Both readers land here. The STH an RFC 6962 log serves and the checkpoint a
// Static CT log serves are the same statement — this log, this many entries,
// this root hash, signed with this key — written two ways, so they are checked
// against one key with one verifier and refused the same way.
//
// What this does not do is worth being as clear about as what it does. It
// checks the head a log publishes and nothing underneath it: no tile or entry
// is checked against the root hash that was just verified, so a log that signs
// an honest checkpoint and serves fabricated tiles beside it passes here. Nor
// does it catch omission — a log can under-report its size, or show this
// monitor one view and everyone else another, and sign both honestly. Catching
// those needs the level-0 tiles hashed up to the root, consistency proofs
// between heads, and gossip with other monitors. This is the floor all three
// are built on, not a substitute for any of them.

// errUntrusted is a log whose signature did not check out.
//
// It is deliberately not an ordinary failure. Everything else a follower hits
// — a timeout, a 500, a tile that has not landed yet — is a log having a bad
// minute, and the answer is to wait and ask again. A signature that does not
// verify is either the wrong key or a log serving something it did not sign,
// and neither improves by asking a fourth time. So it does not go through the
// backoff: the follower says so at error volume and stops, which is the one
// outcome an operator has to see rather than find later in a counter.
var errUntrusted = errors.New("signature did not verify")

// verifierFor builds the verifier for a log's SPKI DER public key. It returns
// a nil verifier, and no error, for a log that came without one.
//
// A missing key is not a failure here. A log named with --logs or --tiled-logs
// has no list entry to take a key from, and refusing to follow it would take
// those flags away from anyone pointing this at a log that is not on Chrome's
// list — a test log, a private one, one being brought up. The run says which
// logs it cannot check, once and out loud, rather than each reader forming its
// own opinion about it.
//
// A key that is present and will not parse is a different thing and is an
// error: the list said what the log signs with and this cannot read it, so
// nothing the log says can be checked. That is reported as errUntrusted rather
// than as a bad configuration, because the effect is the same — this log
// cannot be believed — and the reaction should be too.
func verifierFor(key []byte) (*ct.SignatureVerifier, error) {
	if len(key) == 0 {
		return nil, nil
	}
	pk, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: parse log key: %v", errUntrusted, err)
	}
	v, err := ct.NewSignatureVerifier(pk)
	if err != nil {
		return nil, fmt.Errorf("%w: log key: %v", errUntrusted, err)
	}
	return v, nil
}

// verifySTH checks the signature on an RFC 6962 tree head. A nil verifier is a
// log with no key, and checks nothing.
//
// This is done here rather than by handing jsonclient.Options a PublicKeyDER,
// which would also verify, because of what comes back when it fails: ct-go
// wraps the verification error in an RspError carrying the 200 the log
// answered with, which is the same shape a malformed response gets. Telling a
// bad signature from a bad minute would come down to matching on the text of
// somebody else's error message, and the whole point of separating the two is
// that they get different reactions. Verifying here costs one ECDSA operation
// per poll and leaves the distinction in this package, next to the tiled half
// that has to be written out by hand regardless.
func verifySTH(v *ct.SignatureVerifier, sth *ct.SignedTreeHead) error {
	if v == nil {
		return nil
	}
	if err := v.VerifySTHSignature(*sth); err != nil {
		return fmt.Errorf("%w: %v", errUntrusted, err)
	}
	return nil
}

// noteKeyID is the four bytes that pick a log's own line out of a checkpoint.
//
// A signed note names its signatures by a key id, and the Static CT API fixes
// what that is for an RFC6962NoteSignature: the first four bytes of
//
//	SHA-256(origin || 0x0A || 0x05 || log_id)
//
// where 0x05 identifies the signature type and log_id is SHA-256 of the log's
// public key. It has to be computed and cannot be read off the log list, which
// gives the log id; this is the only thing that turns one into the other.
//
// Note what the id binds: the origin as well as the key. A checkpoint signed
// by the right key for a different log has a different id and is never even
// considered, which is why the origin is worth carrying from the list rather
// than taking from the checkpoint that is being checked.
func noteKeyID(origin string, key []byte) [4]byte {
	logID := sha256.Sum256(key)
	h := sha256.New()
	h.Write([]byte(origin))
	h.Write([]byte{0x0A, 0x05})
	h.Write(logID[:])
	var id [4]byte
	copy(id[:], h.Sum(nil))
	return id
}

// verifyCheckpoint checks a Static CT checkpoint against the log's key. A nil
// verifier is a log with no key, and checks nothing.
//
// origin is the log's submission prefix as a schema-less URL, from the log
// list. It is checked against the checkpoint's first line before anything
// else — not because the signature would otherwise pass, since the key id
// binds the origin and a mismatch simply finds no line, but because "this
// checkpoint is for a different log" is worth saying in those words rather
// than as "no signature from this log".
func verifyCheckpoint(v *ct.SignatureVerifier, cp checkpoint, origin string, key []byte) error {
	if v == nil {
		return nil
	}
	if origin == "" {
		// Reachable from a log list that carries a key for a tiled log and no
		// submission URL to derive the origin from. Nothing can be checked
		// without it, and it is worth saying that rather than reporting the
		// empty string as the origin that was wanted.
		return fmt.Errorf("%w: the log list gave no submission URL to derive %q's origin from",
			errUntrusted, cp.Origin)
	}
	if cp.Origin != origin {
		return fmt.Errorf("%w: checkpoint is for %q, want %q", errUntrusted, cp.Origin, origin)
	}
	want := noteKeyID(origin, key)
	sig, ok := noteSignature(cp.Sigs, want)
	if !ok {
		return fmt.Errorf("%w: no signature from key id %x", errUntrusted, want)
	}
	timestamp, ds, err := parseRFC6962NoteSignature(sig)
	if err != nil {
		return fmt.Errorf("%w: %v", errUntrusted, err)
	}
	sth := ct.SignedTreeHead{
		Version:        ct.V1,
		Timestamp:      timestamp,
		TreeSize:       cp.Size,
		SHA256RootHash: cp.RootHash,
	}
	input, err := ct.SerializeSTHSignatureInput(sth)
	if err != nil {
		return fmt.Errorf("%w: %v", errUntrusted, err)
	}
	if err := v.VerifySignature(input, ds); err != nil {
		return fmt.Errorf("%w: %v", errUntrusted, err)
	}
	return nil
}

// noteSigPrefix opens every signature line in a signed note: an em dash and a
// space, then the signer's name, then the base64 of the key id and signature.
const noteSigPrefix = "— "

// noteSignature finds the signature carrying key id want, and returns what
// follows the id.
//
// A note carries as many signatures as anyone cared to add, and picking the
// right one by anything but its key id is a mistake waiting for the day a log
// adds another. Both Sunlight and Sycamore deliberately sign one line as
// "grease.invalid" with bytes no client can parse, precisely so that a client
// which assumed there was exactly one signature breaks in testing rather than
// in production; Sunlight logs are also cosigned by witnesses, and three of
// the logs on Google's list sign more than once under their own name. Measured
// across the 22 tiled logs on that list, checkpoints carry one to four lines.
//
// So the name in front of a line is not read, unparseable lines are stepped
// over rather than reported, and position means nothing.
func noteSignature(block string, want [4]byte) ([]byte, bool) {
	for _, line := range strings.Split(block, "\n") {
		rest, ok := strings.CutPrefix(line, noteSigPrefix)
		if !ok {
			continue
		}
		// name, then base64. A name never contains a space, so the last
		// field is the signature and the rest is the name this does not read.
		i := strings.LastIndexByte(rest, ' ')
		if i < 0 {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(rest[i+1:])
		if err != nil || len(raw) < 4 {
			continue
		}
		if bytes.Equal(raw[:4], want[:]) {
			return raw[4:], true
		}
	}
	return nil, false
}

// parseRFC6962NoteSignature reads what a Static CT log signs a checkpoint
// with, which is an RFC 6962 tree head signature with the timestamp lifted out
// in front of it:
//
//	struct {
//		uint64 timestamp;
//		TreeHeadSignature signature;
//	} RFC6962NoteSignature;
//
// The timestamp is out here because the note's text has no room for it and the
// signature covers it, so a verifier needs it before it can rebuild what was
// signed. TreeHeadSignature is an ordinary TLS digitally-signed struct, which
// ct-go already knows how to read.
//
// Trailing bytes are refused rather than ignored. Nothing follows the
// signature in this structure, so anything that does means this is not the
// structure it was taken for.
func parseRFC6962NoteSignature(b []byte) (uint64, tls.DigitallySigned, error) {
	var ds tls.DigitallySigned
	if len(b) < 8 {
		return 0, ds, fmt.Errorf("note signature is %d bytes, want at least 8", len(b))
	}
	timestamp := binary.BigEndian.Uint64(b[:8])
	rest, err := tls.Unmarshal(b[8:], &ds)
	if err != nil {
		return 0, ds, fmt.Errorf("tree head signature: %v", err)
	}
	if len(rest) != 0 {
		return 0, ds, fmt.Errorf("tree head signature: %d bytes left over", len(rest))
	}
	return timestamp, ds, nil
}

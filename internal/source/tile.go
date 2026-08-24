package source

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// This file is the Static CT API (c2sp.org/static-ct-api) wire format, and
// nothing else: how a checkpoint is spelled, where a tile lives, and how the
// entries inside one are framed. The follow loop that uses it is in tiled.go.
//
// It is written out here rather than taken from a library because there is no
// library to take it from: certificate-transparency-go speaks RFC 6962 and
// knows nothing about tiles. What it does have — the x509 parser that accepts
// the certificates Go's own rejects — is what this feeds.

// tileWidth is how many entries a full tile holds. The API fixes the tile
// height at 8, so this is not a tuning knob: it is the unit the log publishes
// in, and reading anything else means reading a tile and throwing part away.
const tileWidth = 256

// Entry types, from RFC 6962 section 3.1. A Static CT data tile carries the
// same TimestampedEntry, so it carries the same two.
const (
	entryTypeX509    = 0
	entryTypePrecert = 1
)

// checkpoint is a Static CT log's head: which log it is, how many entries it
// has, what its tree hashes to, and who says so. It is the tiled equivalent of
// an STH, and read for the same reason — to learn where the log ends before
// walking towards it.
//
// Every field of it is needed to check the signature, which is why the root
// hash and the signature block are carried rather than glanced at. The
// checking itself is in verify.go: this file is the wire format and holds no
// opinion about whether the bytes it read can be believed.
type checkpoint struct {
	// Origin identifies the log, and is its submission prefix as a
	// schema-less URL — "log.sycamore.ct.letsencrypt.org/2026h2". It is not
	// the monitoring URL this was fetched from and is not derivable from it,
	// so it is checked against the origin the log list gave rather than
	// against anything here.
	Origin string
	// Size is the number of entries in the tree.
	Size uint64
	// RootHash is what the tree of that size hashes to. Nothing read out of
	// the log is checked against it yet — that needs the level-0 tiles hashed
	// up to the root — but it is what the log signed, so verifying the
	// signature needs it.
	RootHash [32]byte
	// Sigs is the signature block verbatim: everything after the blank line,
	// one signature per line. It is kept whole rather than parsed here
	// because which line matters depends on a key the wire format knows
	// nothing about.
	Sigs string
}

// parseCheckpoint reads the signed note a Static CT log serves at /checkpoint.
//
// The note is a text block, a blank line, and one or more signature lines. The
// first three text lines are the origin, the tree size, and the root hash;
// anything after them is an extension this does not need and steps over.
//
// The blank line is required, and so is a signature after it. Neither is used
// here, which is exactly why they are checked: a truncated body or a CDN error
// page can easily start with three plausible lines, and "the tree has
// 0 entries" is a much worse way to find out than an error is.
func parseCheckpoint(body []byte) (checkpoint, error) {
	text, sigs, ok := strings.Cut(string(body), "\n\n")
	if !ok {
		return checkpoint{}, fmt.Errorf("checkpoint: no signature block")
	}
	if strings.TrimSpace(sigs) == "" {
		return checkpoint{}, fmt.Errorf("checkpoint: no signature lines")
	}
	lines := strings.Split(text, "\n")
	if len(lines) < 3 {
		return checkpoint{}, fmt.Errorf("checkpoint: %d header lines, want at least 3", len(lines))
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return checkpoint{}, fmt.Errorf("checkpoint: tree size %q: %w", lines[1], err)
	}
	hash, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return checkpoint{}, fmt.Errorf("checkpoint: root hash: %w", err)
	}
	if len(hash) != 32 {
		return checkpoint{}, fmt.Errorf("checkpoint: root hash is %d bytes, want 32", len(hash))
	}
	if lines[0] == "" {
		return checkpoint{}, fmt.Errorf("checkpoint: empty origin line")
	}
	cp := checkpoint{Origin: lines[0], Size: size, Sigs: sigs}
	copy(cp.RootHash[:], hash)
	return cp, nil
}

// dataTilePath is where the entries numbered [n*tileWidth, n*tileWidth+width)
// are served, relative to the log's monitoring prefix. A width of tileWidth
// asks for the full tile; anything less asks for the partial one.
//
// A partial tile is a different resource, not a range of the full one, and it
// stops existing as soon as the log grows past it. That is why width comes
// from the checkpoint that was just read rather than from anything cached.
func dataTilePath(n uint64, width int) string {
	p := "tile/data/" + tileIndexPath(n)
	if width < tileWidth {
		p += ".p/" + strconv.Itoa(width)
	}
	return p
}

// tileIndexPath spells a tile index as the API's path segments: three decimal
// digits per segment, every segment but the last prefixed with "x", so index
// 1234067 is "x001/x234/067".
//
// The point of the split is that it keeps any one directory of a log's static
// storage down to a thousand entries, which is the difference between a bucket
// listing that works and one that does not.
func tileIndexPath(n uint64) string {
	s := fmt.Sprintf("%03d", n%1000)
	for n >= 1000 {
		n /= 1000
		s = fmt.Sprintf("x%03d/%s", n%1000, s)
	}
	return s
}

// tileEntry is one entry read out of a data tile: the DER of the certificate
// it carries, and whether that DER is a TBSCertificate rather than a whole
// certificate.
//
// The DER is a slice of the tile, not a copy. Nothing keeps it past the parse.
type tileEntry struct {
	der     []byte
	precert bool
}

// parseDataTile splits one data tile into its entries.
//
// An entry is a TimestampedEntry followed by the extra data the tile adds to
// it, and every field is length-prefixed, so entries can only be found in
// order: there is no index and no separator to resync on. That makes a framing
// error fatal for the whole tile — everything after the bad length is
// unreadable — which is the opposite of how a certificate that fails to parse
// is treated. One is a broken tile and the other is an ordinary day in CT.
//
// The layout, from the Static CT API:
//
//	struct {
//	    TimestampedEntry timestamped_entry;    // RFC 6962 section 3.4
//	    select (entry_type) {
//	        case x509_entry: Empty;
//	        case precert_entry: ASN.1Cert pre_certificate;
//	    };
//	    Fingerprint certificate_chain<0..2^16-1>;
//	} TileLeaf;
//
// Note that the leaf starts at the TimestampedEntry, without RFC 6962's
// MerkleTreeLeaf version and leaf-type bytes in front of it.
//
// For a precertificate the entry carries the certificate twice: the
// TBSCertificate inside the TimestampedEntry, and the submitted
// precertificate after it. The TBSCertificate is the one taken, because it is
// what the RFC 6962 path already reads and it carries the same names.
func parseDataTile(b []byte) ([]tileEntry, error) {
	var entries []tileEntry
	r := &tileReader{b: b}
	for !r.done() {
		start := len(b) - len(r.b)
		r.skip(8) // timestamp
		entryType := r.uint16()
		var e tileEntry
		switch entryType {
		case entryTypeX509:
			e.der = r.vector(3)
		case entryTypePrecert:
			r.skip(32) // issuer_key_hash
			e.der, e.precert = r.vector(3), true
		default:
			// A read that ran off the end reports -1 here, and the length it
			// wanted is the more useful thing to say.
			if r.err != nil {
				return nil, fmt.Errorf("entry %d at offset %d: %w", len(entries), start, r.err)
			}
			return nil, fmt.Errorf("entry %d at offset %d: entry type %d", len(entries), start, entryType)
		}
		r.vector(2) // extensions, which carry the leaf index we already know
		if entryType == entryTypePrecert {
			r.vector(3) // the submitted precertificate, in favour of its TBS
		}
		r.vector(2) // issuer chain fingerprints, which say nothing about names
		if r.err != nil {
			return nil, fmt.Errorf("entry %d at offset %d: %w", len(entries), start, r.err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// tileReader walks a tile, holding the first error rather than returning one
// at every step. Reading past the end is the only thing that can go wrong, and
// checking for it after each of six fields would bury the format the fields
// spell out.
type tileReader struct {
	b   []byte
	err error
}

func (r *tileReader) done() bool { return r.err != nil || len(r.b) == 0 }

// take removes the next n bytes, or records that they were not there.
func (r *tileReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = fmt.Errorf("want %d bytes, %d left", n, len(r.b))
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *tileReader) skip(n int) { r.take(n) }

func (r *tileReader) uint16() int {
	b := r.take(2)
	if b == nil {
		return -1
	}
	return int(binary.BigEndian.Uint16(b))
}

// vector reads a length-prefixed field whose length occupies prefix bytes.
// TLS presentation language writes those big-endian, in as few bytes as the
// declared maximum needs: two for <0..2^16-1>, three for <0..2^24-1>.
func (r *tileReader) vector(prefix int) []byte {
	b := r.take(prefix)
	if b == nil {
		return nil
	}
	n := 0
	for _, c := range b {
		n = n<<8 | int(c)
	}
	return r.take(n)
}

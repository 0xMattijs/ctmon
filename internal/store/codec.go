package store

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// formatVersion is the on-disk record format. Version 1 was JSON.
const formatVersion = 2

// Record layout, version 2. Every field that can be derived from the key is
// derived, every value drawn from a small vocabulary is interned, and
// timestamps are seconds since the epoch rather than formatted strings.
//
//	byte     version
//	byte     flags1
//	uvarint  source id      (dictionary)
//	uvarint  issuer id      (dictionary)
//	uint32   first seen, unix seconds
//	uvarint  last seen  - first seen
//	uvarint  seen count
//	[bytes]  cert name, only when it is not derivable from the host
//	when probed:
//	  byte     flags2
//	  uvarint  probed at - first seen
//	  uvarint  http status
//	  uvarint  probe count
//	  uvarint  body size
//	  [32]byte body hash
//	  [32]byte previous body hash
//	  uvarint  changed at - first seen
//	  uvarint  probe error template id (dictionary)
//	  [bytes]  final URL, only when it is not https://<host>/
const (
	flagWildcard = 1 << 0
	// bits 1-2 hold the origin, bits 3-5 the cert-name shape.
	originShift = 1
	originMask  = 0x3
	certShift   = 3
	certMask    = 0x7
	flagProbed  = 1 << 6
	// flagProbeBlock says the probe section follows. It is distinct from
	// flagProbed so that a record carrying probe data without the flag — or
	// the flag without data — survives a round trip intact.
	flagProbeBlock = 1 << 7
	flagHasBody    = 1 << 0
	flagHasPrev    = 1 << 1
	flagChanged    = 1 << 2
	flagProbeErr   = 1 << 3
	flagURLLit     = 1 << 4
	flagURLAbsent  = 1 << 5
)

// Cert-name shapes. Most records need no bytes at all for the certificate name
// because it is the host, the host with a wildcard, or the wildcard over the
// apex a www host sits under.
const (
	certEmpty = iota
	certHost
	certWildHost
	certWildApex
	certLiteral
)

// Origin codes.
const (
	originNone = iota
	originCN
	originSAN
)

const (
	originCNName  = "cn"
	originSANName = "san"
)

// hostMark stands in for the hostname inside an interned probe error, so the
// thousands of "no such host" messages collapse to one dictionary entry.
const hostMark = "\x01"

// encode packs rec into its stored form. It interns strings through tx and
// returns the dictionary ids that still need confirming once the write commits.
func (s *Store) encode(tx *bolt.Tx, rec *Record) ([]byte, []freshID, error) {
	var fresh []freshID

	srcID, f, err := s.sources.intern(tx, rec.Source)
	if err != nil {
		return nil, nil, err
	}
	fresh = appendFresh(fresh, s.sources, srcID, f)

	issID, f, err := s.issuers.intern(tx, rec.Issuer)
	if err != nil {
		return nil, nil, err
	}
	fresh = appendFresh(fresh, s.issuers, issID, f)

	shape, literal := certShape(rec.Host, rec.CertName)
	flags1 := byte(shape&certMask) << certShift
	if rec.FromWildcard {
		flags1 |= flagWildcard
	}
	flags1 |= byte(originCode(rec.Origin)&originMask) << originShift
	if rec.Probed {
		flags1 |= flagProbed
	}
	if hasProbeData(rec) {
		flags1 |= flagProbeBlock
	}

	first := unixSec(rec.FirstSeen)
	out := make([]byte, 0, 48)
	out = append(out, formatVersion, flags1)
	out = binary.AppendUvarint(out, uint64(srcID))
	out = binary.AppendUvarint(out, uint64(issID))
	out = binary.BigEndian.AppendUint32(out, first)
	out = binary.AppendUvarint(out, uint64(delta(rec.LastSeen, first)))
	out = binary.AppendUvarint(out, uint64(rec.SeenCount))
	if shape == certLiteral {
		out = appendString(out, literal)
	}

	if flags1&flagProbeBlock == 0 {
		return out, fresh, nil
	}

	var (
		flags2 byte
		errID  uint32
	)
	// A digest is 64 hex characters or nothing. Anything else is a bug in the
	// caller, and dropping it silently would lose the very field the store
	// exists to keep.
	if rec.BodyHash != "" {
		if len(rec.BodyHash) != 64 {
			return nil, nil, fmt.Errorf("body hash is %d characters, want 64", len(rec.BodyHash))
		}
		flags2 |= flagHasBody
	}
	if rec.PrevHash != "" {
		if len(rec.PrevHash) != 64 {
			return nil, nil, fmt.Errorf("previous body hash is %d characters, want 64", len(rec.PrevHash))
		}
		flags2 |= flagHasPrev
	}
	if !rec.ChangedAt.IsZero() {
		flags2 |= flagChanged
	}
	if rec.ProbeError != "" {
		flags2 |= flagProbeErr
		errID, f, err = s.errors.intern(tx, templatize(rec.Host, rec.ProbeError))
		if err != nil {
			return nil, nil, err
		}
		fresh = appendFresh(fresh, s.errors, errID, f)
	}
	switch {
	case rec.FinalURL == "":
		flags2 |= flagURLAbsent
	case rec.FinalURL != derivedURL(rec.Host):
		flags2 |= flagURLLit
	}

	out = append(out, flags2)
	out = binary.AppendUvarint(out, uint64(delta(rec.ProbedAt, first)))
	out = binary.AppendUvarint(out, uint64(rec.HTTPStatus))
	out = binary.AppendUvarint(out, uint64(rec.ProbeCount))
	out = binary.AppendUvarint(out, uint64(rec.BodySize))
	if flags2&flagHasBody != 0 {
		h, err := hexBytes(rec.BodyHash)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, h...)
	}
	if flags2&flagHasPrev != 0 {
		h, err := hexBytes(rec.PrevHash)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, h...)
	}
	if flags2&flagChanged != 0 {
		out = binary.AppendUvarint(out, uint64(delta(rec.ChangedAt, first)))
	}
	if flags2&flagProbeErr != 0 {
		out = binary.AppendUvarint(out, uint64(errID))
	}
	if flags2&flagURLLit != 0 {
		out = appendString(out, rec.FinalURL)
	}
	return out, fresh, nil
}

// decode unpacks a stored record. host comes from the key, and everything
// derived from it is rebuilt here.
func (s *Store) decode(host string, raw []byte, rec *Record) error {
	r := reader{b: raw}
	version := r.byte()
	if version != formatVersion {
		return fmt.Errorf("record format %d, want %d", version, formatVersion)
	}
	flags1 := r.byte()

	rec.Host = host
	rec.FromWildcard = flags1&flagWildcard != 0
	rec.Origin = originName(int(flags1>>originShift) & originMask)
	rec.Probed = flags1&flagProbed != 0

	rec.Source = s.sources.name(uint32(r.uvarint()))
	rec.Issuer = s.issuers.name(uint32(r.uvarint()))
	first := r.uint32()
	rec.FirstSeen = fromUnix(first)
	rec.LastSeen = fromUnix(first + uint32(r.uvarint()))
	rec.SeenCount = int(r.uvarint())

	shape := int(flags1>>certShift) & certMask
	if shape == certLiteral {
		rec.CertName = r.string()
	} else {
		rec.CertName = certName(shape, host)
	}

	if flags1&flagProbeBlock == 0 {
		return r.err
	}

	flags2 := r.byte()
	rec.ProbedAt = fromUnix(first + uint32(r.uvarint()))
	rec.HTTPStatus = int(r.uvarint())
	rec.ProbeCount = int(r.uvarint())
	rec.BodySize = int64(r.uvarint())
	if flags2&flagHasBody != 0 {
		rec.BodyHash = r.hex(32)
	}
	if flags2&flagHasPrev != 0 {
		rec.PrevHash = r.hex(32)
	}
	if flags2&flagChanged != 0 {
		rec.ChangedAt = fromUnix(first + uint32(r.uvarint()))
	}
	if flags2&flagProbeErr != 0 {
		rec.ProbeError = expand(host, s.errors.name(uint32(r.uvarint())))
	}
	switch {
	case flags2&flagURLLit != 0:
		rec.FinalURL = r.string()
	case flags2&flagURLAbsent != 0:
		rec.FinalURL = ""
	default:
		rec.FinalURL = derivedURL(host)
	}
	return r.err
}

// hasProbeData reports whether any probe field is set, so the probe section is
// written whenever there is something in it.
func hasProbeData(rec *Record) bool {
	return rec.Probed ||
		rec.BodyHash != "" || rec.PrevHash != "" || rec.ProbeError != "" ||
		rec.FinalURL != "" || rec.HTTPStatus != 0 || rec.ProbeCount != 0 ||
		rec.BodySize != 0 || !rec.ProbedAt.IsZero() || !rec.ChangedAt.IsZero()
}

// certShape classifies a certificate name against its host, so the common
// cases cost no bytes.
func certShape(host, cert string) (int, string) {
	switch {
	case cert == "":
		return certEmpty, ""
	case cert == host:
		return certHost, ""
	case cert == "*."+host:
		return certWildHost, ""
	case strings.HasPrefix(host, "www.") && cert == "*."+host[4:]:
		return certWildApex, ""
	default:
		return certLiteral, cert
	}
}

func certName(shape int, host string) string {
	switch shape {
	case certHost:
		return host
	case certWildHost:
		return "*." + host
	case certWildApex:
		return "*." + strings.TrimPrefix(host, "www.")
	default:
		return ""
	}
}

func originCode(origin string) int {
	switch origin {
	case originCNName:
		return originCN
	case originSANName:
		return originSAN
	default:
		return originNone
	}
}

func originName(code int) string {
	switch code {
	case originCN:
		return originCNName
	case originSAN:
		return originSANName
	default:
		return ""
	}
}

func derivedURL(host string) string { return "https://" + host + "/" }

// templatize replaces the hostname inside a probe error with a marker, so
// errors that differ only by host share one dictionary entry.
func templatize(host, msg string) string {
	if host == "" {
		return msg
	}
	return strings.ReplaceAll(msg, host, hostMark)
}

func expand(host, tmpl string) string {
	return strings.ReplaceAll(tmpl, hostMark, host)
}

// unixSec clamps a time to the uint32 unix range. Zero times stay zero.
func unixSec(t time.Time) uint32 {
	if t.IsZero() {
		return 0
	}
	sec := t.Unix()
	if sec < 0 {
		return 0
	}
	if sec > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(sec)
}

// delta returns t as an offset from base, clamped at zero. Records whose
// later timestamps precede their first sighting are malformed, not fatal.
func delta(t time.Time, base uint32) uint32 {
	sec := unixSec(t)
	if sec <= base {
		return 0
	}
	return sec - base
}

func fromUnix(sec uint32) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(int64(sec), 0).UTC()
}

func appendString(dst []byte, s string) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(s)))
	return append(dst, s...)
}

// hexBytes decodes a 64-character hex digest into its 32 raw bytes.
func hexBytes(s string) ([]byte, error) {
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hi, ok1 := hexVal(s[i*2])
		lo, ok2 := hexVal(s[i*2+1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("digest %q is not hex", s)
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

const hexDigits = "0123456789abcdef"

// reader walks an encoded record. Past the end it yields zeroes and records an
// error, so a truncated value cannot panic.
type reader struct {
	b   []byte
	i   int
	err error
}

func (r *reader) fail() {
	if r.err == nil {
		r.err = fmt.Errorf("record truncated at byte %d of %d", r.i, len(r.b))
	}
}

func (r *reader) byte() byte {
	if r.i >= len(r.b) {
		r.fail()
		return 0
	}
	c := r.b[r.i]
	r.i++
	return c
}

func (r *reader) uvarint() uint64 {
	v, n := binary.Uvarint(r.b[min(r.i, len(r.b)):])
	if n <= 0 {
		r.fail()
		return 0
	}
	r.i += n
	return v
}

func (r *reader) uint32() uint32 {
	if r.i+4 > len(r.b) {
		r.fail()
		return 0
	}
	v := binary.BigEndian.Uint32(r.b[r.i:])
	r.i += 4
	return v
}

func (r *reader) take(n int) []byte {
	if n < 0 || r.i+n > len(r.b) {
		r.fail()
		return nil
	}
	b := r.b[r.i : r.i+n]
	r.i += n
	return b
}

func (r *reader) string() string { return string(r.take(int(r.uvarint()))) }

// hex reads n raw bytes and renders them as a lowercase hex digest.
func (r *reader) hex(n int) string {
	raw := r.take(n)
	if raw == nil {
		return ""
	}
	out := make([]byte, n*2)
	for i, c := range raw {
		out[i*2] = hexDigits[c>>4]
		out[i*2+1] = hexDigits[c&0xf]
	}
	return string(out)
}

// dict interns a small vocabulary — log URIs, issuers, error templates — into
// integer ids. Ids are allocated in memory and written inside the same
// transaction as the record that first uses them; confirm marks them durable
// once that transaction commits, so a rolled-back write leaves no dangling id.
type dict struct {
	bucket    []byte
	mu        sync.Mutex
	ids       map[string]uint32
	names     map[uint32]string
	persisted map[uint32]bool
	next      uint32
}

// freshID is a dictionary entry written but not yet known to be durable.
type freshID struct {
	d  *dict
	id uint32
}

func appendFresh(dst []freshID, d *dict, id uint32, fresh bool) []freshID {
	if fresh {
		return append(dst, freshID{d: d, id: id})
	}
	return dst
}

func newDict(bucket string) *dict {
	return &dict{
		bucket:    []byte(bucket),
		ids:       map[string]uint32{"": 0},
		names:     map[uint32]string{0: ""},
		persisted: map[uint32]bool{0: true},
		next:      1,
	}
}

// load reads a dictionary from its bucket.
func (d *dict) load(tx *bolt.Tx) error {
	b := tx.Bucket(d.bucket)
	if b == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return b.ForEach(func(k, v []byte) error {
		if len(k) != 4 {
			return fmt.Errorf("dictionary %s: bad key", d.bucket)
		}
		id := binary.BigEndian.Uint32(k)
		name := string(v)
		d.ids[name] = id
		d.names[id] = name
		d.persisted[id] = true
		if id >= d.next {
			d.next = id + 1
		}
		return nil
	})
}

// intern returns the id for name, writing the entry through tx if it is not
// known to be durable yet. The bool reports whether the caller must confirm.
func (d *dict) intern(tx *bolt.Tx, name string) (uint32, bool, error) {
	d.mu.Lock()
	id, ok := d.ids[name]
	if !ok {
		id = d.next
		d.next++
		d.ids[name] = id
		d.names[id] = name
	}
	durable := d.persisted[id]
	d.mu.Unlock()

	if durable {
		return id, false, nil
	}
	b, err := tx.CreateBucketIfNotExists(d.bucket)
	if err != nil {
		return 0, false, err
	}
	var key [4]byte
	binary.BigEndian.PutUint32(key[:], id)
	if err := b.Put(key[:], []byte(name)); err != nil {
		return 0, false, err
	}
	return id, true, nil
}

// confirm marks ids durable after their transaction committed.
func (d *dict) confirm(id uint32) {
	d.mu.Lock()
	d.persisted[id] = true
	d.mu.Unlock()
}

func (d *dict) name(id uint32) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.names[id]
}

func (d *dict) len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.names) - 1 // the empty string is not an entry
}

// reverseHost flips a hostname label by label: www.example.com becomes
// com.example.www. Stored that way, every name under one domain sorts
// together, which keeps related records on the same pages and makes "all
// hosts under example.com" a range scan instead of a full walk.
//
// reverseHost is its own inverse.
func reverseHost(host string) string {
	if !strings.Contains(host, ".") {
		return host
	}
	labels := strings.Split(host, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".")
}

package store

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Every error a prober actually produces has to come back out exactly as it
// went in, whatever was lifted out of it on the way.
func TestProbeErrorRoundTrips(t *testing.T) {
	cases := []struct {
		name string
		host string
		err  string
		args int // values expected to move onto the record
	}{
		{
			name: "no address at all",
			host: "www.example.com",
			err:  `Get "https://www.example.com/": EOF`,
		},
		{
			name: "one ipv4",
			host: "www.example.com",
			err:  `Get "https://www.example.com/": dial tcp 178.142.12.95:443: connect: connection refused`,
			args: 1,
		},
		{
			name: "ipv6 in brackets",
			host: "www.example.com",
			err:  `Get "https://www.example.com/": dial tcp [2606:4700:4700::1111]:443: i/o timeout`,
			args: 1,
		},
		{
			name: "two addresses",
			host: "www.example.com",
			err:  `dial tcp 10.0.0.1:443 -> 192.168.1.1:80: no route`,
			args: 2,
		},
		{
			name: "a foreign hostname stays in the template",
			host: "www.example.com",
			err:  `dial tcp: lookup acisji.com.br: i/o timeout`,
		},
		{
			name: "host that is itself an address",
			host: "93.184.216.34",
			err:  `Get "https://93.184.216.34/": dial tcp 93.184.216.34:443: connect: connection refused`,
			args: 0, // both occurrences leave through hostMark, not argMark
		},
		{
			name: "something that only looks like an address",
			host: "www.example.com",
			err:  `unsupported protocol version 1.2.3.4 reported`,
			args: 1, // ParseIP accepts it; it round-trips regardless
		},
		{
			name: "digits but no address",
			host: "www.example.com",
			err:  `Get "https://www.example.com/": unexpected status 502`,
		},
		{
			name: "utf-8 survives the byte walk",
			host: "www.example.com",
			err:  `Get "https://www.example.com/": ünexpected — 10.0.0.9:443 · EOF`,
			args: 1,
		},
		// An address is only lifted when net.IP.String renders it back
		// exactly as it was written. These four are all valid addresses that
		// it would re-spell, so they stay in the template: a record has to
		// come back as the text the prober produced, not as the same address
		// written another way. Every one of them is reachable from an address
		// quoted out of a redirect target or a certificate rather than
		// formatted by Go.
		{
			name: "ipv6 written out in full",
			host: "www.example.com",
			err:  `Get "https://www.example.com/": dial tcp [2606:4700:4700:0:0:0:0:1111]:443: i/o timeout`,
		},
		{
			name: "ipv6 in capitals",
			host: "www.example.com",
			err:  `Get "https://www.example.com/": dial tcp [2606:4700:4700::AAAA]:443: i/o timeout`,
		},
		{
			name: "ipv4-mapped ipv6, which is not even the same notation",
			host: "www.example.com",
			err:  `Get "https://www.example.com/": dial tcp [::ffff:1.2.3.4]:443: i/o timeout`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tmpl, args := templatize(c.host, c.err)
			if len(args) != c.args {
				t.Errorf("lifted %d values, want %d (template %q)", len(args), c.args, tmpl)
			}
			if got := expand(c.host, tmpl, args); got != c.err {
				t.Errorf("round trip:\n got %q\nwant %q\n via %q", got, c.err, tmpl)
			}
		})
	}
}

// The point of lifting the address out: errors that differ only by address
// become one dictionary entry instead of one each.
func TestErrorsDifferingOnlyByAddressShareAnEntry(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	addrs := []string{"178.142.12.95", "46.29.238.201", "38.207.187.34", "10.0.0.1"}
	for i, addr := range addrs {
		host := string(rune('a'+i)) + ".example.com"
		withError(t, s, host, "src", "CA",
			`Get "https://`+host+`/": dial tcp `+addr+`:443: connect: connection refused`, now)
	}
	if got := s.errors.len(); got != 1 {
		t.Errorf("%d error shapes for %d addresses; want 1", got, len(addrs))
	}
	// And each record still reports the address it actually failed against.
	for i, addr := range addrs {
		host := string(rune('a'+i)) + ".example.com"
		rec, err := s.Get(host)
		if err != nil || rec == nil {
			t.Fatalf("get %s: %v", host, err)
		}
		if !strings.Contains(rec.ProbeError, addr) {
			t.Errorf("%s lost its address: %q does not mention %s", host, rec.ProbeError, addr)
		}
	}
}

// A version-2 record has no argument list and must still read. This is the
// whole reason the version byte is per record.
func TestDecodeReadsAVersionTwoRecord(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	host := "old.example.com"

	// Version 2 interned the error whole, address and all, and set no
	// flagErrArgs. Build that by hand.
	whole := `Get "https://` + host + `/": dial tcp 178.142.12.95:443: connect: connection refused`
	var id uint32
	err := s.update(func(tx *bolt.Tx) error {
		var err error
		id, _, err = s.errors.intern(tx, strings.ReplaceAll(whole, host, hostMark))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	s.errors.confirm(id)

	raw := buildV2Record(id, now)
	if err := s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDomains).Put([]byte(reverseHost(host)), raw)
	}); err != nil {
		t.Fatal(err)
	}

	rec, err := s.Get(host)
	if err != nil {
		t.Fatalf("decoding a version 2 record: %v", err)
	}
	if rec.ProbeError != whole {
		t.Errorf("version 2 error = %q; want %q", rec.ProbeError, whole)
	}
	if !rec.Probed {
		t.Error("version 2 record lost its probed flag")
	}
}

// The sweep must not mistake a version 2 record's entry for an unused one.
//
// Its error interns as the whole string, address included, because that is how
// version 2 wrote it. Asking what that text would intern to today gives the
// masked template instead, which the dictionary has never heard of — so the
// entry the record actually points at looks unreferenced, and sweeping it
// leaves the record with no error at all. That is silent data loss on every
// pre-existing record, reachable by running prune once.
func TestSweepKeepsAVersionTwoErrorEntry(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	host := "old.example.com"
	whole := `Get "https://` + host + `/": dial tcp 178.142.12.95:443: connect: connection refused`

	var id uint32
	if err := s.update(func(tx *bolt.Tx) error {
		var err error
		id, _, err = s.errors.intern(tx, strings.ReplaceAll(whole, host, hostMark))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s.errors.confirm(id)
	if err := s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDomains).Put([]byte(reverseHost(host)), buildV2Record(id, now))
	}); err != nil {
		t.Fatal(err)
	}

	res, err := s.SweepDicts()
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.Errors != 0 {
		t.Errorf("sweep dropped %d error shapes; the version 2 record still uses its own", res.Errors)
	}
	rec, err := s.Get(host)
	if err != nil || rec == nil {
		t.Fatalf("get: %v, %v", rec, err)
	}
	if rec.ProbeError != whole {
		t.Errorf("version 2 record lost its error:\n got %q\nwant %q", rec.ProbeError, whole)
	}
}

// A record naming a version this build does not know is refused, not guessed
// at. That is what keeps an older build from misreading a version 3 record.
func TestDecodeRefusesAnUnknownVersion(t *testing.T) {
	s := open(t)
	for _, v := range []byte{formatOldest - 1, formatVersion + 1} {
		raw := []byte{v, 0}
		var rec Record
		if err := s.decode("x.example.com", raw, &rec); err == nil {
			t.Errorf("decode of version %d = nil; want a refusal", v)
		}
	}
}

// A corrupt argument count must not be believed.
func TestDecodeSurvivesACorruptArgumentCount(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	withError(t, s, "a.example.com", "src", "CA",
		`Get "https://a.example.com/": dial tcp 10.0.0.1:443: refused`, now)

	var raw []byte
	if err := s.view(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketDomains).Get([]byte(reverseHost("a.example.com")))
		raw = append([]byte{}, v...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Truncating mid-argument is what a damaged page looks like.
	for _, cut := range []int{len(raw) - 1, len(raw) - 3, len(raw) / 2} {
		if cut <= 2 {
			continue
		}
		var rec Record
		if err := s.decode("a.example.com", raw[:cut], &rec); err == nil {
			t.Errorf("decode of a record cut to %d bytes = nil; want a refusal", cut)
		}
	}
}

// buildV2Record hand-assembles the version 2 layout: no argument list, and the
// error interned whole.
func buildV2Record(errID uint32, now time.Time) []byte {
	first := unixSec(now)
	out := []byte{formatOldest, flagProbed | flagProbeBlock}
	out = binary.AppendUvarint(out, 0) // source
	out = binary.AppendUvarint(out, 0) // issuer
	out = binary.BigEndian.AppendUint32(out, first)
	out = binary.AppendUvarint(out, 0) // last seen delta
	out = binary.AppendUvarint(out, 1) // seen count
	out = append(out, flagProbeErr|flagURLAbsent)
	out = binary.AppendUvarint(out, 0) // probed at delta
	out = binary.AppendUvarint(out, 0) // status
	out = binary.AppendUvarint(out, 1) // probe count
	out = binary.AppendUvarint(out, 0) // body size
	return binary.AppendUvarint(out, uint64(errID))
}

// An argument length that only looks sane once narrowed to a 32-bit int must
// be refused, the same as any other length-prefixed field.
//
// On a 64-bit build take catches this on its own. On GOARCH=386 or arm the
// conversion happens first, take succeeds on the five bytes the truncated
// length asks for, and the decoder walks on through a record it has lost its
// place in — returning a wrong FinalURL with no error to say so. The uint64
// comparison in bytes is what catches it there.
func TestDecodeRejectsAnArgumentLengthThatTruncates(t *testing.T) {
	s := open(t)
	now := time.Now().UTC().Truncate(time.Second)
	first := unixSec(now)

	raw := []byte{formatVersion, flagProbed | flagProbeBlock}
	raw = binary.AppendUvarint(raw, 0) // source
	raw = binary.AppendUvarint(raw, 0) // issuer
	raw = binary.BigEndian.AppendUint32(raw, first)
	raw = binary.AppendUvarint(raw, 0) // last seen delta
	raw = binary.AppendUvarint(raw, 1) // seen count
	raw = append(raw, flagProbeErr|flagErrArgs|flagURLAbsent)
	raw = binary.AppendUvarint(raw, 0)       // probed at delta
	raw = binary.AppendUvarint(raw, 0)       // status
	raw = binary.AppendUvarint(raw, 1)       // probe count
	raw = binary.AppendUvarint(raw, 0)       // body size
	raw = binary.AppendUvarint(raw, 0)       // error shape id
	raw = binary.AppendUvarint(raw, 1)       // one argument
	raw = binary.AppendUvarint(raw, 1<<32|5) // narrows to 5 on a 32-bit int
	raw = append(raw, "hello"...)

	var rec Record
	if err := s.decode("example.com", raw, &rec); err == nil {
		t.Errorf("decode accepted an argument length of %d, reading %q",
			uint64(1<<32|5), rec.ProbeError)
	}
}

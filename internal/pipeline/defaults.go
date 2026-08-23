package pipeline

import (
	_ "embed"
	"strings"
	"time"
)

// Default filter settings. These are on by default because CT's noise is
// overwhelmingly platform tenants, and a monitor that stores them all buries
// the discoveries worth looking at.
const (
	// DefaultParentCap is the number of new hosts accepted per registrable
	// domain per DefaultParentWindow.
	DefaultParentCap = 20
	// DefaultParentWindow is the cap's reset interval.
	DefaultParentWindow = 10 * time.Minute
	// DefaultMaxDepth keeps hosts within one label of their registrable
	// domain.
	DefaultMaxDepth = 1
	// DefaultRecentHosts is how many hostnames the in-memory duplicate
	// filter remembers. It is sized to hold a few minutes of intake, which
	// is where the feeds' repetition lives.
	DefaultRecentHosts = 50000
	// DefaultWorkers is how many probes run at once.
	//
	// It was 16, which with a shared 20-per-second limit put the ceiling at
	// about 15 probes a second against an intake of 108 hostnames a second:
	// the monitor fell seven names behind for every one it fetched. Probes
	// wait on the network rather than on a CPU, so the useful number is set
	// by how many sockets and lookups are in flight, not by cores.
	DefaultWorkers = 256
	// DefaultBackfillLease is how long a host handed to a prober stays out of
	// the pending queue.
	//
	// It has to outlast the whole batch, not one probe: a sweep leases up to
	// BackfillBatch hosts at once and they wait their turn in memory, so with
	// 5,000 of them a five-minute lease expired on anything slower than 17
	// hosts a second and the next sweep handed the same work out again. The
	// cost of setting it long is that a host lost to a killed process waits
	// this long to come back; the cost of setting it short is fetching things
	// twice while already behind.
	DefaultBackfillLease = 30 * time.Minute
	// DefaultDeferBackoff is how long a host waits after its address turned
	// it away for being over budget.
	DefaultDeferBackoff = 30 * time.Second
)

//go:embed skiplist.txt
var defaultSkipList string

// DefaultSkipSuffixes is the built-in blocklist of hosting platforms, compiled
// into the binary from skiplist.txt. It is a starting point, not a maintained
// list: add to it with --skip-suffix and --skip-suffix-file, or drop it with
// --default-skip=false.
func DefaultSkipSuffixes() []string { return ParseSuffixList(defaultSkipList) }

// ParseSuffixList splits a blocklist written as lines, commas, or both, and
// strips "#" comments. It is the one parser behind the built-in list, the
// --skip-suffix flag, and --skip-suffix-file.
func ParseSuffixList(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		for _, entry := range strings.Split(line, ",") {
			if entry = strings.TrimSpace(entry); entry != "" {
				out = append(out, entry)
			}
		}
	}
	return out
}

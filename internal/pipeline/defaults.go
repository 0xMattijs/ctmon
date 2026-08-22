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

package pipeline

import (
	"strings"
	"sync"
	"time"

	"github.com/mvo/ct/internal/domain"
)

// SuffixSet blocks hosts at or under any of a set of parent domains. It is
// how you mute a hosting platform: one entry for workers.dev drops every
// tenant under it.
type SuffixSet map[string]struct{}

// NewSuffixSet builds a set from suffixes. Entries are normalized the same way
// hostnames are, and empty or malformed entries are ignored.
func NewSuffixSet(suffixes []string) SuffixSet {
	if len(suffixes) == 0 {
		return nil
	}
	set := make(SuffixSet, len(suffixes))
	for _, s := range suffixes {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, "*.")
		s = strings.Trim(s, ".")
		if s == "" {
			continue
		}
		set[s] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// Blocks reports whether host is one of the suffixes or sits under one.
func (s SuffixSet) Blocks(host string) bool {
	if len(s) == 0 {
		return false
	}
	for rest := host; rest != ""; {
		if _, ok := s[rest]; ok {
			return true
		}
		i := strings.Index(rest, ".")
		if i < 0 {
			return false
		}
		rest = rest[i+1:]
	}
	return false
}

// parentCap limits how many hosts under one registrable domain are accepted
// per window. It bounds the damage from a platform that mints thousands of
// tenant names an hour without needing that platform named in advance.
//
// The window is fixed, not sliding: a parent's count resets the first time it
// is seen after the window elapses. Counts live in memory only, so a restart
// starts every parent fresh.
type parentCap struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	seen   map[string]*parentCount
}

type parentCount struct {
	n     int
	start time.Time
}

func newParentCap(limit int, window time.Duration) *parentCap {
	if limit <= 0 {
		return nil
	}
	if window <= 0 {
		window = time.Hour
	}
	return &parentCap{limit: limit, window: window, seen: map[string]*parentCount{}}
}

// allow charges host against its parent's budget and reports whether it fits.
// The registrable domain itself is always allowed and never charged: it is the
// one name under a parent that is never noise.
func (c *parentCap) allow(host string, now time.Time) bool {
	if c == nil {
		return true
	}
	parent, ok := domain.Registrable(host)
	if !ok {
		return true // depth filtering already rejects these
	}
	if host == parent {
		return true
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	pc := c.seen[parent]
	switch {
	case pc == nil:
		pc = &parentCount{start: now}
		c.seen[parent] = pc
		// Forget everything occasionally so a long run does not grow a map
		// entry per parent seen since startup.
		if len(c.seen) > 1<<20 {
			c.seen = map[string]*parentCount{parent: pc}
		}
	case now.Sub(pc.start) >= c.window:
		pc.n, pc.start = 0, now
	}
	if pc.n >= c.limit {
		return false
	}
	pc.n++
	return true
}

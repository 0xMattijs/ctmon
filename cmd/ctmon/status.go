package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// defaultWidth is the assumed terminal width when the real one is unknown.
const defaultWidth = 80

// statusLine keeps one counter line at the bottom of the terminal and rewrites
// it in place. It is also the io.Writer the logger writes through, so a log
// record erases the status line, prints, and leaves it redrawn underneath:
// without that the two would overwrite each other.
type statusLine struct {
	mu      sync.Mutex
	f       *os.File
	width   int
	text    string
	shown   bool
	stopped bool
}

// newStatusLine returns a status line on f, or nil if f is not a terminal.
func newStatusLine(f *os.File) *statusLine {
	width, ok := terminalWidth(f)
	if !ok {
		return nil
	}
	return &statusLine{f: f, width: width}
}

// Set replaces the line's contents.
func (s *statusLine) Set(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	s.text = text
	// Cheap enough once a second, and it is how a resize is noticed.
	if width, ok := terminalWidth(s.f); ok {
		s.width = width
	}
	s.draw()
}

// Write prints a log record above the status line.
func (s *statusLine) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clear()
	n, err := s.f.Write(p)
	s.draw()
	return n, err
}

// Stop erases the line for good. A Set still in flight from the refresh loop
// must not draw it again, or the final log record lands above a counter line
// nothing will ever erase.
func (s *statusLine) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clear()
	s.text, s.stopped = "", true
}

// clear and draw assume the caller holds the lock and that the cursor sits at
// the start of the line, which holds because draw never emits a newline and
// every log record ends with one.
func (s *statusLine) clear() {
	if s.shown {
		io.WriteString(s.f, "\r\x1b[K")
		s.shown = false
	}
}

func (s *statusLine) draw() {
	if s.text == "" {
		return
	}
	// A line that wraps cannot be erased by \r, so cut it short. One column
	// is left spare: writing the last one wraps on some terminals.
	text := s.text
	if max := s.width - 1; max > 0 && len(text) > max {
		text = text[:max]
	}
	io.WriteString(s.f, "\r\x1b[K"+text)
	s.shown = true
}

// statusText renders key/value pairs the way the logger does, so the live line
// and the final line read the same.
func statusText(fields []any) string {
	var b strings.Builder
	for i := 0; i+1 < len(fields); i += 2 {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%v=%v", fields[i], fields[i+1])
	}
	return b.String()
}

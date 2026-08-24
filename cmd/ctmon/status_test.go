package main

import (
	"bytes"
	"strings"
	"testing"
)

// eraseLine is what the line emits to take itself back off the terminal.
const eraseLine = "\r\x1b[K"

func fixedWidth(n int) func() (int, bool) {
	return func() (int, bool) { return n, true }
}

// Without a terminal there is nothing to redraw in place, and the run logs
// its counters instead.
func TestNewStatusLineNotATerminal(t *testing.T) {
	line := newStatusLineOn(&bytes.Buffer{}, func() (int, bool) { return 0, false })
	if line != nil {
		t.Error("newStatusLineOn on a non-terminal returned a line")
	}
}

func TestStatusLineSetRedrawsInPlace(t *testing.T) {
	var buf bytes.Buffer
	line := newStatusLineOn(&buf, fixedWidth(40))
	if line == nil {
		t.Fatal("newStatusLineOn returned nil on a terminal")
	}

	line.Set("seen=1")
	if got, want := buf.String(), eraseLine+"seen=1"; got != want {
		t.Fatalf("first Set wrote %q, want %q", got, want)
	}

	// The second draw erases the first rather than scrolling past it, and
	// emits no newline: the cursor has to stay where the next erase expects
	// it.
	buf.Reset()
	line.Set("seen=2")
	if got, want := buf.String(), eraseLine+"seen=2"; got != want {
		t.Fatalf("second Set wrote %q, want %q", got, want)
	}
}

// A line wider than the terminal wraps, and a wrapped line cannot be erased
// with a carriage return. One column is left spare.
func TestStatusLineTruncatesToWidth(t *testing.T) {
	var buf bytes.Buffer
	line := newStatusLineOn(&buf, fixedWidth(10))
	line.Set("abcdefghijklmnop")
	if got, want := buf.String(), eraseLine+"abcdefghi"; got != want {
		t.Errorf("Set wrote %q, want %q", got, want)
	}
}

// The width is asked for again on every Set, which is how a resize between
// redraws is noticed.
func TestStatusLineFollowsAResize(t *testing.T) {
	var buf bytes.Buffer
	width := 40
	line := newStatusLineOn(&buf, func() (int, bool) { return width, true })
	line.Set("abcdefghijklmnop")

	width = 8
	buf.Reset()
	line.Set("abcdefghijklmnop")
	if got, want := buf.String(), eraseLine+"abcdefg"; got != want {
		t.Errorf("after a resize Set wrote %q, want %q", got, want)
	}
}

// A log record has to land above the counter line, not through it: erase,
// print, redraw.
func TestStatusLineWriteKeepsTheLineBelow(t *testing.T) {
	var buf bytes.Buffer
	line := newStatusLineOn(&buf, fixedWidth(40))
	line.Set("seen=1")

	buf.Reset()
	n, err := line.Write([]byte("level=INFO msg=hello\n"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len("level=INFO msg=hello\n") {
		t.Errorf("Write returned %d, want %d", n, len("level=INFO msg=hello\n"))
	}
	want := eraseLine + "level=INFO msg=hello\n" + eraseLine + "seen=1"
	if got := buf.String(); got != want {
		t.Errorf("Write wrote %q, want %q", got, want)
	}
}

// Nothing has been drawn yet, so there is nothing to erase first.
func TestStatusLineWriteBeforeAnySet(t *testing.T) {
	var buf bytes.Buffer
	line := newStatusLineOn(&buf, fixedWidth(40))
	line.Write([]byte("early\n"))
	if got := buf.String(); got != "early\n" {
		t.Errorf("Write before the first Set wrote %q, want %q", got, "early\n")
	}
}

// Stop erases the line for good. A Set still in flight from the refresh loop
// must not draw it again, or the final log record lands above a counter line
// nothing will ever erase.
func TestStatusLineStopIsFinal(t *testing.T) {
	var buf bytes.Buffer
	line := newStatusLineOn(&buf, fixedWidth(40))
	line.Set("seen=1")

	buf.Reset()
	line.Stop()
	if got := buf.String(); got != eraseLine {
		t.Fatalf("Stop wrote %q, want %q", got, eraseLine)
	}

	buf.Reset()
	line.Set("seen=2")
	if got := buf.String(); got != "" {
		t.Errorf("Set after Stop wrote %q, want nothing", got)
	}

	// The logger keeps writing after the line is stopped, and those records
	// go through untouched.
	buf.Reset()
	line.Write([]byte("final\n"))
	if got := buf.String(); got != "final\n" {
		t.Errorf("Write after Stop wrote %q, want %q", got, "final\n")
	}
}

func TestStatusText(t *testing.T) {
	got := statusText([]any{"seen", 12, "probed", 3, "rate", 1.5})
	if want := "seen=12 probed=3 rate=1.5"; got != want {
		t.Errorf("statusText = %q, want %q", got, want)
	}
	if got := statusText(nil); got != "" {
		t.Errorf("statusText(nil) = %q, want empty", got)
	}
	// slog pairs its fields; an odd tail has no value to print.
	if got := statusText([]any{"seen", 1, "dangling"}); got != "seen=1" {
		t.Errorf("statusText with an odd tail = %q, want %q", got, "seen=1")
	}
}

// The status line is written to by the refresh loop and by every log record,
// from different goroutines. Run this one under -race.
func TestStatusLineConcurrentUse(t *testing.T) {
	var buf bytes.Buffer
	line := newStatusLineOn(&buf, fixedWidth(40))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			line.Set("seen=" + strings.Repeat("x", i%20))
		}
	}()
	for i := 0; i < 200; i++ {
		line.Write([]byte("record\n"))
	}
	<-done
	line.Stop()
}

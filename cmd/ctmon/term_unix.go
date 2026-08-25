//go:build unix

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// terminalWidth reports the width of f in columns, and whether f is a
// terminal at all.
func terminalWidth(f *os.File) (int, bool) {
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0, false
	}
	if ws.Col == 0 {
		return defaultWidth, true
	}
	return int(ws.Col), true
}

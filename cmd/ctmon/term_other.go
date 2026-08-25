//go:build !unix

package main

import "os"

// terminalWidth reports the width of f in columns, and whether f is a
// terminal at all. Without an ioctl to ask, the width is a guess.
func terminalWidth(f *os.File) (int, bool) {
	info, err := f.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return 0, false
	}
	return defaultWidth, true
}

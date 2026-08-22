//go:build unix

package main

import (
	"os"
	"syscall"
)

// snapshotSignal is the signal that makes a run write a snapshot of its
// database. SIGUSR1 is the conventional "do the thing" signal for a daemon
// with nothing else to say.
func snapshotSignal() (os.Signal, bool) { return syscall.SIGUSR1, true }

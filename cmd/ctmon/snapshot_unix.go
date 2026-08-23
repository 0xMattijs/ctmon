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

// snapshotSignalName is what to type to send it. syscall.Signal renders
// itself as prose — "user defined signal 1" — which is no use at a shell.
const snapshotSignalName = "SIGUSR1"

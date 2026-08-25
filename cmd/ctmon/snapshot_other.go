//go:build !unix

package main

import "os"

// snapshotSignal reports that this platform has no user-defined signal to
// hang a snapshot on. Stop the run and read the database directly instead.
func snapshotSignal() (os.Signal, bool) { return nil, false }

// snapshotSignalName has nothing to name.
const snapshotSignalName = ""

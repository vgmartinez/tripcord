//go:build unix

package adapters

import "syscall"

// openFlags keeps open(2) from blocking on a FIFO swapped in for a config
// file; the fstat check that follows rejects it.
const openFlags = syscall.O_NONBLOCK

//go:build !windows && !plan9

package acceptance

import (
	"net"
	"syscall"
	"testing"
)

// makeFIFO creates a named pipe at path and reports whether it succeeded.
func makeFIFO(t *testing.T, path string) bool {
	t.Helper()
	if err := syscall.Mkfifo(path, 0644); err != nil {
		t.Logf("unable to create a FIFO at %s: %v", path, err)
		return false
	}
	return true
}

// makeSocket creates a unix-domain socket at path and reports whether it
// succeeded. The listener is closed immediately; only the socket file matters,
// and closing it does not remove the file.
func makeSocket(t *testing.T, path string) bool {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Logf("unable to create a unix socket at %s: %v", path, err)
		return false
	}
	listener.Close()
	return true
}

// A device node would exercise the same code path as a FIFO and a socket —
// they share one arm of the walk — and creating one needs root, so it is
// deliberately not attempted here.

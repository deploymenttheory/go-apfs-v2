//go:build !windows && !plan9

package acceptance

import (
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
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
// succeeded. Only the socket file matters, so the listener is closed straight
// away — but a UnixListener unlinks the file it created on Close by default,
// which would leave nothing behind for the walk to find.
func makeSocket(t *testing.T, path string) bool {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Logf("unable to create a unix socket at %s: %v", path, err)
		return false
	}
	if unixListener, ok := listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(false)
	}
	listener.Close()

	if _, err := os.Lstat(path); err != nil {
		t.Logf("the socket at %s did not survive closing its listener: %v", path, err)
		return false
	}
	return true
}

// A device node would exercise the same arm of the walk as a FIFO and a socket,
// and creating one needs root, so it is deliberately not attempted.

// xattrsReadable reports whether this platform can read extended attributes.
func xattrsReadable() bool { return true }

// readXattrNames returns the names of the extended attributes on path.
func readXattrNames(path string) ([]string, error) {
	size, err := unix.Llistxattr(path, nil)
	if err != nil || size == 0 {
		return nil, err
	}
	buf := make([]byte, size)
	size, err = unix.Llistxattr(path, buf)
	if err != nil {
		return nil, err
	}
	var names []string
	for name := range strings.SplitSeq(string(buf[:size]), "\x00") {
		if name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

// setXattr attaches an attribute to path, reporting whether it worked.
func setXattr(t *testing.T, path, name string, value []byte) bool {
	t.Helper()
	return unix.Lsetxattr(path, name, value, 0) == nil
}

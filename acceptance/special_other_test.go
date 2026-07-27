//go:build windows || plan9

package acceptance

import "testing"

// Windows has no FIFOs or unix-domain sockets in a form the walk would see as
// special, and no extended attributes this tool reads, so the tests that need
// them skip there rather than pretending.

func makeFIFO(t *testing.T, path string) bool {
	t.Helper()
	return false
}

func makeSocket(t *testing.T, path string) bool {
	t.Helper()
	return false
}

func xattrsReadable() bool { return false }

// hardLinksDetectable reports whether this platform exposes inode identity.
// Windows supports hard links on NTFS but does not expose the identity through
// os.FileInfo, so a link is indistinguishable from a separate file.
func hardLinksDetectable() bool { return false }

func readXattrNames(path string) ([]string, error) { return nil, nil }

func setXattr(t *testing.T, path, name string, value []byte) bool {
	t.Helper()
	return false
}

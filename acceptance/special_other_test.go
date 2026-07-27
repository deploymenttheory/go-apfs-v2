//go:build windows || plan9

package acceptance

import "testing"

// Windows has no FIFOs or unix-domain sockets in a form the walk would see as
// special, so the special-file tests skip there rather than pretending.

func makeFIFO(t *testing.T, path string) bool {
	t.Helper()
	return false
}

func makeSocket(t *testing.T, path string) bool {
	t.Helper()
	return false
}

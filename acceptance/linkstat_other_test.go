//go:build windows || plan9

package acceptance

import "testing"

// linkIdentity is unavailable here: these platforms expose no inode identity
// through syscall.Stat_t. The hard-link assertions are macOS-only anyway.
func linkIdentity(t *testing.T, path string) (ino uint64, nlink uint64, ok bool) {
	t.Helper()
	return 0, 0, false
}

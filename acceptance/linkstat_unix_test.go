//go:build !windows && !plan9

package acceptance

import (
	"os"
	"syscall"
	"testing"
)

// linkIdentity reports a file's inode number and link count.
//
// It is split by platform because syscall.Stat_t is not portable: it does not
// exist on Windows, and Nlink is uint16 on darwin against uint64 on Linux. A
// runtime GOOS check would not have helped, since the file still has to
// compile everywhere.
func linkIdentity(t *testing.T, path string) (ino uint64, nlink uint64, ok bool) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Errorf("stat %s: %v", path, err)
		return 0, 0, false
	}
	st, isStat := info.Sys().(*syscall.Stat_t)
	if !isStat {
		return 0, 0, false
	}
	return uint64(st.Ino), uint64(st.Nlink), true
}

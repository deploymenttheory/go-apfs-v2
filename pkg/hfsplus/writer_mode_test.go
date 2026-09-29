package hfsplus

import (
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/hostwalk"
)

func TestImageModeCapturedEntry(t *testing.T) {
	for _, mode := range []os.FileMode{0, os.ModeDir, os.ModeSymlink, os.ModeSetuid | os.ModeSetgid | os.ModeSticky, os.ModeDir | 0711 | os.ModeSetgid} {
		e := newEntry(hostwalk.Node{Name: "captured", Mode: mode, UID: 42, GID: 43}, nil)
		if !e.ModeExplicit || e.Mode != mode || e.UID != 42 || e.GID != 43 {
			t.Fatal("captured mode lost", e)
		}
		if mode.Perm() == 0 && hfsFileMode(&fileNode{entry: e, isDir: mode.IsDir(), isSymlink: mode&os.ModeSymlink != 0})&0777 != 0 {
			t.Fatal("captured zero defaulted")
		}
	}
}

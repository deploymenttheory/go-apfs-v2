package acceptance

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Exercise the production binary with xattrs enabled by default. The link's
// namespace must never borrow metadata from an inside, outside or directory
// target, and a dangling target must not prevent image creation.
func TestPackLinuxSymlinkMetadata(t *testing.T) {
	source := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	for _, name := range []string{filepath.Join(source, "file"), outside} {
		if err := os.WriteFile(name, []byte("payload"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := unix.Setxattr(name, "user.target-only", []byte("target-value"), 0); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{"inside": "file", "outside": outside, "dangling": "missing", "directory": "."}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(source, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, format := range []string{"apfs", "hfs+"} {
		t.Run(format, func(t *testing.T) {
			image := filepath.Join(t.TempDir(), "packed.dmg")
			mustRun(t, "pack", source, image, "--fs", format, "--compression", "none")
			volume := openVolumeFS(t, image)
			attributes, ok := volume.(interface {
				Xattrs(string) (map[string][]byte, error)
			})
			if !ok {
				t.Fatal("image reader does not expose attributes")
			}
			attrs, err := attributes.Xattrs("file")
			if err != nil || !bytes.Equal(attrs["user.target-only"], []byte("target-value")) {
				t.Fatal(attrs, err)
			}
			for name, target := range links {
				got, err := volume.Readlink(name)
				if err != nil || got != target {
					t.Fatal(name, got, target, err)
				}
				attrs, err := attributes.Xattrs(name)
				if err != nil {
					t.Fatal(name, err)
				}
				if _, present := attrs["user.target-only"]; present {
					t.Fatal("borrowed link target metadata", name, attrs)
				}
			}
		})
	}
}

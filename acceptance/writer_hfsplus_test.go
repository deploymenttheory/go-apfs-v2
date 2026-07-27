// Oracle-backed acceptance tests for the HFS+ writer: images produced by
// pkg/hfsplus are checked with fsck_hfs and mounted with hdiutil. The
// in-memory round-trip tests stay in pkg/hfsplus.
package acceptance

import (
	"bytes"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
)

// memWriterAt is an in-memory io.WriterAt that grows as needed.
type memWriterAt struct{ b []byte }

func (m *memWriterAt) WriteAt(p []byte, off int64) (int, error) {
	if need := int(off) + len(p); need > len(m.b) {
		grown := make([]byte, need)
		copy(grown, m.b)
		m.b = grown
	}
	copy(m.b[off:], p)
	return len(p), nil
}

// hfsSampleTree is the fixture both HFS+ oracle tests write: a small file, a
// file over a megabyte, an executable, a symlink, a unicode name, an empty
// file and two levels of directory. It returns the tree and the large file's
// contents so the mount test can compare checksums.
func hfsSampleTree() (*hfsplus.Entry, []byte) {
	big := bytes.Repeat([]byte("ABCDEFGH0123456789"), 60000) // ~1.03 MiB
	root := &hfsplus.Entry{Children: []*hfsplus.Entry{
		{Name: "hello.txt", Mode: 0o644, Data: []byte("hello world\n")},
		{Name: "big.bin", Mode: 0o644, Data: big},
		{Name: "run.sh", Mode: 0o755, Data: []byte("#!/bin/sh\necho hi\n")},
		{Name: "link", Mode: os.ModeSymlink | 0o755, Data: []byte("hello.txt")},
		{Name: "café", Mode: 0o644, Data: []byte("unicode name\n")},
		{Name: "empty.txt", Mode: 0o644, Data: nil},
		{Name: "sub", Mode: os.ModeDir | 0o755, Children: []*hfsplus.Entry{
			{Name: "nested.txt", Mode: 0o644, Data: []byte("nested\n")},
			{Name: "deep", Mode: os.ModeDir | 0o755, Children: []*hfsplus.Entry{
				{Name: "leaf.txt", Mode: 0o644, Data: []byte("leaf\n")},
			}},
		}},
	}}
	return root, big
}

// buildHFSImage writes hfsSampleTree to an in-memory HFS+ image.
func buildHFSImage(t *testing.T) ([]byte, []byte) {
	t.Helper()
	root, big := hfsSampleTree()
	fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	w := &memWriterAt{}
	if err := hfsplus.CreateImage(w, 0, "TestVol", root, &hfsplus.CreateOptions{FixedTime: fixed}); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}
	return w.b, big
}

// firstField returns the first whitespace-separated field of s, which for an
// hdiutil attach response is the device node.
func firstField(s string) string {
	for _, line := range bytes.Fields([]byte(s)) {
		return string(line)
	}
	return ""
}

// TestWriteFsckClean writes an image, attaches it as a raw device and runs
// fsck_hfs -n, asserting the volume is reported OK. darwin only.
func TestWriteFsckClean(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fsck_hfs is macOS-only")
	}
	requireTools(t, "hdiutil", "fsck_hfs")

	img, _ := buildHFSImage(t)
	path := filepath.Join(t.TempDir(), "vol.img")
	if err := os.WriteFile(path, img, 0o644); err != nil {
		t.Fatal(err)
	}

	dev := attachRaw(t, path)
	defer detach(t, dev)

	out, _ := exec.Command("fsck_hfs", "-n", dev).CombinedOutput()
	// fsck_hfs exits non-zero when it cannot open the raw device for the
	// character-device pass, yet still completes the check via the buffered
	// device; the authoritative signal is the "appears to be OK" line.
	if !bytes.Contains(out, []byte("appears to be OK")) {
		t.Fatalf("fsck_hfs did not report clean:\n%s", out)
	}
}

// TestWriteMountsViaHdiutil mounts the written image read-only and verifies
// file content, a symlink target and directory structure. darwin only.
func TestWriteMountsViaHdiutil(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("hdiutil is macOS-only")
	}
	requireTools(t, "hdiutil")

	img, big := buildHFSImage(t)
	path := filepath.Join(t.TempDir(), "vol.img")
	if err := os.WriteFile(path, img, 0o644); err != nil {
		t.Fatal(err)
	}

	mnt := t.TempDir()
	out, err := exec.Command("hdiutil", "attach", "-readonly", "-nobrowse",
		"-mountpoint", mnt, path).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach: %v\n%s", err, out)
	}
	dev := firstField(string(out))
	defer detach(t, dev)

	// Small file.
	if got, err := os.ReadFile(filepath.Join(mnt, "hello.txt")); err != nil || string(got) != "hello world\n" {
		t.Errorf("hello.txt = %q, %v", got, err)
	}
	// Large file by sha.
	got, err := os.ReadFile(filepath.Join(mnt, "big.bin"))
	if err != nil {
		t.Fatalf("read big.bin: %v", err)
	}
	if sha256.Sum256(got) != sha256.Sum256(big) {
		t.Errorf("big.bin sha mismatch")
	}
	// Symlink.
	if tgt, err := os.Readlink(filepath.Join(mnt, "link")); err != nil || tgt != "hello.txt" {
		t.Errorf("readlink = %q, %v", tgt, err)
	}
	// Nested.
	if got, err := os.ReadFile(filepath.Join(mnt, "sub", "deep", "leaf.txt")); err != nil || string(got) != "leaf\n" {
		t.Errorf("leaf.txt = %q, %v", got, err)
	}
}

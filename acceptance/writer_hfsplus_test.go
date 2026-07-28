// Checker tests for the HFS+ writer: an image written by pkg/hfsplus is
// checked with fsck_hfs and mounted with hdiutil so the files can be read back
// through the operating system. The in-memory round-trip tests stay in
// pkg/hfsplus.
package acceptance

import (
	"bytes"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

// hfsSampleTree is the fixture both HFS+ checker tests write: a small file, a
// file over a megabyte, an executable, a symlink, a unicode name, an empty
// file and two levels of directory. It returns the tree and the large file's
// contents so the mount test can compare checksums.
func hfsSampleTree() (*hfsplus.Entry, []byte) {
	big := bytes.Repeat([]byte("ABCDEFGH0123456789"), 60000) // ~1.03 MiB
	root := &hfsplus.Entry{Children: []*hfsplus.Entry{
		{Name: "hello.txt", Mode: 0o644, Data: []byte("hello world\n")},
		// A resource fork, so fsck_hfs and hdiutil judge one on every run
		// rather than only the data fork.
		{Name: "forked.txt", Mode: 0o644, Data: []byte("has a resource fork\n"),
			ResourceFork: []byte("resource fork payload\n")},
		// Extended attributes in both record shapes, so fsck_hfs judges the
		// attributes file on every run: one value small enough to sit inside
		// its record, one that needs an allocation extent of its own.
		{Name: "attrs.txt", Mode: 0o644, Data: []byte("has attributes\n"), Xattrs: map[string][]byte{
			"com.example.small": []byte("value42"),
			"com.example.big":   bytes.Repeat([]byte("big attribute value. "), 400),
		}},
		// Three names for one file, so fsck_hfs judges the private metadata
		// directory and the indirect node on every run.
		{Name: "link-a.txt", Mode: 0o644, Data: []byte("shared content\n"), LinkGroup: 1},
		{Name: "link-b.txt", Mode: 0o644, Data: []byte("shared content\n"), LinkGroup: 1},
		{Name: "link-c.txt", Mode: 0o644, Data: []byte("shared content\n"), LinkGroup: 1},
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
	// Resource fork, read the way macOS exposes it. This is the check that the
	// fork is not merely present on disk but reachable as macOS expects, which
	// our own reader could not tell us.
	rsrc, err := os.ReadFile(filepath.Join(mnt, "forked.txt", "..namedfork", "rsrc"))
	if err != nil {
		t.Errorf("reading the resource fork of forked.txt: %v", err)
	} else if string(rsrc) != "resource fork payload\n" {
		t.Errorf("resource fork = %q", rsrc)
	}
	// And as the attribute macOS presents it as.
	xattr, err := exec.Command("xattr", "-p", "com.apple.ResourceFork",
		filepath.Join(mnt, "forked.txt")).CombinedOutput()
	if err != nil {
		t.Errorf("xattr -p com.apple.ResourceFork: %v\n%s", err, xattr)
	} else if !bytes.Contains(xattr, []byte("resource fork payload")) {
		t.Errorf("com.apple.ResourceFork = %q", xattr)
	}

	// Extended attributes, read back through macOS rather than our own reader.
	// fsck_hfs reporting the attributes file well-formed is a weaker claim than
	// the kernel being able to hand the values back, so both are checked.
	attrsPath := filepath.Join(mnt, "attrs.txt")
	small, err := exec.Command("xattr", "-p", "com.example.small", attrsPath).CombinedOutput()
	if err != nil {
		t.Errorf("xattr -p com.example.small: %v\n%s", err, small)
	} else if !bytes.Contains(small, []byte("value42")) {
		t.Errorf("com.example.small = %q, want value42", small)
	}

	// The large one exercises the fork-data record: its value lives in an
	// allocation extent rather than inside the attribute record.
	big2, err := exec.Command("xattr", "-p", "-x", "com.example.big", attrsPath).CombinedOutput()
	if err != nil {
		t.Errorf("xattr -p com.example.big: %v\n%s", err, big2)
	} else {
		want := len(bytes.Repeat([]byte("big attribute value. "), 400))
		// -x prints hex bytes; two hex digits per byte, whitespace separated.
		if got := len(bytes.Fields(big2)); got != want {
			t.Errorf("com.example.big is %d bytes, want %d", got, want)
		}
	}

	// A listing must name both and not invent others.
	list, err := exec.Command("xattr", attrsPath).CombinedOutput()
	if err != nil {
		t.Errorf("xattr listing: %v\n%s", err, list)
	} else {
		for _, want := range []string{"com.example.small", "com.example.big"} {
			if !bytes.Contains(list, []byte(want)) {
				t.Errorf("attribute listing %q is missing %s", list, want)
			}
		}
	}

	// Hard links, judged by the kernel rather than by fsck. This is the check
	// that matters: fsck_hfs will accept a private directory and an indirect
	// node that macOS then declines to resolve, so what proves the links work
	// is macOS reporting one inode with three names.
	names := []string{"link-a.txt", "link-b.txt", "link-c.txt"}
	var inode uint64
	for _, name := range names {
		ino, nlink, ok := linkIdentity(t, filepath.Join(mnt, name))
		if !ok {
			t.Skip("this platform exposes no inode identity")
		}
		if nlink != uint64(len(names)) {
			t.Errorf("%s: link count = %d, want %d", name, nlink, len(names))
		}
		if inode == 0 {
			inode = ino
		} else if ino != inode {
			t.Errorf("%s: inode %d differs from %d; the names are copies, not links", name, ino, inode)
		}
		content, err := os.ReadFile(filepath.Join(mnt, name))
		if err != nil || string(content) != "shared content\n" {
			t.Errorf("%s = %q, %v", name, content, err)
		}
	}

	// The private metadata directory must not be visible in a listing.
	dirents, err := os.ReadDir(mnt)
	if err != nil {
		t.Fatalf("reading the mount point: %v", err)
	}
	for _, d := range dirents {
		if strings.Contains(d.Name(), "HFS+ Private Data") {
			t.Errorf("the private metadata directory is visible as %q", d.Name())
		}
	}
}

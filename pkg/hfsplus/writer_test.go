package hfsplus

import (
	"bytes"
	"crypto/sha256"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"testing/fstest"
	"time"
)

// memWriterAt is an in-memory io.WriterAt that grows as needed.
type memWriterAt struct{ b []byte }

func (m *memWriterAt) WriteAt(p []byte, off int64) (int, error) {
	end := int(off) + len(p)
	if end > len(m.b) {
		nb := make([]byte, end)
		copy(nb, m.b)
		m.b = nb
	}
	copy(m.b[off:], p)
	return len(p), nil
}

// sampleTree builds a representative directory tree: nested dirs, a small and
// a ~1 MiB file, a symlink, an executable and a unicode name.
func sampleTree() (*Entry, []byte) {
	big := bytes.Repeat([]byte("ABCDEFGH0123456789"), 60000) // ~1.03 MiB
	root := &Entry{Children: []*Entry{
		{Name: "hello.txt", Mode: 0o644, Data: []byte("hello world\n")},
		{Name: "big.bin", Mode: 0o644, Data: big},
		{Name: "run.sh", Mode: 0o755, Data: []byte("#!/bin/sh\necho hi\n")},
		{Name: "link", Mode: os.ModeSymlink | 0o755, Data: []byte("hello.txt")},
		{Name: "café", Mode: 0o644, Data: []byte("unicode name\n")},
		{Name: "empty.txt", Mode: 0o644, Data: nil},
		{Name: "sub", Mode: os.ModeDir | 0o755, Children: []*Entry{
			{Name: "nested.txt", Mode: 0o644, Data: []byte("nested\n")},
			{Name: "deep", Mode: os.ModeDir | 0o755, Children: []*Entry{
				{Name: "leaf.txt", Mode: 0o644, Data: []byte("leaf\n")},
			}},
		}},
	}}
	return root, big
}

func buildSampleImage(t *testing.T) ([]byte, []byte) {
	t.Helper()
	root, big := sampleTree()
	fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	w := &memWriterAt{}
	if err := CreateImage(w, 0, "TestVol", root, &CreateOptions{FixedTime: fixed}); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}
	return w.b, big
}

func TestWriteReadRoundTrip(t *testing.T) {
	img, big := buildSampleImage(t)

	v, err := New(bytes.NewReader(img))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if v.Name() != "TestVol" {
		t.Errorf("volume name = %q, want TestVol", v.Name())
	}
	if !v.CaseSensitive() {
		t.Errorf("expected case-sensitive HFSX volume")
	}

	// fstest.TestFS validates the fs.FS contract and directory walking.
	if err := fstest.TestFS(v,
		"hello.txt", "big.bin", "run.sh", "link", "café", "empty.txt",
		"sub/nested.txt", "sub/deep/leaf.txt",
	); err != nil {
		t.Errorf("fstest.TestFS: %v", err)
	}

	// Content checks.
	checkContent := func(name string, want []byte) {
		got, err := fs.ReadFile(v, name)
		if err != nil {
			t.Errorf("ReadFile(%q): %v", name, err)
			return
		}
		if sha256.Sum256(got) != sha256.Sum256(want) {
			t.Errorf("content mismatch for %q (got %d bytes, want %d)", name, len(got), len(want))
		}
	}
	checkContent("hello.txt", []byte("hello world\n"))
	checkContent("big.bin", big)
	checkContent("empty.txt", nil)
	checkContent("sub/deep/leaf.txt", []byte("leaf\n"))

	// Symlink target.
	target, err := v.Readlink("link")
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if target != "hello.txt" {
		t.Errorf("symlink target = %q, want hello.txt", target)
	}

	// Modes.
	checkMode := func(name string, want fs.FileMode) {
		info, err := fs.Stat(v, name)
		if err != nil {
			t.Errorf("Stat(%q): %v", name, err)
			return
		}
		if info.Mode() != want {
			t.Errorf("mode(%q) = %v, want %v", name, info.Mode(), want)
		}
	}
	checkMode("run.sh", 0o755)
	checkMode("hello.txt", 0o644)
	checkMode("sub", fs.ModeDir|0o755)
	checkMode("link", fs.ModeSymlink|0o755)

	// Directory structure.
	entries, err := fs.ReadDir(v, "sub")
	if err != nil {
		t.Fatalf("ReadDir(sub): %v", err)
	}
	if len(entries) != 2 || entries[0].Name() != "deep" || entries[1].Name() != "nested.txt" {
		t.Errorf("sub children = %v, want [deep nested.txt]", names(entries))
	}
}

func names(entries []fs.DirEntry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func TestWriteFromDirRoundTrip(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a.txt"), []byte("alpha"))
	mustMkdir(t, filepath.Join(dir, "d"))
	mustWrite(t, filepath.Join(dir, "d", "b.txt"), []byte("bravo"))

	w := &memWriterAt{}
	if err := CreateImageFromDir(w, 0, "FromDir", dir, nil); err != nil {
		t.Fatalf("CreateImageFromDir: %v", err)
	}
	v, err := New(bytes.NewReader(w.b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := fs.ReadFile(v, "d/b.txt")
	if err != nil || string(got) != "bravo" {
		t.Errorf("d/b.txt = %q, %v; want bravo", got, err)
	}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestWriteFsckClean writes an image, attaches it as a raw device and runs
// fsck_hfs -n, asserting the volume is reported OK. darwin only.
func TestWriteFsckClean(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fsck_hfs is macOS-only")
	}
	requireTools(t, "hdiutil", "fsck_hfs")

	img, _ := buildSampleImage(t)
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

	img, big := buildSampleImage(t)
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

func requireTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
}

func attachRaw(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command("hdiutil", "attach",
		"-imagekey", "diskimage-class=CRawDiskImage",
		"-nomount", "-readonly", path).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach: %v\n%s", err, out)
	}
	dev := firstField(string(out))
	if dev == "" {
		t.Fatalf("could not parse device from: %s", out)
	}
	return dev
}

func detach(t *testing.T, dev string) {
	t.Helper()
	if dev == "" {
		return
	}
	if out, err := exec.Command("hdiutil", "detach", dev).CombinedOutput(); err != nil {
		t.Logf("hdiutil detach %s: %v\n%s", dev, err, out)
	}
}

func firstField(s string) string {
	for _, line := range bytes.Fields([]byte(s)) {
		return string(line)
	}
	return ""
}

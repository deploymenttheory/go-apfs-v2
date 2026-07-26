// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"math/rand"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// randomBytes returns n deterministic pseudo-random bytes for a given seed, so
// content mismatches are reproducible.
func randomBytes(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

// openVolumeSize creates a container of the given size and returns its first
// volume as an fs.FS, using the MIT reader as the cross-platform oracle.
func openVolumeSize(t *testing.T, size int64, opts *apfswrite.CreateOptions) *apfs.Volume {
	t.Helper()
	img := &memImage{}
	if err := apfswrite.CreateContainer(img, size, opts); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	container, err := apfs.Open(img, &apfs.OpenOptions{})
	if err != nil {
		t.Fatalf("apfs.Open: %v", err)
	}
	volumes, err := container.Volumes()
	if err != nil {
		t.Fatalf("Volumes: %v", err)
	}
	if len(volumes) != 1 {
		t.Fatalf("volume count = %d, want 1", len(volumes))
	}
	return volumes[0]
}

// TestCreateContainerLargeFile writes several multi-block files, including sizes
// that are exact block multiples and sizes that are not (partial last block),
// plus a ~5 MiB file, and verifies each reads back with the exact byte count and
// matching sha256. This catches wrong extent lengths, missing tail bytes, and
// zero-padding leaking into the content. Runs on every OS.
func TestCreateContainerLargeFile(t *testing.T) {
	const bs = 4096
	files := []struct {
		name string
		size int
	}{
		{"onemib.bin", 1 << 20},        // 1 MiB, exact block multiple
		{"partial.bin", 1<<20 + 123},   // 1 MiB + a partial last block
		{"exact2.bin", 2 * bs},         // exactly two blocks
		{"almost.bin", 3*bs - 1},       // three blocks minus one byte
		{"onebyte.bin", 1},             // a single byte in one block
		{"five.bin", 5*(1<<20) + 4095}, // ~5 MiB, non-multiple
	}

	children := make([]*apfswrite.Entry, 0, len(files))
	for i, f := range files {
		children = append(children, &apfswrite.Entry{Name: f.name, Data: randomBytes(f.size, int64(i+1))})
	}
	root := &apfswrite.Entry{Children: children}

	const size = 32 * 1024 * 1024
	v := openVolumeSize(t, size, &apfswrite.CreateOptions{VolumeName: "LargeVol", Root: root})
	walkAndAssert(t, v, collectWants(root))

	// Assert the exact sizes and byte-exact content explicitly too.
	for i, f := range files {
		got, err := v.ReadFile(f.name)
		if err != nil {
			t.Fatalf("ReadFile %q: %v", f.name, err)
		}
		if len(got) != f.size {
			t.Errorf("%q: read %d bytes, want exactly %d", f.name, len(got), f.size)
		}
		if sha256.Sum256(got) != sha256.Sum256(randomBytes(f.size, int64(i+1))) {
			t.Errorf("%q: content sha256 mismatch", f.name)
		}
	}
}

// TestCreateContainerEmptyFile writes a 0-byte regular file (alongside a normal
// one) and verifies it lists with size 0 and reads back empty. Runs on every OS.
func TestCreateContainerEmptyFile(t *testing.T) {
	root := &apfswrite.Entry{Children: []*apfswrite.Entry{
		{Name: "empty.txt", Data: []byte{}},
		{Name: "nonempty.txt", Data: []byte("not empty\n")},
		{Name: "dir", Mode: fs.ModeDir, Children: []*apfswrite.Entry{
			{Name: "alsoempty", Data: nil},
		}},
	}}

	const size = 16 * 1024 * 1024
	v := openVolumeSize(t, size, &apfswrite.CreateOptions{VolumeName: "EmptyVol", Root: root})
	walkAndAssert(t, v, collectWants(root))

	entries, err := v.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Name() == "empty.txt" {
			found = true
			info, err := e.Info()
			if err != nil {
				t.Fatalf("Info: %v", err)
			}
			if info.Size() != 0 {
				t.Errorf("empty.txt size = %d, want 0", info.Size())
			}
			if info.IsDir() {
				t.Errorf("empty.txt reported as directory")
			}
		}
	}
	if !found {
		t.Fatal("empty.txt not listed in root")
	}

	got, err := v.ReadFile("empty.txt")
	if err != nil {
		t.Fatalf("ReadFile empty.txt: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty.txt read %d bytes, want 0", len(got))
	}
}

// TestCreateContainerManyExtents writes enough files to overflow a single
// extent-reference leaf, forcing the extref tree to grow to two physical
// levels, and verifies every file still reads back correctly. Runs on every OS.
func TestCreateContainerManyExtents(t *testing.T) {
	const nFiles = 200
	children := make([]*apfswrite.Entry, 0, nFiles)
	for i := 0; i < nFiles; i++ {
		children = append(children, &apfswrite.Entry{
			Name: fmt.Sprintf("blob_%03d.bin", i),
			Data: randomBytes(1000+i, int64(1000+i)),
		})
	}
	root := &apfswrite.Entry{Children: children}

	const size = 32 * 1024 * 1024
	v := openVolumeSize(t, size, &apfswrite.CreateOptions{VolumeName: "ManyExtents", Root: root})
	walkAndAssert(t, v, collectWants(root))
}

// TestCreateContainerManyExtentsFsckClean runs fsck_apfs against a container
// whose extentref tree has grown to two physical levels (macOS only).
func TestCreateContainerManyExtentsFsckClean(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fsck_apfs is only available on macOS")
	}
	requireTools(t, "hdiutil", "fsck_apfs")

	const nFiles = 200
	children := make([]*apfswrite.Entry, 0, nFiles)
	for i := 0; i < nFiles; i++ {
		children = append(children, &apfswrite.Entry{
			Name: fmt.Sprintf("blob_%03d.bin", i),
			Data: randomBytes(1000+i, int64(1000+i)),
		})
	}
	root := &apfswrite.Entry{Children: children}

	const size = 32 * 1024 * 1024
	imgPath := filepath.Join(t.TempDir(), "manyextents.img")
	writeImage(t, imgPath, size, &apfswrite.CreateOptions{VolumeName: "FsckManyExtents", Root: root})

	dev := attachRaw(t, imgPath)
	defer detach(t, dev)

	out, err := exec.Command("fsck_apfs", "-n", dev).CombinedOutput()
	t.Logf("fsck_apfs output:\n%s", out)
	if err != nil {
		t.Fatalf("fsck_apfs reported errors (exit %v)", err)
	}
	if !strings.Contains(string(out), "appears to be OK") {
		t.Errorf("fsck_apfs did not report the container clean")
	}
}

// TestCreateContainerAutoSize verifies that passing size 0 sizes the image to
// fit a large file plus metadata automatically.
func TestCreateContainerAutoSize(t *testing.T) {
	root := &apfswrite.Entry{Children: []*apfswrite.Entry{
		{Name: "big.bin", Data: randomBytes(3<<20, 42)}, // 3 MiB
		{Name: "small.txt", Data: []byte("hi\n")},
	}}
	v := openVolumeSize(t, 0 /* auto */, &apfswrite.CreateOptions{VolumeName: "AutoVol", Root: root})
	walkAndAssert(t, v, collectWants(root))
}

// TestCreateContainerMultiChunk writes enough file data to cross a space-manager
// chunk boundary (a 4 KiB-block chunk spans 32768 blocks = 128 MiB), exercising
// the multi-chunk bitmap / chunk-info / free-count accounting. Reads back on
// every OS; runs fsck_apfs on darwin.
func TestCreateContainerMultiChunk(t *testing.T) {
	// 130 MiB of data pushes the used region past block 32768 (chunk 0).
	big := randomBytes(130*(1<<20)+777, 7)
	root := &apfswrite.Entry{Children: []*apfswrite.Entry{
		{Name: "huge.bin", Data: big},
		{Name: "note.txt", Data: []byte("crosses a chunk boundary\n")},
	}}

	const size = 160 * 1024 * 1024

	// Cross-platform reader check.
	v := openVolumeSize(t, size, &apfswrite.CreateOptions{VolumeName: "MultiChunk", Root: root})
	walkAndAssert(t, v, collectWants(root))

	if runtime.GOOS != "darwin" {
		return
	}
	requireTools(t, "hdiutil", "fsck_apfs")
	imgPath := filepath.Join(t.TempDir(), "multichunk.img")
	writeImage(t, imgPath, size, &apfswrite.CreateOptions{VolumeName: "MultiChunk", Root: root})
	dev := attachRaw(t, imgPath)
	defer detach(t, dev)
	out, err := exec.Command("fsck_apfs", "-n", dev).CombinedOutput()
	t.Logf("fsck_apfs output:\n%s", out)
	if err != nil {
		t.Fatalf("fsck_apfs reported errors (exit %v)", err)
	}
	if !strings.Contains(string(out), "appears to be OK") {
		t.Errorf("fsck_apfs did not report the container clean")
	}
}

// TestCreateContainerLargeFileFsckClean runs Apple's fsck_apfs against a tree
// containing large multi-block files and an empty file (macOS only).
func TestCreateContainerLargeFileFsckClean(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fsck_apfs is only available on macOS")
	}
	requireTools(t, "hdiutil", "fsck_apfs")

	root := &apfswrite.Entry{Children: []*apfswrite.Entry{
		{Name: "onemib.bin", Data: randomBytes(1<<20, 1)},
		{Name: "partial.bin", Data: randomBytes(1<<20+123, 2)},
		{Name: "five.bin", Data: randomBytes(5*(1<<20)+4095, 3)},
		{Name: "empty.txt", Data: []byte{}},
		{Name: "docs", Mode: fs.ModeDir, Children: []*apfswrite.Entry{
			{Name: "twoblk.bin", Data: bytes.Repeat([]byte{0x5A}, 2*4096)},
			{Name: "emptytoo", Data: nil},
		}},
	}}

	const size = 64 * 1024 * 1024
	imgPath := filepath.Join(t.TempDir(), "large.img")
	writeImage(t, imgPath, size, &apfswrite.CreateOptions{VolumeName: "FsckLargeVol", Root: root})

	dev := attachRaw(t, imgPath)
	defer detach(t, dev)

	out, err := exec.Command("fsck_apfs", "-n", dev).CombinedOutput()
	t.Logf("fsck_apfs output:\n%s", out)
	if err != nil {
		t.Fatalf("fsck_apfs reported errors (exit %v)", err)
	}
	if !strings.Contains(string(out), "appears to be OK") {
		t.Errorf("fsck_apfs did not report the container clean")
	}
}

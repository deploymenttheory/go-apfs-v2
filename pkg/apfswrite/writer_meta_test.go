// SPDX-License-Identifier: GPL-2.0-only
// Ported from mkapfs (apfsprogs) — Copyright (C) 2019 Ernesto A. Fernández. Go port Copyright (C) 2024 Deployment Theory.

package apfswrite_test

import (
	"crypto/sha256"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// openVolumeMem opens an already-written container image and returns its single
// volume.
func openVolumeMem(t *testing.T, img *memImage) *apfs.Volume {
	t.Helper()
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

// S_IF* file-type bits used to assert the mode written into inodes.
const (
	sIFMT  = 0o170000
	sIFREG = 0o100000
	sIFDIR = 0o040000
	sIFLNK = 0o120000
)

// TestCreateContainerMetadata writes entries with varied permission bits,
// owners/groups and modification times, reads them back through the MIT reader
// (which resolves each path by the hashed dentry key — so this also proves the
// name hash matches), and asserts the mode, uid/gid and mtime round-trip.
func TestCreateContainerMetadata(t *testing.T) {
	modTime := time.Unix(1_600_000_000, 123_000_000).UTC()
	root := &apfswrite.Entry{Children: []*apfswrite.Entry{
		{Name: "private.txt", Mode: 0o600, ModTime: modTime, UID: 501, GID: 20, Data: []byte("secret\n")},
		{Name: "script.sh", Mode: 0o755, ModTime: modTime, UID: 0, GID: 0, Data: []byte("#!/bin/sh\necho hi\n")},
		{Name: "sub", Mode: fs.ModeDir | 0o750, ModTime: modTime, UID: 501, GID: 20, Children: []*apfswrite.Entry{
			{Name: "inner.txt", Mode: 0o640, ModTime: modTime, UID: 7, GID: 9, Data: []byte("inner\n")},
		}},
	}}

	v := openVolume(t, &apfswrite.CreateOptions{VolumeName: "MetaVol", Root: root})

	check := func(path string, wantMode uint16, wantUID, wantGID uint32) {
		t.Helper()
		fe, err := v.GetFileEntryByPath(path)
		if err != nil {
			t.Fatalf("GetFileEntryByPath(%q): %v", path, err)
		}
		mode, err := fe.GetFileMode()
		if err != nil {
			t.Fatalf("%q GetFileMode: %v", path, err)
		}
		if mode != wantMode {
			t.Errorf("%q mode = %o, want %o", path, mode, wantMode)
		}
		if uid, _ := fe.GetOwnerIdentifier(); uid != wantUID {
			t.Errorf("%q uid = %d, want %d", path, uid, wantUID)
		}
		if gid, _ := fe.GetGroupIdentifier(); gid != wantGID {
			t.Errorf("%q gid = %d, want %d", path, gid, wantGID)
		}
		if got := fe.Inode.ModificationTime; got != uint64(modTime.UnixNano()) {
			t.Errorf("%q mtime = %d, want %d", path, got, uint64(modTime.UnixNano()))
		}
	}

	check("private.txt", sIFREG|0o600, 501, 20)
	check("script.sh", sIFREG|0o755, 0, 0)
	check("sub", sIFDIR|0o750, 501, 20)
	check("sub/inner.txt", sIFREG|0o640, 7, 9)
}

// TestCreateContainerSymlink writes symbolic links (relative and absolute) and
// verifies the reader reports S_IFLNK and resolves the exact target through the
// com.apple.fs.symlink extended attribute. Runs on every OS.
func TestCreateContainerSymlink(t *testing.T) {
	root := &apfswrite.Entry{Children: []*apfswrite.Entry{
		{Name: "target.txt", Mode: 0o644, Data: []byte("i am the target\n")},
		{Name: "rel.link", Mode: fs.ModeSymlink | 0o777, Data: []byte("target.txt")},
		{Name: "abs.link", Mode: fs.ModeSymlink | 0o777, Data: []byte("/usr/local/bin/thing")},
		{Name: "dir", Mode: fs.ModeDir | 0o755, Children: []*apfswrite.Entry{
			{Name: "up.link", Mode: fs.ModeSymlink, Data: []byte("../target.txt")},
		}},
	}}

	v := openVolume(t, &apfswrite.CreateOptions{VolumeName: "LinkVol", Root: root})

	check := func(path, wantTarget string) {
		t.Helper()
		fe, err := v.GetFileEntryByPath(path)
		if err != nil {
			t.Fatalf("GetFileEntryByPath(%q): %v", path, err)
		}
		mode, err := fe.GetFileMode()
		if err != nil {
			t.Fatalf("%q GetFileMode: %v", path, err)
		}
		if mode&sIFMT != sIFLNK {
			t.Errorf("%q file type = %o, want S_IFLNK (%o)", path, mode&sIFMT, sIFLNK)
		}
		target, err := fe.GetSymbolicLinkTarget()
		if err != nil {
			t.Fatalf("%q GetSymbolicLinkTarget: %v", path, err)
		}
		if target != wantTarget {
			t.Errorf("%q target = %q, want %q", path, target, wantTarget)
		}
	}

	check("rel.link", "target.txt")
	check("abs.link", "/usr/local/bin/thing")
	check("dir/up.link", "../target.txt")
}

// TestCreateContainerUnicodeNames writes entries whose names carry uppercase and
// non-ASCII characters (which only round-trip if the dentry name hash is
// computed with the same case-folded, NFD-normalized algorithm the reader uses
// on lookup). Path resolution + content check prove the hash matches.
func TestCreateContainerUnicodeNames(t *testing.T) {
	files := map[string][]byte{
		"README.md":   []byte("uppercase name\n"),
		"MixedCase":   []byte("mixed\n"),
		"café.txt":    []byte("accented\n"),
		"Ünïcödé.dat": []byte("more unicode\n"),
	}
	var children []*apfswrite.Entry
	for name, data := range files {
		children = append(children, &apfswrite.Entry{Name: name, Mode: 0o644, Data: data})
	}
	root := &apfswrite.Entry{Children: children}

	v := openVolume(t, &apfswrite.CreateOptions{VolumeName: "UniVol", Root: root})
	for name, data := range files {
		got, err := v.ReadFile(name)
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", name, err)
		}
		if sha256.Sum256(got) != sha256.Sum256(data) {
			t.Errorf("%q: content mismatch", name)
		}
	}
}

// TestCreateContainerFromDir builds a real directory tree on disk (nested dirs,
// an executable, a large file, a symlink) and packs it with
// CreateContainerFromDir, then reads it back and checks content sha256 and the
// symlink target.
func TestCreateContainerFromDir(t *testing.T) {
	dir := t.TempDir()
	mustWrite := func(rel string, data []byte, mode os.FileMode) {
		t.Helper()
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, mode); err != nil {
			t.Fatal(err)
		}
	}
	hello := []byte("hello from disk\n")
	big := randomBytes(200*1024+7, 99)
	mustWrite("hello.txt", hello, 0o644)
	mustWrite("bin/run.sh", []byte("#!/bin/sh\necho hi\n"), 0o755)
	mustWrite("data/big.bin", big, 0o600)

	haveSymlink := true
	if err := os.Symlink("hello.txt", filepath.Join(dir, "link")); err != nil {
		haveSymlink = false
		t.Logf("symlink unsupported on this platform, skipping link check: %v", err)
	}

	img := &memImage{}
	if err := apfswrite.CreateContainerFromDir(img, 32*1024*1024, dir, &apfswrite.CreateOptions{VolumeName: "FromDir"}); err != nil {
		t.Fatalf("CreateContainerFromDir: %v", err)
	}

	v := openVolumeMem(t, img)

	if got, err := v.ReadFile("hello.txt"); err != nil || sha256.Sum256(got) != sha256.Sum256(hello) {
		t.Errorf("hello.txt round-trip failed: err=%v", err)
	}
	if got, err := v.ReadFile("data/big.bin"); err != nil || sha256.Sum256(got) != sha256.Sum256(big) {
		t.Errorf("data/big.bin round-trip failed: err=%v", err)
	}
	if fe, err := v.GetFileEntryByPath("bin/run.sh"); err != nil {
		t.Errorf("bin/run.sh: %v", err)
	} else if mode, _ := fe.GetFileMode(); mode&0o111 == 0 {
		t.Errorf("bin/run.sh not executable: mode %o", mode)
	}
	if haveSymlink {
		fe, err := v.GetFileEntryByPath("link")
		if err != nil {
			t.Fatalf("link: %v", err)
		}
		target, err := fe.GetSymbolicLinkTarget()
		if err != nil {
			t.Fatalf("link GetSymbolicLinkTarget: %v", err)
		}
		if target != "hello.txt" {
			t.Errorf("link target = %q, want %q", target, "hello.txt")
		}
	}
}

// TestCreateContainerMetadataFsckClean runs Apple's fsck_apfs against a tree
// carrying non-default modes, owners, timestamps and a symbolic link (macOS
// only). fsck_apfs is the strict oracle for the inode fields and the symlink
// xattr representation.
func TestCreateContainerMetadataFsckClean(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fsck_apfs is only available on macOS")
	}
	requireTools(t, "hdiutil", "fsck_apfs")

	modTime := time.Unix(1_600_000_000, 0).UTC()
	root := &apfswrite.Entry{Children: []*apfswrite.Entry{
		{Name: "private.txt", Mode: 0o600, ModTime: modTime, UID: 501, GID: 20, Data: []byte("secret\n")},
		{Name: "script.sh", Mode: 0o755, ModTime: modTime, Data: []byte("#!/bin/sh\n")},
		{Name: "README.md", Mode: 0o644, ModTime: modTime, Data: []byte("Upper And café name\n")},
		{Name: "rel.link", Mode: fs.ModeSymlink | 0o777, Data: []byte("private.txt")},
		{Name: "sub", Mode: fs.ModeDir | 0o750, ModTime: modTime, UID: 501, GID: 20, Children: []*apfswrite.Entry{
			{Name: "inner.txt", Mode: 0o640, ModTime: modTime, Data: []byte("inner\n")},
			{Name: "deep.link", Mode: fs.ModeSymlink, Data: []byte("../README.md")},
		}},
	}}

	const size = 32 * 1024 * 1024
	imgPath := filepath.Join(t.TempDir(), "meta.img")
	writeImage(t, imgPath, size, &apfswrite.CreateOptions{VolumeName: "FsckMetaVol", Root: root})

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

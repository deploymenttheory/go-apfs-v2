// Checker tests for the APFS container writer. Each one formats a container
// with pkg/apfswrite and hands it to a tool that ships with the platform:
// fsck_apfs and diskutil on macOS, apfsck on Linux. Tests that only read a
// container back with our own reader stay in pkg/apfswrite.
package acceptance

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// TestCreateContainerFsckClean formats a container into a temp file and runs
// Apple's fsck_apfs against it (macOS only).
func TestCreateContainerFsckClean(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fsck_apfs is only available on macOS")
	}
	requireTools(t, "hdiutil", "fsck_apfs")

	// The macOS raw-disk driver refuses to attach very small images, so use a
	// comfortably-sized (32 MiB) container for the on-device check.
	const size = 32 * 1024 * 1024
	imgPath := filepath.Join(t.TempDir(), "fsck.img")
	writeImage(t, imgPath, size, &apfswrite.CreateOptions{VolumeName: "FsckVol"})

	dev := attachRaw(t, imgPath)
	defer detach(t, dev)

	out, err := exec.Command("fsck_apfs", "-n", dev).CombinedOutput()
	t.Logf("fsck_apfs output:\n%s", out)
	if err != nil {
		t.Fatalf("fsck_apfs reported errors (exit %v)", err)
	}
	text := string(out)
	if !strings.Contains(text, "The container "+dev+" appears to be OK") &&
		!strings.Contains(text, "appears to be OK") {
		t.Errorf("fsck_apfs did not report the container clean")
	}
}

// TestCreateContainerApfsckClean validates a created container with apfsck
// (from linux-apfs/apfsprogs), which operates on an image file directly and
// runs on Linux. Skipped unless apfsck is installed. This is the Linux-side
// counterpart to the macOS fsck_apfs check.
func TestCreateContainerApfsckClean(t *testing.T) {
	if _, err := exec.LookPath("apfsck"); err != nil {
		t.Skip("apfsck not installed; skipping (install apfsprogs)")
	}

	const size = 32 * 1024 * 1024
	imgPath := filepath.Join(t.TempDir(), "apfsck.img")
	writeImage(t, imgPath, size, &apfswrite.CreateOptions{VolumeName: "ApfsckVol"})

	// apfsck exits non-zero on problems; -c also checks the container.
	out, err := exec.Command("apfsck", "-cw", imgPath).CombinedOutput()
	t.Logf("apfsck output:\n%s", out)
	if err != nil {
		t.Fatalf("apfsck reported problems (exit %v)", err)
	}
}

// TestCreateContainerMountsViaHdiutil mounts the empty volume read-only and
// confirms its root is empty (macOS only).
func TestCreateContainerMountsViaHdiutil(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("hdiutil is only available on macOS")
	}
	requireTools(t, "hdiutil")

	const size = 32 * 1024 * 1024
	imgPath := filepath.Join(t.TempDir(), "mount.img")
	writeImage(t, imgPath, size, &apfswrite.CreateOptions{VolumeName: "MountVol"})

	mnt := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatalf("mkdir mnt: %v", err)
	}

	out, err := exec.Command("hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", mnt, imgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach: %v\n%s", err, out)
	}
	defer func() {
		if o, e := exec.Command("hdiutil", "detach", mnt).CombinedOutput(); e != nil {
			exec.Command("diskutil", "unmount", "force", mnt).Run()
			t.Logf("hdiutil detach: %v\n%s", e, o)
		}
	}()

	entries, err := os.ReadDir(mnt)
	if err != nil {
		t.Fatalf("ReadDir mount: %v", err)
	}
	for _, e := range entries {
		// The volume itself is empty; ignore any OS-injected artifacts.
		if e.Name() != ".Trashes" && e.Name() != ".fseventsd" && e.Name() != ".Spotlight-V100" {
			t.Errorf("unexpected entry in empty volume root: %q", e.Name())
		}
	}
}

// TestCreateContainerWithFileFsckClean runs Apple's fsck_apfs against a
// container holding one file and checks it with fsck_apfs (macOS only).
func TestCreateContainerWithFileFsckClean(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fsck_apfs is only available on macOS")
	}
	requireTools(t, "hdiutil", "fsck_apfs")

	const size = 32 * 1024 * 1024
	imgPath := filepath.Join(t.TempDir(), "file.img")
	content := []byte("Hello, APFS milestone 1!\n")
	writeImage(t, imgPath, size, &apfswrite.CreateOptions{
		VolumeName: "FsckFileVol",
		RootFiles:  []apfswrite.RootFile{{Name: "hello.txt", Data: content}},
	})

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
			Data: seededBytes(1000+i, int64(1000+i)),
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

// TestCreateContainerLargeFileFsckClean runs Apple's fsck_apfs against a tree
// containing large multi-block files and an empty file (macOS only).
func TestCreateContainerLargeFileFsckClean(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fsck_apfs is only available on macOS")
	}
	requireTools(t, "hdiutil", "fsck_apfs")

	root := &apfswrite.Entry{Children: []*apfswrite.Entry{
		{Name: "onemib.bin", Data: seededBytes(1<<20, 1)},
		{Name: "partial.bin", Data: seededBytes(1<<20+123, 2)},
		{Name: "five.bin", Data: seededBytes(5*(1<<20)+4095, 3)},
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

// TestCreateContainerMetadataFsckClean runs Apple's fsck_apfs against a tree
// carrying non-default modes, owners, timestamps and a symbolic link (macOS
// only). fsck_apfs checks the inode fields and the symlink
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

// TestCreateContainerSnapshotFsckClean creates a container whose volume carries a
// snapshot and checks it with fsck_apfs (macOS).
func TestCreateContainerSnapshotFsckClean(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fsck_apfs is only available on macOS")
	}
	requireTools(t, "hdiutil", "fsck_apfs")

	const size = 32 * 1024 * 1024
	imgPath := filepath.Join(t.TempDir(), "snap.img")
	writeImage(t, imgPath, size, snapshotOpts())

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

// TestCreateContainerSnapshotApfsckClean is the Linux counterpart via apfsck.
func TestCreateContainerSnapshotApfsckClean(t *testing.T) {
	if _, err := exec.LookPath("apfsck"); err != nil {
		t.Skip("apfsck not installed; skipping (install apfsprogs)")
	}
	const size = 32 * 1024 * 1024
	imgPath := filepath.Join(t.TempDir(), "snap.img")
	writeImage(t, imgPath, size, snapshotOpts())

	out, err := exec.Command("apfsck", "-cw", imgPath).CombinedOutput()
	t.Logf("apfsck output:\n%s", out)
	if err != nil {
		t.Fatalf("apfsck reported problems (exit %v)", err)
	}
}

// TestCreateContainerSnapshotListedByDiskutil confirms macOS recognizes the
// snapshot: it synthesizes and mounts the APFS volume (which proves the
// container is spec-valid to the real driver, not just to fsck) and lists the
// snapshot with diskutil.
func TestCreateContainerSnapshotListedByDiskutil(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("diskutil is only available on macOS")
	}
	requireTools(t, "hdiutil", "diskutil")

	const size = 32 * 1024 * 1024
	imgPath := filepath.Join(t.TempDir(), "snap.img")
	writeImage(t, imgPath, size, snapshotOpts())

	mnt := t.TempDir()
	// Mounting (not a raw attach) makes macOS synthesize the APFS volume; the
	// attach output names the synthesized volume device.
	out, err := exec.Command("hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", mnt, imgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach (mount) failed: %v\n%s", err, out)
	}
	defer exec.Command("hdiutil", "detach", mnt).Run()

	vol := regexp.MustCompile(`/dev/disk\d+s\d+`).FindString(string(out))
	if vol == "" {
		t.Fatalf("could not find synthesized volume device in attach output:\n%s", out)
	}

	snap, err := exec.Command("diskutil", "apfs", "listSnapshots", vol).CombinedOutput()
	t.Logf("diskutil listSnapshots %s:\n%s", vol, snap)
	if err != nil {
		t.Fatalf("diskutil listSnapshots failed (exit %v)", err)
	}
	if !strings.Contains(string(snap), "baseline") {
		t.Errorf("diskutil did not list the 'baseline' snapshot:\n%s", snap)
	}
}

// snapshotOpts builds CreateOptions for a small populated volume carrying one
// snapshot named "baseline".
func snapshotOpts() *apfswrite.CreateOptions {
	return &apfswrite.CreateOptions{
		VolumeName: "SnapVol",
		RootFiles:  []apfswrite.RootFile{{Name: "hello.txt", Data: []byte("hello snapshot\n")}},
		Snapshots:  []apfswrite.SnapshotSpec{{Name: "baseline"}},
	}
}

// TestCreateContainerTreeFsckClean runs Apple's fsck_apfs against a nested tree
// (macOS only).
func TestCreateContainerTreeFsckClean(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fsck_apfs is only available on macOS")
	}
	requireTools(t, "hdiutil", "fsck_apfs")

	root := &apfswrite.Entry{Children: []*apfswrite.Entry{
		{Name: "readme.txt", Data: []byte("hello from a tree\n")},
		{Name: "dir_a", Mode: fs.ModeDir, Children: []*apfswrite.Entry{
			{Name: "one.txt", Data: []byte("one\n")},
			{Name: "two.txt", Data: []byte("two\n")},
			{Name: "inner", Mode: fs.ModeDir, Children: []*apfswrite.Entry{
				{Name: "deep.bin", Data: bytes.Repeat([]byte{0x5A}, 300)},
			}},
		}},
		{Name: "dir_b", Mode: fs.ModeDir, Children: []*apfswrite.Entry{
			{Name: "b1.txt", Data: []byte("b one\n")},
		}},
	}}

	const size = 32 * 1024 * 1024
	imgPath := filepath.Join(t.TempDir(), "tree.img")
	writeImage(t, imgPath, size, &apfswrite.CreateOptions{VolumeName: "FsckTreeVol", Root: root})

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

// TestCreateContainerMultiLeafFsckClean forces file-system tree growth and checks
// fsck_apfs is still clean (macOS only).
func TestCreateContainerMultiLeafFsckClean(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fsck_apfs is only available on macOS")
	}
	requireTools(t, "hdiutil", "fsck_apfs")

	const nFiles = 60
	children := make([]*apfswrite.Entry, 0, nFiles)
	for i := 0; i < nFiles; i++ {
		children = append(children, &apfswrite.Entry{
			Name: fmt.Sprintf("file_%03d.txt", i),
			Data: []byte(fmt.Sprintf("content for file %d\n", i)),
		})
	}
	root := &apfswrite.Entry{Children: children}

	const size = 32 * 1024 * 1024
	imgPath := filepath.Join(t.TempDir(), "multileaf.img")
	writeImage(t, imgPath, size, &apfswrite.CreateOptions{VolumeName: "FsckMultiLeaf", Root: root})

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

// TestCreateContainerMultiChunkFsckClean checks a container whose allocation
// bitmap spans more than one chunk: 130 MiB of file data pushes the used
// region past block 32768, the end of the space manager's first chunk.
// pkg/apfswrite's TestCreateContainerMultiChunk reads the same container back
// with our own reader; this one asks fsck_apfs instead.
func TestCreateContainerMultiChunkFsckClean(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fsck_apfs is only available on macOS")
	}
	requireTools(t, "hdiutil", "fsck_apfs")

	const size = 160 * 1024 * 1024
	root := &apfswrite.Entry{Children: []*apfswrite.Entry{
		{Name: "huge.bin", Data: seededBytes(130*(1<<20)+777, 7)},
		{Name: "note.txt", Data: []byte("crosses a chunk boundary\n")},
	}}

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

// multiSnapshotOptions builds a populated volume carrying n snapshots.
func multiSnapshotOptions(n int) *apfswrite.CreateOptions {
	snaps := make([]apfswrite.SnapshotSpec, n)
	for i := range snaps {
		snaps[i] = apfswrite.SnapshotSpec{Name: fmt.Sprintf("snap%d", i+1)}
	}
	return &apfswrite.CreateOptions{
		VolumeName: "MultiSnap",
		Snapshots:  snaps,
		Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
			{Name: "f.txt", Data: []byte("multi-snapshot content\n")},
		}},
	}
}

// TestMultipleSnapshotsApfsckClean is the always-on gate for more than one
// snapshot. Each of the three things that had to change shows up here as a
// distinct apfsck complaint if it regresses: the object map's node transaction
// id, the ephemeral objects' transaction id, and which snapshot owns the
// populated extent-reference tree.
func TestMultipleSnapshotsApfsckClean(t *testing.T) {
	if _, err := exec.LookPath("apfsck"); err != nil {
		t.Skip("apfsck not installed; skipping (install apfsprogs)")
	}

	for _, n := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("%d snapshots", n), func(t *testing.T) {
			imgPath := filepath.Join(t.TempDir(), "snaps.img")
			writeImage(t, imgPath, 64*1024*1024, multiSnapshotOptions(n))

			out, err := exec.Command("apfsck", "-cw", imgPath).CombinedOutput()
			t.Logf("apfsck output:\n%s", out)
			if err != nil {
				t.Fatalf("apfsck reported problems (exit %v)", err)
			}
		})
	}
}

// TestMultipleSnapshotsMountAndList is the driver's verdict. Raising the live
// transaction id past the snapshots is exactly the change macOS refuses when
// the container has no earlier checkpoint, so mounting is the test that
// matters; diskutil then has to agree about how many snapshots there are and
// what they are called.
func TestMultipleSnapshotsMountAndList(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("hdiutil and diskutil are macOS-only")
	}
	requireTools(t, "hdiutil", "diskutil", "fsck_apfs")

	const n = 3
	imgPath := filepath.Join(t.TempDir(), "snaps.img")
	writeImage(t, imgPath, 64*1024*1024, multiSnapshotOptions(n))

	// An APFS container surfaces as a synthesized disk of its own, separate
	// from the physical store hdiutil attached, so the volume to ask about is
	// not simply the attached device plus a slice.
	attach, err := exec.Command("hdiutil", "attach", "-readonly", "-nobrowse",
		"-imagekey", "diskimage-class=CRawDiskImage", imgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach: %v\n%s", err, attach)
	}
	dev := devRe.FindString(string(attach))
	defer detach(t, dev)

	volume := regexp.MustCompile(`/dev/disk\d+s\d+`).FindString(string(attach))
	if volume == "" {
		t.Fatalf("no APFS volume device in the attach output:\n%s", attach)
	}

	out, err := exec.Command("diskutil", "apfs", "listSnapshots", volume).CombinedOutput()
	if err != nil {
		t.Fatalf("diskutil listSnapshots: %v\n%s", err, out)
	}
	t.Logf("diskutil output:\n%s", out)
	for i := 1; i <= n; i++ {
		if !strings.Contains(string(out), fmt.Sprintf("snap%d", i)) {
			t.Errorf("diskutil does not list snap%d", i)
		}
	}

	fsck, _ := exec.Command("fsck_apfs", "-n", dev).CombinedOutput()
	if strings.Contains(string(fsck), "corrupt") {
		t.Errorf("fsck_apfs found the volume corrupt:\n%s", fsck)
	}
}

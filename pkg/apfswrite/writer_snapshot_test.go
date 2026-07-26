// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// TestSnapshotWriterRejectsBadSpecs covers the snapshot validation error paths
// (cross-platform, no external tools).
func TestSnapshotWriterRejectsBadSpecs(t *testing.T) {
	cases := []struct {
		name  string
		snaps []apfswrite.SnapshotSpec
	}{
		{"empty name", []apfswrite.SnapshotSpec{{Name: ""}}},
		{"duplicate-nul", []apfswrite.SnapshotSpec{{Name: "a\x00b"}}},
		{"more than one", []apfswrite.SnapshotSpec{{Name: "a"}, {Name: "b"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "snap-*.img")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			err = apfswrite.CreateContainer(f, 32*1024*1024, &apfswrite.CreateOptions{
				VolumeName: "V",
				RootFiles:  []apfswrite.RootFile{{Name: "f", Data: []byte("x")}},
				Snapshots:  tc.snaps,
			})
			if err == nil {
				t.Errorf("expected an error for %q, got nil", tc.name)
			}
		})
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

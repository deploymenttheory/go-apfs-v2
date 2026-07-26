// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// memImage is a growable in-memory io.WriterAt / io.ReaderAt used to build and
// then read back a container without touching the filesystem.
type memImage struct {
	data []byte
}

func (m *memImage) WriteAt(p []byte, off int64) (int, error) {
	end := off + int64(len(p))
	if end > int64(len(m.data)) {
		grown := make([]byte, end)
		copy(grown, m.data)
		m.data = grown
	}
	copy(m.data[off:], p)
	return len(p), nil
}

func (m *memImage) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, fmt.Errorf("read past end of image")
	}
	n := copy(p, m.data[off:])
	return n, nil
}

// TestCreateContainerReadRoundTrip formats a container in memory and reads it
// back with the MIT reader. It runs on every OS and is the cross-platform gate.
func TestCreateContainerReadRoundTrip(t *testing.T) {
	containerUUID := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x47, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	volumeUUID := [16]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x47, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}

	cases := []struct {
		name          string
		caseSensitive bool
	}{
		{"case-insensitive", false},
		{"case-sensitive", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const size = 8 * 1024 * 1024
			img := &memImage{}
			opts := &apfswrite.CreateOptions{
				VolumeName:    "RoundTrip",
				CaseSensitive: tc.caseSensitive,
				ContainerUUID: containerUUID,
				VolumeUUID:    volumeUUID,
			}
			if err := apfswrite.CreateContainer(img, size, opts); err != nil {
				t.Fatalf("CreateContainer: %v", err)
			}

			container, err := apfs.Open(img, &apfs.OpenOptions{})
			if err != nil {
				t.Fatalf("apfs.Open: %v", err)
			}

			// Container UUID.
			gotCUUID, err := container.Identifier()
			if err != nil {
				t.Fatalf("container GetIdentifier: %v", err)
			}
			if !bytesEqual(gotCUUID, containerUUID[:]) {
				t.Errorf("container UUID = %x, want %x", gotCUUID, containerUUID)
			}

			// Exactly one volume.
			volumes, err := container.Volumes()
			if err != nil {
				t.Fatalf("Volumes: %v", err)
			}
			if len(volumes) != 1 {
				t.Fatalf("volume count = %d, want 1", len(volumes))
			}
			v := volumes[0]

			// Name.
			name, err := v.UTF8Name()
			if err != nil {
				t.Fatalf("GetUTF8Name: %v", err)
			}
			if name != "RoundTrip" {
				t.Errorf("volume name = %q, want %q", name, "RoundTrip")
			}

			// Volume UUID.
			gotVUUID, err := v.Identifier()
			if err != nil {
				t.Fatalf("volume GetIdentifier: %v", err)
			}
			if gotVUUID != volumeUUID {
				t.Errorf("volume UUID = %x, want %x", gotVUUID, volumeUUID)
			}

			// Case sensitivity.
			caseInsensitive, err := v.IsCaseInsensitive()
			if err != nil {
				t.Fatalf("IsCaseInsensitive: %v", err)
			}
			if caseInsensitive != !tc.caseSensitive {
				t.Errorf("IsCaseInsensitive = %v, want %v", caseInsensitive, !tc.caseSensitive)
			}

			// Zero user files: the root directory is empty.
			entries, err := v.ReadDir(".")
			if err != nil {
				t.Fatalf("ReadDir: %v", err)
			}
			if len(entries) != 0 {
				names := make([]string, len(entries))
				for i, e := range entries {
					names[i] = e.Name()
				}
				t.Errorf("root has %d entries %v, want 0", len(entries), names)
			}
		})
	}
}

func bytesEqual(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestCreateContainerFsckClean formats a container into a temp file and runs
// Apple's fsck_apfs against it (macOS only). fsck_apfs is the primary oracle.
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

// --- darwin test helpers ---

func writeImage(t *testing.T, path string, size int64, opts *apfswrite.CreateOptions) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create image: %v", err)
	}
	if err := apfswrite.CreateContainer(f, size, opts); err != nil {
		f.Close()
		t.Fatalf("CreateContainer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close image: %v", err)
	}
}

var devRe = regexp.MustCompile(`/dev/disk\d+`)

func attachRaw(t *testing.T, imgPath string) string {
	t.Helper()
	out, err := exec.Command("hdiutil", "attach",
		"-imagekey", "diskimage-class=CRawDiskImage",
		"-nomount", "-readonly", imgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach: %v\n%s", err, out)
	}
	dev := devRe.FindString(string(out))
	if dev == "" {
		t.Fatalf("could not find /dev/diskN in hdiutil output:\n%s", out)
	}
	return dev
}

func detach(t *testing.T, dev string) {
	t.Helper()
	if out, err := exec.Command("hdiutil", "detach", dev).CombinedOutput(); err != nil {
		t.Logf("hdiutil detach %s: %v\n%s", dev, err, out)
	}
}

func requireTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("required tool %q not found", tool)
		}
	}
}

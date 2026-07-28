//go:build linux || darwin

// End-to-end mount coverage: the volume is mounted for real and then read
// through the operating system, so the kernel decides whether it worked.
//
// This is the only thing that exercises Lookup, which allocates an inode in a
// live FUSE tree and so cannot be called directly. Every path resolved below
// goes through it.
//
// FUSE is required. Linux runners have it; macOS needs macFUSE, which installs
// a kernel extension and is not available on hosted runners, so this skips
// there rather than failing.
package acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
)

// requireFUSE skips unless a FUSE mount can actually be attempted here.
func requireFUSE(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "darwin" {
		// macFUSE ships a kernel extension, so it is absent on hosted runners
		// and on most developer machines that have not installed it.
		if _, err := os.Stat("/Library/Filesystems/macfuse.fs"); err != nil {
			t.Skip("macFUSE is not installed; a real mount cannot be tested here")
		}
		return
	}
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("/dev/fuse is absent; a real mount cannot be tested here")
	}
}

// openVolumeFS opens an image as a VolumeFS, dispatching on the file system the
// same way the command line does.
func openVolumeFS(t *testing.T, imagePath string) tools.VolumeFS {
	t.Helper()

	reader, offset, closer, err := disk.OpenWithOffset(imagePath)
	if err != nil {
		t.Fatalf("opening %s: %v", imagePath, err)
	}
	t.Cleanup(func() { closer.Close() })

	var device io.ReaderAt = reader
	if offset != 0 {
		device = io.NewSectionReader(reader, offset, 1<<62)
	}

	magic := make([]byte, 4)
	if _, err := device.ReadAt(magic, 32); err == nil && string(magic) == "NXSB" {
		container, err := apfs.Open(device, &apfs.OpenOptions{})
		if err != nil {
			t.Fatalf("opening the APFS container: %v", err)
		}
		t.Cleanup(func() { container.Close() })
		volume, err := container.VolumeBySelector("0")
		if err != nil {
			t.Fatalf("selecting the volume: %v", err)
		}
		return volume
	}

	volume, err := hfsplus.New(device)
	if err != nil {
		t.Fatalf("opening the HFS+ volume: %v", err)
	}
	return volume
}

// mountFixture mounts an image and returns the mount point. Unmounting is
// registered as cleanup, so a failing assertion cannot leave a mount behind.
func mountFixture(t *testing.T, imagePath string) string {
	t.Helper()

	volume := openVolumeFS(t, imagePath)
	mountPoint := t.TempDir()

	server, err := tools.MountVolumeFS(volume, "apfs-test", mountPoint, false)
	if err != nil {
		t.Skipf("unable to mount (FUSE present but unusable here): %v", err)
	}

	t.Cleanup(func() {
		// Unmount can race the kernel releasing the last reference, so give it
		// a few attempts before falling back to the system tool.
		for range 10 {
			if err := server.Unmount(); err == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		if runtime.GOOS == "linux" {
			exec.Command("fusermount3", "-u", mountPoint).Run()
			exec.Command("fusermount", "-u", mountPoint).Run()
		} else {
			exec.Command("umount", mountPoint).Run()
		}
	})

	return mountPoint
}

// TestMountHFSPlusEndToEnd mounts the HFS+ fixture and reads it back through
// the kernel, checking content against the manifest.
func TestMountHFSPlusEndToEnd(t *testing.T) {
	requireFUSE(t)
	if hfsManifest.VolumeName == "" {
		t.Skip("no HFS+ fixture manifest")
	}

	mnt := mountFixture(t, fixtureHFS)

	// Every lookup below resolves a path through the FUSE layer, which is what
	// makes this the coverage Lookup otherwise has none of.
	var checked int
	for name, entry := range hfsManifest.Files {
		path := filepath.Join(mnt, name)

		switch entry.Type {
		case "file":
			info, err := os.Stat(path)
			if err != nil {
				t.Errorf("stat %s: %v", name, err)
				continue
			}
			if info.Size() != entry.Size {
				t.Errorf("%s: size = %d, want %d", name, info.Size(), entry.Size)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Errorf("read %s: %v", name, err)
				continue
			}
			sum := sha256.Sum256(data)
			if got := hex.EncodeToString(sum[:]); got != entry.SHA256 {
				t.Errorf("%s: sha256 = %s, want %s", name, got, entry.SHA256)
			}
			checked++

		case "symlink":
			target, err := os.Readlink(path)
			if err != nil {
				t.Errorf("readlink %s: %v", name, err)
				continue
			}
			if target != entry.Target {
				t.Errorf("%s: target = %q, want %q", name, target, entry.Target)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("the manifest described nothing to check")
	}
	t.Logf("verified %d entries through a real mount", checked)
}

// TestMountReaddirEndToEnd checks a directory listing through the kernel,
// which goes through Readdir and then Lookup for each entry stat.
func TestMountReaddirEndToEnd(t *testing.T) {
	requireFUSE(t)
	if hfsManifest.VolumeName == "" {
		t.Skip("no HFS+ fixture manifest")
	}

	mnt := mountFixture(t, fixtureHFS)

	entries, err := os.ReadDir(mnt)
	if err != nil {
		t.Fatalf("reading the mount point: %v", err)
	}

	got := make([]string, 0, len(entries))
	for _, e := range entries {
		got = append(got, e.Name())
	}
	sort.Strings(got)

	// Every manifest path contributes its first component to the root listing.
	want := map[string]bool{}
	for name := range hfsManifest.Files {
		first, _, _ := strings.Cut(name, "/")
		want[first] = true
	}
	for name := range want {
		found := false
		for _, g := range got {
			if g == name {
				found = true
			}
		}
		if !found {
			t.Errorf("the mounted root is missing %q; it listed %v", name, got)
		}
	}

	// A directory must be reported as one, and be walkable.
	if _, err := os.ReadDir(filepath.Join(mnt, "dir1")); err != nil {
		t.Errorf("reading a subdirectory through the mount: %v", err)
	}
	if _, err := os.Stat(filepath.Join(mnt, "dir1", "nested", "deep.txt")); err != nil {
		t.Errorf("resolving a nested path through the mount: %v", err)
	}
}

// TestMountXattrsEndToEnd checks extended attributes are served, which is the
// half of the FUSE layer a read-only listing does not touch.
func TestMountXattrsEndToEnd(t *testing.T) {
	requireFUSE(t)
	if hfsManifest.VolumeName == "" {
		t.Skip("no HFS+ fixture manifest")
	}

	// Find a manifest entry that records at least one attribute.
	var target string
	var wantAttrs map[string]manifestXattr
	for name, entry := range hfsManifest.Files {
		if entry.Type == "file" && len(entry.Xattrs) > 0 {
			target, wantAttrs = name, entry.Xattrs
			break
		}
	}
	if target == "" {
		t.Skip("the manifest records no extended attributes")
	}

	mnt := mountFixture(t, fixtureHFS)
	path := filepath.Join(mnt, target)

	names, err := readXattrNames(path)
	if err != nil {
		t.Skipf("unable to list attributes through the mount: %v", err)
	}
	for want := range wantAttrs {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: attribute %q missing through the mount; got %v", target, want, names)
		}
	}
}

// TestMountAPFSEndToEnd mounts the APFS fixture, so the same FUSE layer is
// shown to serve both file systems rather than only the one it was written
// against.
func TestMountAPFSEndToEnd(t *testing.T) {
	requireFUSE(t)

	mnt := mountFixture(t, fixtureDMG)

	var checked int
	for name, entry := range manifest.Files {
		if entry.Type != "file" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(mnt, name))
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != entry.SHA256 {
			t.Errorf("%s: sha256 = %s, want %s", name, got, entry.SHA256)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("the APFS manifest described no files to check")
	}
	t.Logf("verified %d APFS entries through a real mount", checked)
}

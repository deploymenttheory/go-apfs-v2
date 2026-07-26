// CLI acceptance tests for the write/inverse direction: `apfs pack <dir> out.dmg`
// builds an HFS+ volume from a directory. These exercise the built binary.
package cli_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// buildSampleTree writes a small directory tree under a temp dir and returns
// its path plus a manifest of relative path -> sha256 for regular files.
func buildSampleTree(t *testing.T) (string, map[string]string) {
	t.Helper()
	root := t.TempDir()
	files := map[string][]byte{
		"hello.txt":        []byte("hello from pack\n"),
		"sub/deep.txt":     []byte("a deeper file\n"),
		"sub/more/leaf.md": []byte("# leaf\n"),
		"data.bin":         randomBytes(t, 300000),
	}
	manifest := map[string]string{}
	for rel, content := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, content, 0644); err != nil {
			t.Fatal(err)
		}
		manifest[rel] = sha256Hex(content)
	}
	// An executable and a symlink round out the feature coverage.
	if err := os.WriteFile(filepath.Join(root, "run.sh"), []byte("#!/bin/sh\necho ok\n"), 0755); err != nil {
		t.Fatal(err)
	}
	manifest["run.sh"] = sha256Hex([]byte("#!/bin/sh\necho ok\n"))
	if runtime.GOOS != "windows" {
		os.Symlink("hello.txt", filepath.Join(root, "link"))
	}
	return root, manifest
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestPackDirRoundTrip packs a directory into an HFS+ DMG and verifies our own
// reader extracts identical content — the write->read round trip.
func TestPackDirRoundTrip(t *testing.T) {
	src, manifest := buildSampleTree(t)
	dmg := filepath.Join(t.TempDir(), "packed.dmg")

	mustRun(t, "pack", src, dmg, "--volname", "PACKTEST")

	info := infoJSON(t, dmg)
	if info.FileSystem != "hfs+" {
		t.Errorf("packed volume file system = %q, want hfs+", info.FileSystem)
	}
	if info.Volumes[0].Name != "PACKTEST" {
		t.Errorf("volume name = %q, want PACKTEST", info.Volumes[0].Name)
	}

	dest := t.TempDir()
	mustRun(t, "extract", dmg, "-C", dest)
	for rel, want := range manifest {
		got, err := fileSHA256(filepath.Join(dest, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("%s: missing after pack+extract: %v", rel, err)
			continue
		}
		if got != want {
			t.Errorf("%s: content mismatch after pack round-trip", rel)
		}
	}
}

// TestPackAddFileByteDelta is the write-direction size-attribution test: adding
// a file of K incompressible bytes grows the created HFS+ raw image by the
// block-aligned data size plus only a small metadata envelope. This is the
// sound form of "add files and expect a byte diff" — exact at the block level,
// not the (compressor-dependent) DMG level.
func TestPackAddFileByteDelta(t *testing.T) {
	const blockSize = 4096
	const addedBytes = 512 * 1024 // 512 KiB of random (incompressible) data

	base, _ := buildSampleTree(t)

	// Pack the base tree and measure its raw image size.
	baseDMG := filepath.Join(t.TempDir(), "base.dmg")
	mustRun(t, "pack", base, baseDMG, "--volname", "DELTA")
	baseRaw, err := disk.ReconstructRawImage(baseDMG)
	if err != nil {
		t.Fatal(err)
	}
	baseSize := len(baseRaw)

	// Add one incompressible file and re-pack.
	added := randomBytes(t, addedBytes)
	if err := os.WriteFile(filepath.Join(base, "added.bin"), added, 0644); err != nil {
		t.Fatal(err)
	}
	plusDMG := filepath.Join(t.TempDir(), "plus.dmg")
	mustRun(t, "pack", base, plusDMG, "--volname", "DELTA")
	plusRaw, err := disk.ReconstructRawImage(plusDMG)
	if err != nil {
		t.Fatal(err)
	}
	plusSize := len(plusRaw)

	delta := plusSize - baseSize
	alignedData := ((addedBytes + blockSize - 1) / blockSize) * blockSize
	const metadataEnvelope = 256 * 1024 // catalog/bitmap growth headroom

	if delta < alignedData {
		t.Errorf("raw image grew by %d bytes, want at least the block-aligned data size %d", delta, alignedData)
	}
	if delta > alignedData+metadataEnvelope {
		t.Errorf("raw image grew by %d bytes, more than data %d + metadata envelope %d", delta, alignedData, metadataEnvelope)
	}
	t.Logf("adding %d bytes grew the raw HFS+ image by %d bytes (block-aligned data %d)", addedBytes, delta, alignedData)

	// The added file must extract with correct content.
	dest := t.TempDir()
	mustRun(t, "extract", plusDMG, "-C", dest)
	got, err := fileSHA256(filepath.Join(dest, "added.bin"))
	if err != nil || got != sha256Hex(added) {
		t.Errorf("added.bin did not round-trip after pack: err=%v", err)
	}
}

// TestPackDirFsckAndMount validates the created file system with Apple's own
// tools on macOS: reconstruct the raw HFS+ image from our DMG, run fsck_hfs,
// and mount it read-only, confirming content.
func TestPackDirFsckAndMount(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fsck_hfs / hdiutil ground truth requires macOS")
	}
	src, manifest := buildSampleTree(t)
	dmg := filepath.Join(t.TempDir(), "packed.dmg")
	mustRun(t, "pack", src, dmg, "--volname", "FSCKTEST")

	raw, err := disk.ReconstructRawImage(dmg)
	if err != nil {
		t.Fatal(err)
	}
	rawPath := filepath.Join(t.TempDir(), "raw.img")
	if err := os.WriteFile(rawPath, raw, 0644); err != nil {
		t.Fatal(err)
	}

	// Attach the raw image without mounting, fsck the device, then detach.
	out, err := exec.Command("hdiutil", "attach", "-imagekey", "diskimage-class=CRawDiskImage",
		"-nomount", "-readonly", rawPath).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach (nomount) failed: %v\n%s", err, out)
	}
	dev := firstDevice(string(out))
	defer exec.Command("hdiutil", "detach", dev).Run()

	fsckOut, _ := exec.Command("fsck_hfs", "-n", dev).CombinedOutput()
	if !strings.Contains(string(fsckOut), "appears to be OK") {
		t.Errorf("fsck_hfs did not report clean:\n%s", fsckOut)
	}

	// Mount read-only and verify content.
	mnt := filepath.Join(t.TempDir(), "mnt")
	os.MkdirAll(mnt, 0755)
	if out, err := exec.Command("hdiutil", "attach", "-readonly", "-nobrowse",
		"-mountpoint", mnt, rawPath).CombinedOutput(); err != nil {
		t.Fatalf("hdiutil mount failed: %v\n%s", err, out)
	}
	defer exec.Command("hdiutil", "detach", mnt).Run()

	for rel, want := range manifest {
		got, err := fileSHA256(filepath.Join(mnt, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("%s: unreadable on mounted volume: %v", rel, err)
			continue
		}
		if got != want {
			t.Errorf("%s: content mismatch on hdiutil-mounted created volume", rel)
		}
	}
}

func firstDevice(hdiutilOutput string) string {
	for _, line := range strings.Split(hdiutilOutput, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.HasPrefix(f[0], "/dev/") {
			return f[0]
		}
	}
	return ""
}

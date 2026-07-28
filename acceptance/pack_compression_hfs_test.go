//go:build darwin

// Packing a compressed source tree into HFS+. macOS-only for the same reason
// as the APFS side: only macOS can produce a compressed file to pack, and only
// macOS and fsck_hfs can judge the result independently.
//
// HFS+ differs from APFS in a way worth exploiting here: this toolkit's own
// reader dispatches on UF_COMPRESSED rather than on the attribute's presence,
// so a self round-trip is a genuine test of the flag. It is still not the whole
// story — fsck_hfs and the driver see things our reader cannot — which is what
// these add.
package acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var wholeDiskRe = regexp.MustCompile(`/dev/disk\d+`)

// attachHFS attaches a packed HFS+ DMG and returns its mount point and the
// device fsck_hfs should be pointed at.
//
// A DMG this tool creates carries no partition map, so the whole disk is the
// volume: there is no sNN slice, and the device to check is /dev/diskN itself.
func attachHFS(t *testing.T, dmg string) (mountPoint, dev string) {
	t.Helper()
	out, err := exec.Command("hdiutil", "attach", "-readonly", "-nobrowse", dmg).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach %s: %v\n%s", dmg, err, out)
	}
	dev = wholeDiskRe.FindString(string(out))
	mountPoint = mountPointFrom(out)
	if dev == "" || mountPoint == "" {
		t.Fatalf("%s did not attach and mount:\n%s", dmg, out)
	}
	return mountPoint, dev
}

// TestPackHFSPlusPreservesCompression is the change: HFS+ no longer silently
// means "no compression".
func TestPackHFSPlusPreservesCompression(t *testing.T) {
	src, wantSum, wantSize := compressibleTree(t)

	dmg := filepath.Join(t.TempDir(), "hfs-keep.dmg")
	stdout, stderr, code := run(t, "pack", src, dmg, "--fs", "hfs+", "--volname", "HfsKeep")
	if code != 0 {
		t.Fatalf("pack exited %d\n%s%s", code, stdout, stderr)
	}
	if strings.Contains(stderr, "compression not carried across") {
		t.Errorf("HFS+ reported the compression dropped:\n%s", stderr)
	}

	mountPoint, dev := attachHFS(t, dmg)
	defer detach(t, dev)

	path := filepath.Join(mountPoint, "big.txt")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != wantSize {
		t.Errorf("size = %d, want %d", info.Size(), wantSize)
	}
	if _, _, compressed := compressedAttributes(t, path); !compressed {
		t.Error("the packed file is not compressed; its compression was not carried across")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read through the mount: %v", err)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != wantSum {
		t.Error("content read through macOS does not match the source")
	}
}

// TestPackHFSPlusCompressedIsFsckClean is the independent structural check.
// Writing UF_COMPRESSED without the attribute the flag promises, or the
// attribute without the flag, is the kind of disagreement fsck_hfs is built to
// notice and our own reader is not.
func TestPackHFSPlusCompressedIsFsckClean(t *testing.T) {
	requireTools(t, "fsck_hfs")
	src, _, _ := compressibleTree(t)

	dmg := filepath.Join(t.TempDir(), "hfs-fsck.dmg")
	mustRun(t, "pack", src, dmg, "--fs", "hfs+", "--volname", "HfsFsck")

	mountPoint, dev := attachHFS(t, dmg)
	_ = mountPoint
	defer detach(t, dev)

	out, _ := exec.Command("fsck_hfs", "-n", dev).CombinedOutput()
	t.Logf("fsck_hfs output:\n%s", out)
	if !strings.Contains(string(out), "appears to be OK") {
		t.Errorf("fsck_hfs did not report the volume clean")
	}
}

// TestPackHFSPlusDecompressOptsOut checks --decompress now applies to HFS+ too,
// where it used to be refused because the writer could not do anything else.
func TestPackHFSPlusDecompressOptsOut(t *testing.T) {
	src, wantSum, wantSize := compressibleTree(t)

	dmg := filepath.Join(t.TempDir(), "hfs-full.dmg")
	stdout, stderr, code := run(t, "pack", src, dmg, "--fs", "hfs+", "--volname", "HfsFull", "--decompress")
	if code != 0 {
		t.Fatalf("pack --decompress exited %d\n%s%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "compression not carried across") {
		t.Errorf("no note about the compression being dropped:\n%s", stderr)
	}

	mountPoint, dev := attachHFS(t, dmg)
	defer detach(t, dev)

	path := filepath.Join(mountPoint, "big.txt")
	if _, _, compressed := compressedAttributes(t, path); compressed {
		t.Error("--decompress left the file compressed")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != wantSize {
		t.Errorf("size = %d, want %d", info.Size(), wantSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read through the mount: %v", err)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != wantSum {
		t.Error("content does not match the source")
	}

	// The hazard when compression is dropped: the compressed payload must not
	// come along on its own. HFS+ stores a resource fork on the catalog record,
	// so a fork carried without its decmpfs header would be compressed bytes
	// hanging off a file whose content is already there in full.
	names, err := readXattrNames(path)
	if err == nil {
		for _, n := range names {
			if n == "com.apple.ResourceFork" {
				t.Error("the compressed resource fork was written beside the decompressed content")
			}
		}
	}
}

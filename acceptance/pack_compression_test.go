//go:build darwin

// Packing a transparently compressed source tree. macOS-only because decmpfs
// is: only macOS can produce a compressed file to pack, and only macOS can say
// whether the packed one is still compressed.
//
// The hazard these guard against is subtle. Reading a compressed file's
// attributes needs XATTR_SHOWCOMPRESSION, and turning it on makes both
// com.apple.decmpfs and com.apple.ResourceFork visible to the walk for the
// first time. Carried separately they contradict each other: the fork alone is
// compressed bytes sitting beside a decompressed data fork, and the header
// alone describes content that is not there. So they are kept or dropped as one
// thing, and the data fork is not read at all when they are kept.
//
// The HFS+ half lives in pack_compression_hfs_test.go, which needs a different
// mount helper: a DMG this tool creates has no partition map, so the whole disk
// is the volume.
package acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// compressibleTree builds a source tree holding one compressed file and one
// ordinary one. ditto --hfsCompression is how macOS compresses a file in place;
// it is the same mechanism the system uses for its own binaries.
func compressibleTree(t *testing.T) (dir string, wantSum string, size int64) {
	t.Helper()
	requireTools(t, "ditto")

	plain := t.TempDir()
	body := strings.Repeat("the quick brown fox jumps over the lazy dog\n", 8000)
	if err := os.WriteFile(filepath.Join(plain, "big.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plain, "plain.txt"), []byte("ordinary\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	dir = filepath.Join(t.TempDir(), "compressed")
	if out, err := exec.Command("ditto", "--hfsCompression", plain, dir).CombinedOutput(); err != nil {
		t.Skipf("ditto --hfsCompression failed, so there is no compressed file to pack: %v\n%s", err, out)
	}

	// Confirm the source really is compressed; otherwise the test proves nothing.
	if _, _, ok := compressedAttributes(t, filepath.Join(dir, "big.txt")); !ok {
		t.Skip("ditto did not compress the file on this file system")
	}

	sum := sha256.Sum256([]byte(body))
	return dir, hex.EncodeToString(sum[:]), int64(len(body))
}

// packedFile mounts a packed DMG and returns one file's contents, its size as
// the driver reports it, and whether the driver considers it compressed.
func packedFile(t *testing.T, dmg, name string) (data []byte, size int64, compressed bool) {
	t.Helper()
	requireTools(t, "hdiutil")

	out, err := exec.Command("hdiutil", "attach", "-readonly", dmg).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach %s: %v\n%s", dmg, err, out)
	}
	dev := devRe.FindString(string(out))
	defer detach(t, dev)

	mountPoint := mountPointFrom(out)
	if mountPoint == "" {
		t.Fatalf("%s did not mount:\n%s", dmg, out)
	}

	path := filepath.Join(mountPoint, name)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	if data, err = os.ReadFile(path); err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	_, _, compressed = compressedAttributes(t, path)
	return data, info.Size(), compressed
}

// TestPackAPFSPreservesCompression is the point of the whole change: a
// compressed file packed into an APFS image is still compressed, and still
// reads back byte for byte.
func TestPackAPFSPreservesCompression(t *testing.T) {
	src, wantSum, wantSize := compressibleTree(t)

	dmg := filepath.Join(t.TempDir(), "keep.dmg")
	mustRun(t, "pack", src, dmg, "--fs", "apfs", "--volname", "Keep")

	data, size, compressed := packedFile(t, dmg, "big.txt")
	if !compressed {
		t.Error("the packed file is not compressed; its compression was not carried across")
	}
	if size != wantSize {
		t.Errorf("size = %d, want %d", size, wantSize)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != wantSum {
		t.Errorf("content does not match the source")
	}
}

// TestPackAPFSDecompressOptsOut checks --decompress writes the file out in full
// and says so, rather than quietly doing the same thing either way.
func TestPackAPFSDecompressOptsOut(t *testing.T) {
	src, wantSum, wantSize := compressibleTree(t)

	dmg := filepath.Join(t.TempDir(), "full.dmg")
	stdout, stderr, code := run(t, "pack", src, dmg, "--fs", "apfs", "--volname", "Full", "--decompress")
	if code != 0 {
		t.Fatalf("pack --decompress exited %d\n%s%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "compression not carried across") {
		t.Errorf("no note about the compression being dropped:\n%s", stderr)
	}

	data, size, compressed := packedFile(t, dmg, "big.txt")
	if compressed {
		t.Error("--decompress left the file compressed")
	}
	if size != wantSize {
		t.Errorf("size = %d, want %d", size, wantSize)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != wantSum {
		t.Errorf("content does not match the source")
	}
}

// TestPackCompressionIsCountedInJSON checks the loss is reported under its own
// key, not folded into the attribute or resource-fork counts, which would say
// content was lost when none was.
func TestPackCompressionIsCountedInJSON(t *testing.T) {
	src, _, _ := compressibleTree(t)

	dmg := filepath.Join(t.TempDir(), "json.dmg")
	report, code := packJSON(t, src, dmg, "--fs", "apfs", "--volname", "J", "--decompress", "-o", "json")
	if code != 0 {
		t.Fatalf("pack exited %d", code)
	}
	if got := intField(t, report, "compressionNotPreserved"); got != 1 {
		t.Errorf("compressionNotPreserved = %d, want 1 (keys: %v)", got, sortedKeys(report))
	}
	for _, key := range []string{"xattrsDropped", "resourceForksDropped"} {
		if got := intField(t, report, key); got != 0 {
			t.Errorf("%s = %d, want 0: nothing was lost, the file was written out in full", key, got)
		}
	}
}

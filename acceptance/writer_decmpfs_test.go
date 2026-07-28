// Checker tests for decmpfs-compressed files. The unit tests in pkg/apfswrite
// read one back with our own reader, which dispatches on the com.apple.decmpfs
// attribute being present. macOS dispatches on UF_COMPRESSED in bsd_flags
// instead, so a file written with the attribute and no flag passes every test
// we can run against ourselves — and fsck_apfs calls the volume clean — while
// macOS reports it as 0 bytes and empty. Only apfsck and a real mount catch it,
// which is what these are for.
package acceptance

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

const decmpfsText = "the quick brown fox jumps over the lazy dog, repeatedly and at length. " +
	"the quick brown fox jumps over the lazy dog, repeatedly and at length. " +
	"the quick brown fox jumps over the lazy dog, repeatedly and at length.\n"

// inlineDecmpfsAttr builds a type-3 attribute: zlib, payload inline after the
// 16-byte fpmc header. Inline is used here rather than a resource fork because
// apfsck cannot check the fork types macOS actually produces; see
// TestDecmpfsRealFilePassesThrough.
func inlineDecmpfsAttr(payload string) []byte {
	var compressed bytes.Buffer
	w := zlib.NewWriter(&compressed)
	w.Write([]byte(payload))
	w.Close()

	attr := make([]byte, 16)
	copy(attr, "fpmc")
	binary.LittleEndian.PutUint32(attr[4:], 3)
	binary.LittleEndian.PutUint64(attr[8:], uint64(len(payload)))
	return append(attr, compressed.Bytes()...)
}

// writeDecmpfsImage formats a container holding one compressed file and one
// ordinary file, so a checker sees both together.
func writeDecmpfsImage(t *testing.T, path string) {
	t.Helper()
	writeImage(t, path, 32*1024*1024, &apfswrite.CreateOptions{
		VolumeName: "DecmpfsVol",
		Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
			{Name: "plain.txt", Data: []byte("not compressed\n")},
			{Name: "squeezed.txt", Xattrs: map[string][]byte{
				"com.apple.decmpfs": inlineDecmpfsAttr(decmpfsText),
			}},
		}},
	})
}

// TestDecmpfsFsckClean checks Apple's checker accepts a compressed file.
func TestDecmpfsFsckClean(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fsck_apfs is only available on macOS")
	}
	requireTools(t, "hdiutil", "fsck_apfs")

	imgPath := filepath.Join(t.TempDir(), "decmpfs.img")
	writeDecmpfsImage(t, imgPath)

	dev := attachRaw(t, imgPath)
	defer detach(t, dev)

	out, err := exec.Command("fsck_apfs", "-n", dev).CombinedOutput()
	t.Logf("fsck_apfs output:\n%s", out)
	if err != nil {
		t.Fatalf("fsck_apfs reported errors (exit %v)", err)
	}
	if strings.Contains(string(out), "corrupt") {
		t.Errorf("fsck_apfs found the volume corrupt")
	}
}

// TestDecmpfsApfsckClean is the always-on gate. apfsck is the only checker that
// verifies bsd_flags against the attribute — "Inode: is not compressed but has
// decmpfs xattr" — so this is what stops the flag being dropped on a platform
// where no mount is possible.
func TestDecmpfsApfsckClean(t *testing.T) {
	if _, err := exec.LookPath("apfsck"); err != nil {
		t.Skip("apfsck not installed; skipping (install apfsprogs)")
	}

	imgPath := filepath.Join(t.TempDir(), "decmpfs-apfsck.img")
	writeDecmpfsImage(t, imgPath)

	out, err := exec.Command("apfsck", "-cw", imgPath).CombinedOutput()
	t.Logf("apfsck output:\n%s", out)
	if err != nil {
		t.Fatalf("apfsck reported problems (exit %v)", err)
	}
}

// TestDecmpfsMountsAndDecompresses is the driver's verdict: macOS marks the
// file compressed, reports its decompressed length, and hands back the original
// bytes. Nothing else we can run proves the file is readable by the system that
// defines the format.
func TestDecmpfsMountsAndDecompresses(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the APFS driver is only available on macOS")
	}
	requireTools(t, "hdiutil")

	imgPath := filepath.Join(t.TempDir(), "decmpfs-mount.img")
	writeDecmpfsImage(t, imgPath)

	mountPoint, dev := attachAndMount(t, imgPath)
	defer detach(t, dev)

	path := filepath.Join(mountPoint, "squeezed.txt")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat the compressed file: %v", err)
	}
	if info.Size() != int64(len(decmpfsText)) {
		t.Errorf("size = %d, want %d; a size of 0 means UF_COMPRESSED was not set",
			info.Size(), len(decmpfsText))
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the compressed file through the mount: %v", err)
	}
	if string(got) != decmpfsText {
		t.Errorf("read %d bytes, want %d", len(got), len(decmpfsText))
	}

	// The uncompressed file beside it must be untouched.
	if plain, err := os.ReadFile(filepath.Join(mountPoint, "plain.txt")); err != nil ||
		string(plain) != "not compressed\n" {
		t.Errorf("plain.txt = %q, %v", plain, err)
	}
}

// TestDecmpfsRealFilePassesThrough is the fidelity claim tested against real
// data: take a compressed file macOS itself produced, carry its two attributes
// through the writer unchanged, and check the volume reads back byte for byte.
//
// It uses a live system file rather than a committed fixture, because the
// fixture would be a copy of Apple's binary. macOS compresses system files with
// decmpfs type 8 (LZVN in a resource fork) almost exclusively, which is why the
// other tests here use an inline attribute instead: apfsck v0.2.1 misparses the
// fork layout of every type except zlib's and rejects genuine Apple data, so it
// cannot check this one.
func TestDecmpfsRealFilePassesThrough(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("compressed system files and the APFS driver are macOS-only")
	}
	requireTools(t, "hdiutil")

	source := "/bin/ls"
	attr, fork, ok := compressedAttributes(t, source)
	if !ok {
		t.Skipf("%s is not decmpfs-compressed here", source)
	}
	want, err := os.ReadFile(source)
	if err != nil {
		t.Skipf("unable to read %s: %v", source, err)
	}

	imgPath := filepath.Join(t.TempDir(), "decmpfs-real.img")
	writeImage(t, imgPath, 64*1024*1024, &apfswrite.CreateOptions{
		VolumeName: "RealCmp",
		Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
			{Name: "carried", Mode: 0o755, Xattrs: map[string][]byte{
				"com.apple.decmpfs":      attr,
				"com.apple.ResourceFork": fork,
			}},
		}},
	})

	mountPoint, dev := attachAndMount(t, imgPath)
	defer detach(t, dev)

	got, err := os.ReadFile(filepath.Join(mountPoint, "carried"))
	if err != nil {
		t.Fatalf("read the carried file through the mount: %v", err)
	}
	gotSum, wantSum := sha256.Sum256(got), sha256.Sum256(want)
	if gotSum != wantSum {
		t.Errorf("the carried file does not match its source:\n  got  %s (%d bytes)\n  want %s (%d bytes)",
			hex.EncodeToString(gotSum[:]), len(got), hex.EncodeToString(wantSum[:]), len(want))
	}
}

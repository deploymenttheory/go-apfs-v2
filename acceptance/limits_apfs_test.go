// End-to-end measurement of the APFS writer's file-count limit through the
// real binary. pkg/apfswrite/limits_test.go measures the same limit on the
// library; this test repeats it the way a user meets it (pack a directory),
// then hands the largest accepted image to an independent checker.
package acceptance

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/exitcode"
)

// flatDir creates a directory of n small files with 12-byte names.
func flatDir(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	for i := range n {
		name := filepath.Join(dir, fmt.Sprintf("file%08d", i))
		if err := os.WriteFile(name, fmt.Appendf(nil, "file %d\n", i), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// packAPFS packs src into a new APFS DMG and returns its path and exit code.
func packAPFS(t *testing.T, src string) (string, string, int) {
	t.Helper()
	dmg := filepath.Join(t.TempDir(), "limit.dmg")
	_, stderr, code := run(t, "pack", src, dmg, "--fs", "apfs", "--volname", "Limit")
	return dmg, stderr, code
}

// TestPackAPFSFileCountLimit searches for the largest flat directory of small
// files that `pack --fs apfs` accepts, asserts the next file is refused with
// the file-system tree leaf limit, and checks the largest accepted image with
// fsck_apfs (macOS) or apfsck (Linux) when available.
//
// The limit is in leaf nodes, not files, so it moves with per-file metadata:
// macOS tags every file this test creates with a com.apple.provenance xattr,
// which pack preserves as an extra record, and the measured count there
// (714) is lower than the library's bare-file figure (850).
func TestPackAPFSFileCountLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("packs thousands of files")
	}
	accepts := func(n int) bool {
		_, stderr, code := packAPFS(t, flatDir(t, n))
		if code != exitcode.OK && !strings.Contains(stderr, "file-system tree needs") {
			t.Fatalf("pack of %d files failed for an unexpected reason (%s): %s", n, exitcode.Name(code), stderr)
		}
		return code == exitcode.OK
	}

	lo, hi := 1, 5000
	if !accepts(lo) {
		t.Fatalf("pack refused a single file")
	}
	if accepts(hi) {
		t.Fatalf("pack accepted %d files; the limit may have been lifted", hi)
	}
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		if accepts(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	_, stderr, _ := packAPFS(t, flatDir(t, hi))
	attest(t, "pack --fs apfs on %s accepts %d small files; %d refused: %s", runtime.GOOS, lo, hi, strings.TrimSpace(stderr))

	dmg, _, code := packAPFS(t, flatDir(t, lo))
	if code != exitcode.OK {
		t.Fatalf("repack of %d files: %s", lo, exitcode.Name(code))
	}
	checkPackedAPFS(t, dmg)
}

// checkPackedAPFS runs whichever independent APFS checker this platform has
// against the raw image inside dmg.
func checkPackedAPFS(t *testing.T, dmg string) {
	t.Helper()
	raw, err := disk.ReconstructRawImage(dmg)
	if err != nil {
		t.Fatal(err)
	}
	rawPath := filepath.Join(t.TempDir(), "raw.img")
	if err := os.WriteFile(rawPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	checked := false
	if _, err := exec.LookPath("apfsck"); err == nil {
		out, err := exec.Command("apfsck", "-cw", rawPath).CombinedOutput()
		if err != nil {
			t.Fatalf("apfsck reported problems (exit %v):\n%s", err, out)
		}
		attest(t, "apfsck clean on the largest accepted image")
		checked = true
	}
	if runtime.GOOS == "darwin" {
		requireTools(t, "hdiutil", "fsck_apfs")
		dev := attachRaw(t, rawPath)
		defer detach(t, dev)
		out, err := exec.Command("fsck_apfs", "-n", dev).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "appears to be OK") {
			t.Fatalf("fsck_apfs did not report the container clean (%v):\n%s", err, out)
		}
		attest(t, "fsck_apfs clean on the largest accepted image")
		checked = true
	}
	if !checked {
		t.Log("no APFS checker on this platform; the image was only packed")
	}
}

//go:build darwin

package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

// reconstructToRaw decompresses a DMG to a raw image file (fsck/attach need the
// raw file system image, not the compressed DMG wrapper).
func reconstructToRaw(t *testing.T, dmg string) string {
	t.Helper()
	raw, err := disk.ReconstructRawImage(dmg)
	if err != nil {
		t.Fatalf("reconstruct %s: %v", dmg, err)
	}
	p := dmg + ".raw"
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// fsckRaw attaches a raw image and returns fsck_apfs -n output.
func fsckRaw(t *testing.T, rawPath string) string {
	t.Helper()
	for _, tool := range []string{"hdiutil", "fsck_apfs"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	out, err := exec.Command("hdiutil", "attach", "-nomount", "-imagekey", "diskimage-class=CRawDiskImage", rawPath).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach: %v\n%s", err, out)
	}
	dev := strings.Fields(string(out))[0]
	defer exec.Command("hdiutil", "detach", dev).Run()

	fo, _ := exec.Command("fsck_apfs", "-n", dev).CombinedOutput()
	return string(fo)
}

// TestSnapshotCreateRevertFsckDarwin validates that the rebuilt `snapshot create`
// output is fsck-clean and the `snapshot revert` output carries the revert marker
// (macOS/Apple fsck_apfs is the oracle).
func TestSnapshotCreateRevertFsckDarwin(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "f.txt"), []byte("data\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	base := filepath.Join(dir, "base.dmg")
	mustRun(t, "pack", src, base, "--fs", "apfs", "--volname", "Ev")

	// snapshot create output must be fsck-clean.
	withSnap := filepath.Join(dir, "withsnap.dmg")
	mustRun(t, "snapshot", "create", base, "--name", "s1", "-O", withSnap)
	fo := fsckRaw(t, reconstructToRaw(t, withSnap))
	t.Logf("fsck (create output):\n%s", fo)
	if !strings.Contains(fo, "appears to be OK") || strings.Contains(fo, "warning:") {
		t.Errorf("snapshot create output not fsck-clean:\n%s", fo)
	}

	// snapshot revert output must be valid and carry the revert marker.
	revOut := filepath.Join(dir, "rev.dmg")
	mustRun(t, "snapshot", "revert", withSnap, "--name", "s1", "-O", revOut)
	fr := fsckRaw(t, reconstructToRaw(t, revOut))
	t.Logf("fsck (revert output):\n%s", fr)
	if !strings.Contains(fr, "appears to be OK") {
		t.Errorf("revert output not fsck-clean:\n%s", fr)
	}
	if !strings.Contains(fr, "revert_to_xid set") {
		t.Errorf("fsck did not recognize the revert marker:\n%s", fr)
	}
}

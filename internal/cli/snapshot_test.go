// CLI acceptance tests for `apfs snapshot`, exercised through the built binary.
package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSnapshotListCreatedSnapshot creates an APFS volume carrying a snapshot and
// lists it back through the reader.
func TestSnapshotListCreatedSnapshot(t *testing.T) {
	dmg := filepath.Join(t.TempDir(), "snap.dmg")
	mustRun(t, "create", dmg, "--fs", "apfs", "--volname", "SnapVol", "--snapshot", "baseline")

	out := mustRun(t, "snapshot", "list", dmg)
	if !strings.Contains(out, "baseline") {
		t.Errorf("snapshot list did not show the snapshot:\n%s", out)
	}

	j := mustRun(t, "snapshot", "list", "-o", "json", dmg)
	if !strings.Contains(j, `"name":"baseline"`) || !strings.Contains(j, `"xid":1`) {
		t.Errorf("snapshot list json missing snapshot fields:\n%s", j)
	}
}

// TestSnapshotListNoSnapshots confirms a volume with no snapshots lists none.
func TestSnapshotListNoSnapshots(t *testing.T) {
	dmg := filepath.Join(t.TempDir(), "plain.dmg")
	mustRun(t, "create", dmg, "--fs", "apfs", "--volname", "PlainVol")

	out := mustRun(t, "snapshot", "list", dmg)
	if strings.Contains(out, "xid") {
		t.Errorf("expected no snapshots, got:\n%s", out)
	}
}

// TestSnapshotListRejectsNonAPFS confirms snapshots are APFS-only.
func TestSnapshotListRejectsNonAPFS(t *testing.T) {
	dmg := filepath.Join(t.TempDir(), "hfs.dmg")
	mustRun(t, "create", dmg, "--fs", "hfs+", "--volname", "HfsVol", "--size", "8")

	_, stderr, code := run(t, "snapshot", "list", dmg)
	if code != 5 {
		t.Errorf("snapshot list on HFS+ exited %d, want 5 (unsupported)\nstderr: %s", code, stderr)
	}
}

// TestSnapshotCreateOnExistingImage rebuilds an existing APFS image with a
// snapshot and confirms the snapshot and the content survive.
func TestSnapshotCreateOnExistingImage(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("alpha\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "b.txt"), []byte("beta\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	base := filepath.Join(dir, "evidence.dmg")
	mustRun(t, "pack", src, base, "--fs", "apfs", "--volname", "Evidence")

	out := filepath.Join(dir, "evidence-snap.dmg")
	mustRun(t, "snapshot", "create", base, "--name", "baseline", "-O", out)

	if listing := mustRun(t, "snapshot", "list", out); !strings.Contains(listing, "baseline") {
		t.Errorf("snapshot not listed after create:\n%s", listing)
	}
	if got := mustRun(t, "cat", out, "/a.txt"); got != "alpha\n" {
		t.Errorf("content not preserved: a.txt = %q", got)
	}
	if got := mustRun(t, "cat", out, "/sub/b.txt"); got != "beta\n" {
		t.Errorf("content not preserved: sub/b.txt = %q", got)
	}
}

// TestSnapshotCreateRefusesOverwrite confirms the forensic-safe default: no
// --output and no --force is a usage error.
func TestSnapshotCreateRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	dmg := filepath.Join(dir, "img.dmg")
	mustRun(t, "create", dmg, "--fs", "apfs", "--volname", "V", "--snapshot", "s0")

	_, _, code := run(t, "snapshot", "create", dmg, "--name", "s1")
	if code != 2 {
		t.Errorf("snapshot create without --output/--force exited %d, want 2 (usage)", code)
	}
}

// TestSnapshotRevert marks an image to revert and confirms the result is still a
// valid, listable APFS image.
func TestSnapshotRevert(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "img.dmg")
	mustRun(t, "create", base, "--fs", "apfs", "--volname", "V", "--snapshot", "baseline")

	out := filepath.Join(dir, "reverted.dmg")
	mustRun(t, "snapshot", "revert", base, "--name", "baseline", "-O", out)

	if listing := mustRun(t, "snapshot", "list", out); !strings.Contains(listing, "baseline") {
		t.Errorf("reverted image no longer lists the snapshot:\n%s", listing)
	}

	// Reverting to a nonexistent snapshot is an error.
	if _, _, code := run(t, "snapshot", "revert", base, "--name", "nope", "-O", filepath.Join(dir, "x.dmg")); code == 0 {
		t.Errorf("revert to a nonexistent snapshot should fail")
	}
}

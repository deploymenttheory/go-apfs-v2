// CLI acceptance tests for `apfs snapshot`, exercised through the built binary.
package cli_test

import (
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

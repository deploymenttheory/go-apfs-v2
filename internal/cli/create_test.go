// CLI acceptance tests for `apfs create`, exercised through the built binary.
// Both HFS+ and APFS creation are part of the default build; the APFS writer
// itself is covered in depth by pkg/apfswrite.
package cli_test

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestCreateHFSEmpty creates an empty HFS+ volume and reads it back.
func TestCreateHFSEmpty(t *testing.T) {
	dmg := filepath.Join(t.TempDir(), "blank.dmg")
	mustRun(t, "create", dmg, "--fs", "hfs+", "--volname", "BlankHFS", "--size", "8")

	out := mustRun(t, "info", "-o", "json", dmg)
	if !strings.Contains(out, `"fileSystem":"hfs+"`) {
		t.Errorf("created volume is not hfs+:\n%s", out)
	}
	if !strings.Contains(out, `"name":"BlankHFS"`) {
		t.Errorf("created volume name wrong:\n%s", out)
	}

	// The empty volume should list nothing.
	if listing := mustRun(t, "list", dmg); nonEmptyLines(listing) != nil {
		t.Errorf("empty volume listing not empty: %q", listing)
	}
}

// TestCreateAPFSEmpty creates an empty APFS volume and reads it back.
func TestCreateAPFSEmpty(t *testing.T) {
	dmg := filepath.Join(t.TempDir(), "blank.dmg")
	mustRun(t, "create", dmg, "--fs", "apfs", "--volname", "BlankAPFS")

	out := mustRun(t, "info", "-o", "json", dmg)
	if !strings.Contains(out, `"fileSystem":"apfs"`) {
		t.Errorf("created volume is not apfs:\n%s", out)
	}
	if !strings.Contains(out, `"name":"BlankAPFS"`) {
		t.Errorf("created volume name wrong:\n%s", out)
	}

	// The empty volume should list nothing.
	if listing := mustRun(t, "list", dmg); nonEmptyLines(listing) != nil {
		t.Errorf("empty volume listing not empty: %q", listing)
	}
}

func TestCreateBadFilesystem(t *testing.T) {
	_, _, code := run(t, "create", filepath.Join(t.TempDir(), "x.dmg"), "--fs", "zfs")
	if code != 2 {
		t.Errorf("create --fs zfs exited %d, want 2 (usage)", code)
	}
}

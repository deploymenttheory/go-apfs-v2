// CLI acceptance tests for `apfs create`, exercised through the built binary.
// The test binary is built without -tags apfswrite (the default MIT build), so
// APFS creation is expected to be refused here; the APFS writer itself is
// covered by pkg/apfswrite.
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
	if !strings.Contains(out, `"filesystem":"hfs+"`) {
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

// TestCreateAPFSRefusedInDefaultBuild confirms APFS creation is gated behind
// the GPL build tag: the default (MIT) binary refuses it with exit 5.
func TestCreateAPFSRefusedInDefaultBuild(t *testing.T) {
	dmg := filepath.Join(t.TempDir(), "x.dmg")
	_, stderr, code := run(t, "create", dmg, "--fs", "apfs")
	if code != 5 {
		t.Errorf("apfs create in default build exited %d, want 5 (unsupported)\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "apfswrite") {
		t.Errorf("refusal did not mention the -tags apfswrite build:\n%s", stderr)
	}
}

func TestCreateBadFilesystem(t *testing.T) {
	_, _, code := run(t, "create", filepath.Join(t.TempDir(), "x.dmg"), "--fs", "zfs")
	if code != 2 {
		t.Errorf("create --fs zfs exited %d, want 2 (usage)", code)
	}
}

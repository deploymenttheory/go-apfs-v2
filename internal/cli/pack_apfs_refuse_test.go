// CLI acceptance test confirming that packing to APFS is gated behind the GPL
// build tag. The test binary is built without -tags apfswrite (the default MIT
// build), so `pack <dir> --fs apfs` must be refused with exit 5. The GPL build's
// pack path is covered by the pkg/apfswrite tests.
package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPackAPFSRefusedInDefaultBuild confirms the default (MIT) binary refuses
// `pack <dir> --fs apfs` with exit 5, mirroring create's refusal.
func TestPackAPFSRefusedInDefaultBuild(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "out.dmg")

	_, stderr, code := run(t, "pack", srcDir, dst, "--fs", "apfs")
	if code != 5 {
		t.Errorf("pack --fs apfs in default build exited %d, want 5 (unsupported)\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "apfswrite") {
		t.Errorf("refusal did not mention the -tags apfswrite build:\n%s", stderr)
	}
}

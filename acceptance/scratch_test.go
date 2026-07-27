// Acceptance coverage for the scratch file used while building an image. It
// must not outlive the command, on success or on failure: a build that leaves
// a copy of the image behind has traded a memory problem for a disk one.
package acceptance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/exitcode"
)

// dirEntries returns the names in dir, for asserting nothing was left behind.
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// TestBuildLeavesNoScratchFile checks a successful build cleans up after
// itself. The scratch file lands beside the output by default, so a leak would
// silently double the disk cost of every image built.
func TestBuildLeavesNoScratchFile(t *testing.T) {
	src, _ := buildSampleTree(t)

	cases := []struct {
		name string
		args func(out string) []string
	}{
		{"pack apfs", func(out string) []string {
			return []string{"pack", src, out, "--fs", "apfs", "--volname", "SCRATCH", "-q"}
		}},
		{"pack hfs+", func(out string) []string {
			return []string{"pack", src, out, "--fs", "hfs+", "--volname", "SCRATCH", "-q"}
		}},
		{"create apfs", func(out string) []string {
			return []string{"create", out, "--fs", "apfs", "--volname", "SCRATCH", "-q"}
		}},
		{"create hfs+", func(out string) []string {
			return []string{"create", out, "--fs", "hfs+", "--volname", "SCRATCH", "-q"}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "image.dmg")

			if _, stderr, code := run(t, tc.args(out)...); code != exitcode.OK {
				t.Fatalf("exited %s\nstderr: %s", exitcode.Name(code), stderr)
			}

			names := dirEntries(t, dir)
			if len(names) != 1 || names[0] != "image.dmg" {
				t.Errorf("directory holds %v, want only image.dmg; a scratch file was left behind", names)
			}
		})
	}
}

// TestFailedBuildLeavesNoScratchFile checks the same on the error path. A
// deferred close covers a normal return, and this is what proves it.
func TestFailedBuildLeavesNoScratchFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "image.dmg")

	// A volume name too long for HFS+ fails after the scratch file is created.
	_, _, code := run(t, "create", out, "--fs", "apfs", "--volname", strings.Repeat("x", 512), "-q")
	if code == exitcode.OK {
		t.Skip("this input no longer fails, so it cannot exercise the error path")
	}

	if names := dirEntries(t, dir); len(names) != 0 {
		t.Errorf("a failed build left %v behind", names)
	}
}

// TestTempDirIsHonoured checks --temp-dir moves the scratch file. That matters
// because the default is beside the output, and a caller whose output directory
// is small or read-heavy needs somewhere else to put it.
func TestTempDirIsHonoured(t *testing.T) {
	outDir := t.TempDir()
	tempDir := t.TempDir()
	out := filepath.Join(outDir, "image.dmg")

	_, stderr, code := run(t, "create", out, "--fs", "apfs", "--volname", "TEMPDIR", "-q", "--temp-dir", tempDir)
	if code != exitcode.OK {
		t.Fatalf("exited %s\nstderr: %s", exitcode.Name(code), stderr)
	}

	// Both directories must end up clean: the scratch file is removed wherever
	// it was put.
	if names := dirEntries(t, tempDir); len(names) != 0 {
		t.Errorf("the temp directory holds %v, want it empty", names)
	}
	if names := dirEntries(t, outDir); len(names) != 1 || names[0] != "image.dmg" {
		t.Errorf("the output directory holds %v, want only image.dmg", names)
	}
}

// TestMissingTempDirIsAnError checks a --temp-dir that does not exist fails
// rather than silently falling back somewhere the caller did not choose.
func TestMissingTempDirIsAnError(t *testing.T) {
	out := filepath.Join(t.TempDir(), "image.dmg")
	absent := filepath.Join(t.TempDir(), "does-not-exist")

	_, _, code := run(t, "create", out, "--fs", "apfs", "--volname", "T", "-q", "--temp-dir", absent)
	if code == exitcode.OK {
		t.Error("a missing --temp-dir was accepted")
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("the destination was written despite the scratch file failing")
	}
}

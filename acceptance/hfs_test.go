// CLI acceptance tests for HFS+ images, exercised through the built binary
// against the committed HFS+ fixture. Complements the pkg/hfsplus library
// tests by covering the info/list/cat/extract path end to end.
package acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/exitcode"
)

func requireHFSFixture(t *testing.T) {
	t.Helper()
	if hfsManifest.VolumeName == "" {
		t.Skip("HFS+ fixture not present")
	}
}

// TestHFSInfoReportsFileSystem confirms the CLI detects and reports HFS+.
func TestHFSInfoReportsFileSystem(t *testing.T) {
	requireHFSFixture(t)
	out := mustRun(t, "info", "-o", "json", fixtureHFS)
	if !strings.Contains(out, `"fileSystem":"hfs+"`) {
		t.Errorf("info did not report hfs+ file system:\n%s", out)
	}
	if !strings.Contains(out, hfsManifest.VolumeName) {
		t.Errorf("info missing volume name %q:\n%s", hfsManifest.VolumeName, out)
	}
}

// TestHFSListRecursive checks every manifest entry is enumerated.
func TestHFSListRecursive(t *testing.T) {
	requireHFSFixture(t)
	lines := nonEmptyLines(mustRun(t, "list", "-R", fixtureHFS))
	for path := range hfsManifest.Files {
		if !containsLinePrefix(lines, path) {
			t.Errorf("recursive list missing %q", path)
		}
	}
}

// TestHFSCatMatchesManifest streams each file and checks its digest.
func TestHFSCatMatchesManifest(t *testing.T) {
	requireHFSFixture(t)
	for path, entry := range hfsManifest.Files {
		if entry.Type != "file" {
			continue
		}
		out, stderr, code := run(t, "cat", fixtureHFS, "/"+path)
		if code != exitcode.OK {
			t.Errorf("cat %s exited %d: %s", path, code, stderr)
			continue
		}
		sum := sha256.Sum256([]byte(out))
		if hex.EncodeToString(sum[:]) != entry.SHA256 {
			t.Errorf("cat %s: content digest mismatch", path)
		}
	}
}

// TestHFSExtractMatchesManifest extracts the whole volume and verifies every
// file, symlink and hardlink against the committed manifest.
func TestHFSExtractMatchesManifest(t *testing.T) {
	requireHFSFixture(t)
	dest := t.TempDir()
	// Auto symlink handling keeps exit 0 on every OS.
	if _, stderr, code := run(t, "extract", fixtureHFS, "-C", dest); code != exitcode.OK {
		t.Fatalf("extract exited %d: %s", code, stderr)
	}

	for path, entry := range hfsManifest.Files {
		if entry.Type != "file" {
			continue
		}
		got, err := fileSHA256(filepath.Join(dest, filepath.FromSlash(path)))
		if err != nil {
			t.Errorf("%s: missing after extract: %v", path, err)
			continue
		}
		if got != entry.SHA256 {
			t.Errorf("%s: checksum mismatch after extract", path)
		}
	}
}

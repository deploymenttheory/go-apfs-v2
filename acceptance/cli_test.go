// Acceptance tests for the apfs command against the committed fixtures in
// testdata/cli. These run on Linux, macOS and Windows in CI.
package acceptance

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/exitcode"
)

// --- info ---

func TestInfoText(t *testing.T) {
	out := mustRun(t, "info", fixtureDMG)
	for _, want := range []string{"Apple File System", manifest.VolumeName, "Volumes            1"} {
		if !strings.Contains(out, want) {
			t.Errorf("info output missing %q:\n%s", want, out)
		}
	}
}

func TestInfoJSON(t *testing.T) {
	out := mustRun(t, "info", "-o", "json", fixtureDMG)

	var info struct {
		UUID        string `json:"uuid"`
		BlockSize   int    `json:"blockSize"`
		VolumeCount int    `json:"volumeCount"`
		Volumes     []struct {
			Name     string `json:"name"`
			Files    int    `json:"files"`
			Symlinks int    `json:"symlinks"`
		} `json:"volumes"`
	}
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatalf("info -o json is not valid JSON: %v\n%s", err, out)
	}

	if info.VolumeCount != 1 || len(info.Volumes) != 1 {
		t.Fatalf("expected 1 volume, got %d", info.VolumeCount)
	}
	if info.Volumes[0].Name != manifest.VolumeName {
		t.Errorf("volume name = %q, want %q", info.Volumes[0].Name, manifest.VolumeName)
	}
	if info.BlockSize != 4096 {
		t.Errorf("block size = %d, want 4096", info.BlockSize)
	}
	if info.Volumes[0].Symlinks != 1 {
		t.Errorf("symlinks = %d, want 1", info.Volumes[0].Symlinks)
	}
}

// TestInfoAllImageFormats proves the same container opens from every fixture
// format: zlib DMG, bzip2 DMG, lzfse DMG and raw GPT image.
func TestInfoAllImageFormats(t *testing.T) {
	for name, image := range map[string]string{
		"udzo":   fixtureDMG,
		"udbz":   fixtureBZ2,
		"ulfo":   fixtureLZFSE,
		"rawgpt": fixtureRaw,
	} {
		t.Run(name, func(t *testing.T) {
			out := mustRun(t, "info", image)
			if !strings.Contains(out, manifest.VolumeName) {
				t.Errorf("info on %s missing volume name:\n%s", name, out)
			}
		})
	}
}

// --- list ---

func TestListRootSorted(t *testing.T) {
	out := mustRun(t, "list", fixtureDMG)
	lines := nonEmptyLines(out)
	if !sort.StringsAreSorted(lines) {
		t.Errorf("list output is not sorted:\n%s", out)
	}
	for _, want := range []string{"hello.txt", "dir1", "random.bin"} {
		if !containsLinePrefix(lines, want) {
			t.Errorf("list output missing %q:\n%s", want, out)
		}
	}
}

func TestListRecursiveComplete(t *testing.T) {
	out := mustRun(t, "list", "-R", fixtureDMG)
	lines := nonEmptyLines(out)

	// Every manifest entry must be listed
	for path := range manifest.Files {
		if !containsLinePrefix(lines, path) {
			t.Errorf("recursive list missing %q", path)
		}
	}
}

func TestListJSONLines(t *testing.T) {
	out := mustRun(t, "list", "-o", "json", "-R", fixtureDMG)

	found := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		var entry struct {
			Path   string `json:"path"`
			Type   string `json:"type"`
			Size   int64  `json:"size"`
			Target string `json:"target"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("list -o json produced invalid JSON line: %v\n%s", err, scanner.Text())
		}
		found[entry.Path] = true

		if expected, ok := manifest.Files[entry.Path]; ok {
			if expected.Type != entry.Type {
				t.Errorf("%s: type = %q, want %q", entry.Path, entry.Type, expected.Type)
			}
			if expected.Type == "file" && entry.Size != expected.Size {
				t.Errorf("%s: size = %d, want %d", entry.Path, entry.Size, expected.Size)
			}
			if expected.Type == "symlink" && entry.Target != expected.Target {
				t.Errorf("%s: target = %q, want %q", entry.Path, entry.Target, expected.Target)
			}
		}
	}

	for path := range manifest.Files {
		if !found[path] {
			t.Errorf("list -o json missing %q", path)
		}
	}
}

func TestListEnvOutputJSON(t *testing.T) {
	cmd := exec.Command(binPath, "list", fixtureDMG)
	cmd.Env = append(os.Environ(), "APFS_OUTPUT=json")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("list with APFS_OUTPUT=json failed: %v", err)
	}
	firstLine := strings.SplitN(string(out), "\n", 2)[0]
	var entry map[string]any
	if err := json.Unmarshal([]byte(firstLine), &entry); err != nil {
		t.Fatalf("APFS_OUTPUT=json not honored, got: %s", firstLine)
	}
}

// --- cat ---

func TestCatContentsMatchManifest(t *testing.T) {
	for _, path := range manifestFilePaths() {
		expected := manifest.Files[path]
		out, stderr, code := run(t, "cat", fixtureDMG, "/"+path)
		if code != exitcode.OK {
			t.Errorf("cat %s exited %d: %s", path, code, stderr)
			continue
		}
		sum := sha256.Sum256([]byte(out))
		if hex.EncodeToString(sum[:]) != expected.SHA256 {
			t.Errorf("cat %s: content hash mismatch (got %d bytes)", path, len(out))
		}
	}
}

func TestCatDirectoryIsUsageError(t *testing.T) {
	_, _, code := run(t, "cat", fixtureDMG, "/dir1")
	if code != exitcode.Usage {
		t.Errorf("cat on a directory exited %d, want 2", code)
	}
}

// --- extract ---

func TestExtractFullVolume(t *testing.T) {
	dest := t.TempDir()
	_, stderr, code := run(t, "extract", fixtureDMG, "-C", dest)

	// Default (auto) symlink handling degrades unsupported symlinks to files,
	// so extraction completes cleanly on every OS including Windows.
	if code != exitcode.OK {
		t.Fatalf("extract exited %d\nstderr: %s", code, stderr)
	}

	for path, expected := range manifest.Files {
		destPath := filepath.Join(dest, filepath.FromSlash(path))
		switch expected.Type {
		case "file":
			sum, err := fileSHA256(destPath)
			if err != nil {
				t.Errorf("%s: %v", path, err)
				continue
			}
			if sum != expected.SHA256 {
				t.Errorf("%s: checksum mismatch", path)
			}
		case "symlink":
			// Depending on OS symlink privilege the entry is either a real
			// symlink (target == link target) or, when the OS refused, a
			// regular file whose content is the target path. Both are correct.
			lstat, err := os.Lstat(destPath)
			if err != nil {
				t.Errorf("%s: %v", path, err)
				continue
			}
			if lstat.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(destPath)
				if err != nil {
					t.Errorf("%s: %v", path, err)
					continue
				}
				if target != expected.Target {
					t.Errorf("%s: symlink target = %q, want %q", path, target, expected.Target)
				}
			} else {
				content, err := os.ReadFile(destPath)
				if err != nil {
					t.Errorf("%s: %v", path, err)
					continue
				}
				if string(content) != expected.Target {
					t.Errorf("%s: degraded-symlink content = %q, want %q", path, content, expected.Target)
				}
			}
		}
	}
}

func TestExtractSubtreeAndPattern(t *testing.T) {
	dest := t.TempDir()
	mustRun(t, "extract", fixtureDMG, "/dir1", "-r", "-C", dest)
	if _, err := os.Stat(filepath.Join(dest, "dir1", "nested", "deep.txt")); err != nil {
		t.Errorf("subtree extract missing deep.txt: %v", err)
	}

	dest2 := t.TempDir()
	mustRun(t, "extract", fixtureDMG, "-C", dest2, "--pattern", `\.txt$`)
	if _, err := os.Stat(filepath.Join(dest2, "hello.txt")); err != nil {
		t.Errorf("pattern extract missing hello.txt: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest2, "random.bin")); err == nil {
		t.Errorf("pattern extract should not have extracted random.bin")
	}
}

func TestExtractDirWithoutRecursiveFails(t *testing.T) {
	_, _, code := run(t, "extract", fixtureDMG, "/dir1", "-C", t.TempDir())
	if code == 0 {
		t.Errorf("extract of a directory without -r should fail")
	}
}

// TestExtractSymlinkAsFile proves the lossless symlink fallback on every OS:
// --symlinks file writes the link target into a regular file (the same path
// auto mode takes on an OS that refuses symlinks). Exit 0, content == target.
func TestExtractSymlinkAsFile(t *testing.T) {
	expected, ok := manifest.Files["link-to-hello"]
	if !ok || expected.Type != "symlink" {
		t.Skip("fixture has no link-to-hello symlink")
	}

	dest := t.TempDir()
	_, stderr, code := run(t, "extract", fixtureDMG, "-C", dest, "--symlinks", "file")
	if code != exitcode.OK {
		t.Fatalf("extract --symlinks file exited %d: %s", code, stderr)
	}

	linkPath := filepath.Join(dest, "link-to-hello")
	info, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("degraded symlink missing: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Errorf("expected a regular file, got a symlink")
	}
	content, err := os.ReadFile(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != expected.Target {
		t.Errorf("degraded-symlink content = %q, want %q", content, expected.Target)
	}
}

// TestExtractSymlinkRealMode ensures --symlinks real produces an actual
// symlink (skipped on Windows where the privilege is typically absent).
func TestExtractSymlinkRealMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("real symlink creation needs privilege not present on Windows runners")
	}
	expected, ok := manifest.Files["link-to-hello"]
	if !ok || expected.Type != "symlink" {
		t.Skip("fixture has no link-to-hello symlink")
	}

	dest := t.TempDir()
	mustRun(t, "extract", fixtureDMG, "-C", dest, "--symlinks", "real")
	target, err := os.Readlink(filepath.Join(dest, "link-to-hello"))
	if err != nil {
		t.Fatalf("expected a real symlink: %v", err)
	}
	if target != expected.Target {
		t.Errorf("target = %q, want %q", target, expected.Target)
	}
}

func TestExtractJSONSummary(t *testing.T) {
	out := mustRun(t, "extract", "-o", "json", "-q", fixtureDMG, "/hello.txt", "-C", t.TempDir())
	var summary struct {
		Files int `json:"files"`
	}
	if err := json.Unmarshal([]byte(out), &summary); err != nil {
		t.Fatalf("extract -o json invalid: %v\n%s", err, out)
	}
	if summary.Files != 1 {
		t.Errorf("files = %d, want 1", summary.Files)
	}
}

func TestExtractVerify(t *testing.T) {
	out, stderr, code := run(t, "extract", fixtureDMG, "/random.bin", "-C", t.TempDir(), "--verify")
	if code != exitcode.OK {
		t.Fatalf("extract --verify exited %d: %s", code, stderr)
	}
	if !strings.Contains(out, "All files verified successfully") {
		t.Errorf("verify output missing success marker:\n%s", out)
	}
}

// --- inspect ---

func TestInspectWalk(t *testing.T) {
	out := mustRun(t, "inspect", fixtureDMG)
	for _, want := range []string{"Container Superblock", manifest.VolumeName, "Checkpoint"} {
		if !strings.Contains(out, want) {
			t.Errorf("inspect output missing %q", want)
		}
	}
}

func TestInspectBlockZero(t *testing.T) {
	out := mustRun(t, "inspect", fixtureDMG, "block", "0")
	for _, want := range []string{"NX_SUPERBLOCK", "Checksum valid", "Object identifier"} {
		if !strings.Contains(out, want) {
			t.Errorf("inspect block 0 output missing %q:\n%s", want, out)
		}
	}
}

// TestInspectFSTree covers the mode formerly spelled "inspect IMAGE btree".
// The explorer is interactive: entry 0 is selected repeatedly until it
// reaches a leaf record and returns.
func TestInspectFSTree(t *testing.T) {
	out, stderr, code := runWithStdin(t, strings.Repeat("0\n", 8), "inspect", fixtureDMG, "fstree")
	if code != exitcode.OK {
		t.Fatalf("inspect fstree exited %d\nstderr: %s", code, stderr)
	}
	for _, want := range []string{"file-system tree", "object map", "Object identifier"} {
		if !strings.Contains(out, want) {
			t.Errorf("inspect fstree output missing %q:\n%s", want, out)
		}
	}
}

// TestInspectRejectsOldBtreeMode pins the rename: the old spelling must fail
// with a usage error rather than silently doing nothing.
func TestInspectRejectsOldBtreeMode(t *testing.T) {
	_, stderr, code := run(t, "inspect", fixtureDMG, "btree")
	if code != exitcode.Usage {
		t.Errorf("inspect btree exit code = %d, want 2 (usage)", code)
	}
	if !strings.Contains(stderr, "fstree") {
		t.Errorf("inspect btree error should point at fstree, got: %s", stderr)
	}
}

// --- exit codes ---

func TestExitCodes(t *testing.T) {
	notAPFS := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(notAPFS, []byte("not an apfs image, just text padding padding padding"), 0644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"missing image", []string{"info", filepath.Join(t.TempDir(), "nope.dmg")}, exitcode.BadImage},
		{"not apfs", []string{"info", notAPFS}, exitcode.BadImage},
		{"unknown flag", []string{"info", "--definitely-not-a-flag", fixtureDMG}, exitcode.Usage},
		{"bad output format", []string{"info", "-o", "yaml", fixtureDMG}, exitcode.Usage},
		{"unknown volume", []string{"list", "--volume", "NoSuchVolume", fixtureDMG}, exitcode.Usage},
		{"missing args", []string{"cat", fixtureDMG}, exitcode.Usage},
		{"success", []string{"info", fixtureDMG}, exitcode.OK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, code := run(t, tc.args...)
			if code != tc.want {
				t.Errorf("%v exited %d (%s), want %d (%s)\nstderr: %s",
					tc.args, code, exitcode.Name(code), tc.want, exitcode.Name(tc.want), stderr)
			}
		})
	}
}

// --- volume selection ---

func TestVolumeSelectorByName(t *testing.T) {
	out := mustRun(t, "list", "--volume", manifest.VolumeName, fixtureDMG)
	if !strings.Contains(out, "hello.txt") {
		t.Errorf("list --volume %q failed:\n%s", manifest.VolumeName, out)
	}
}

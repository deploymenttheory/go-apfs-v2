// Acceptance tests: run the CLI against a downloaded vendor DMG (by default
// Firefox 150's release DMG). Gated on APFS_ACCEPTANCE_DMG so ordinary test
// runs skip them; CI downloads the image and runs these on Linux, macOS and
// Windows. On macOS the extraction is additionally verified file-by-file
// against an hdiutil mount of the same image — the platform ground truth.
// Observed values are reported to the pipeline via GITHUB_STEP_SUMMARY.
package cli_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Expected facts about the acceptance image (Firefox 150), overridable via
// environment to swap artifacts.
var (
	acceptanceVolumeName = envOr("APFS_ACCEPTANCE_VOLNAME", "Firefox")
	acceptanceAppBundle  = envOr("APFS_ACCEPTANCE_APP", "Firefox.app")
	acceptanceBundleID   = envOr("APFS_ACCEPTANCE_BUNDLE_ID", "org.mozilla.firefox")
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// stepSummary appends a markdown line to the GitHub Actions step summary so
// observed acceptance values are visible in the pipeline UI. A no-op outside
// GitHub Actions.
func stepSummary(format string, args ...any) {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, format+"\n", args...)
}

// acceptanceDMG skips the test unless the acceptance image is configured.
func acceptanceDMG(t *testing.T) string {
	t.Helper()
	path := os.Getenv("APFS_ACCEPTANCE_DMG")
	if path == "" {
		t.Skip("APFS_ACCEPTANCE_DMG not set; skipping acceptance-image test")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("APFS_ACCEPTANCE_DMG: %v", err)
	}
	return path
}

type acceptanceInfo struct {
	VolumeCount int `json:"volumeCount"`
	Volumes     []struct {
		Name        string `json:"name"`
		Files       uint64 `json:"files"`
		Directories uint64 `json:"directories"`
		Symlinks    uint64 `json:"symlinks"`
	} `json:"volumes"`
}

func acceptanceInfoJSON(t *testing.T, dmg string) acceptanceInfo {
	t.Helper()
	out := mustRun(t, "info", "-o", "json", dmg)
	var info acceptanceInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatalf("info -o json invalid: %v\n%s", err, out)
	}
	if info.VolumeCount < 1 || len(info.Volumes) < 1 {
		t.Fatalf("no volumes reported: %s", out)
	}
	return info
}

func TestAcceptanceInfo(t *testing.T) {
	dmg := acceptanceDMG(t)
	info := acceptanceInfoJSON(t, dmg)

	if info.Volumes[0].Name != acceptanceVolumeName {
		t.Errorf("volume name = %q, want %q", info.Volumes[0].Name, acceptanceVolumeName)
	}
	if info.Volumes[0].Files == 0 {
		t.Error("volume reports zero files")
	}

	stepSummary("### Acceptance image results (%s/%s)", runtime.GOOS, runtime.GOARCH)
	stepSummary("- **Image**: %s", filepath.Base(dmg))
	stepSummary("- **Volume**: %s — %d files, %d directories, %d symlinks (superblock accounting)",
		info.Volumes[0].Name, info.Volumes[0].Files, info.Volumes[0].Directories, info.Volumes[0].Symlinks)
}

// TestAcceptanceListMatchesSuperblockCounts cross-checks the recursive listing
// against the volume superblock's own accounting: every file, directory and
// symlink the superblock claims must be enumerated by the walk. Hardlinks
// share an inode, so listed file entries may exceed the superblock count.
func TestAcceptanceListMatchesSuperblockCounts(t *testing.T) {
	dmg := acceptanceDMG(t)
	info := acceptanceInfoJSON(t, dmg)

	out := mustRun(t, "list", "-o", "json", "-R", dmg)

	var files, dirs, symlinks uint64
	sawAppBundle := false
	sawInfoPlist := false

	scanner := bufio.NewScanner(strings.NewReader(out))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		var entry struct {
			Path string `json:"path"`
			Type string `json:"type"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("invalid JSON line: %v: %s", err, scanner.Text())
		}
		switch entry.Type {
		case "file":
			files++
		case "dir":
			dirs++
		case "symlink":
			symlinks++
		}
		if entry.Path == acceptanceAppBundle {
			sawAppBundle = true
		}
		if entry.Path == acceptanceAppBundle+"/Contents/Info.plist" {
			sawInfoPlist = true
		}
	}

	if files < info.Volumes[0].Files {
		t.Errorf("listed %d files, superblock claims %d", files, info.Volumes[0].Files)
	}
	if dirs != info.Volumes[0].Directories {
		t.Errorf("listed %d directories, superblock claims %d", dirs, info.Volumes[0].Directories)
	}
	if symlinks != info.Volumes[0].Symlinks {
		t.Errorf("listed %d symlinks, superblock claims %d", symlinks, info.Volumes[0].Symlinks)
	}
	if !sawAppBundle {
		t.Errorf("recursive list missing %s", acceptanceAppBundle)
	}
	if !sawInfoPlist {
		t.Errorf("recursive list missing %s/Contents/Info.plist", acceptanceAppBundle)
	}

	stepSummary("- **Recursive list**: %d files, %d directories, %d symlinks enumerated", files, dirs, symlinks)
}

func TestAcceptanceCatInfoPlist(t *testing.T) {
	dmg := acceptanceDMG(t)
	out := mustRun(t, "cat", dmg, "/"+acceptanceAppBundle+"/Contents/Info.plist")
	if !strings.Contains(out, acceptanceBundleID) {
		t.Errorf("Info.plist does not contain bundle id %q", acceptanceBundleID)
	}
}

// TestAcceptanceCatMainBinaryIsMachO reads the app's main executable and checks it
// is a Mach-O image — proof that large multi-extent binary content survives
// the DMG chunk and APFS extent layers intact at the front.
func TestAcceptanceCatMainBinaryIsMachO(t *testing.T) {
	dmg := acceptanceDMG(t)

	// The main binary name comes from CFBundleExecutable, but for the
	// default artifact it matches the bundle name
	binary := strings.TrimSuffix(acceptanceAppBundle, ".app")
	out, stderr, code := run(t, "cat", dmg, "/"+acceptanceAppBundle+"/Contents/MacOS/"+binary)
	if code != 0 {
		t.Fatalf("cat main binary exited %d: %s", code, stderr)
	}
	if len(out) < 4 {
		t.Fatalf("main binary too short: %d bytes", len(out))
	}

	magic := []byte(out[:4])
	machO := bytes.Equal(magic, []byte{0xca, 0xfe, 0xba, 0xbe}) || // universal
		bytes.Equal(magic, []byte{0xcf, 0xfa, 0xed, 0xfe}) || // 64-bit LE
		bytes.Equal(magic, []byte{0xfe, 0xed, 0xfa, 0xcf}) // 64-bit BE
	if !machO {
		t.Errorf("main binary magic = %x, not Mach-O", magic)
	}
}

// TestAcceptanceExtractVerified extracts the whole volume with --verify (source
// checksums recomputed against the written files) and asserts completeness.
func TestAcceptanceExtractVerified(t *testing.T) {
	dmg := acceptanceDMG(t)
	info := acceptanceInfoJSON(t, dmg)
	dest := t.TempDir()

	out, stderr, code := run(t, "extract", dmg, "-C", dest, "--verify")
	if code != 0 {
		if runtime.GOOS == "windows" && code == 6 {
			t.Logf("windows: accepting partial extraction (symlink privileges): %s", stderr)
		} else {
			t.Fatalf("extract exited %d\nstderr: %s\n%s", code, stderr, out)
		}
	} else if !strings.Contains(out, "All files verified successfully") {
		t.Errorf("verify success marker missing:\n%s", lastLines(out, 10))
	}

	var extractedFiles uint64
	filepath.WalkDir(dest, func(path string, entry fs.DirEntry, err error) error {
		if err == nil && entry.Type().IsRegular() {
			extractedFiles++
		}
		return nil
	})

	if extractedFiles < info.Volumes[0].Files {
		t.Errorf("extracted %d files, superblock claims %d", extractedFiles, info.Volumes[0].Files)
	}

	verified := "passed"
	if code != 0 {
		verified = fmt.Sprintf("exit %d", code)
	}
	stepSummary("- **Extraction**: %d files written, checksum verification %s", extractedFiles, verified)
}

// TestAcceptanceGroundTruthAgainstHdiutil mounts the same DMG with macOS hdiutil
// and compares the sha256 of every regular file against our extraction.
// This is the platform ground truth and runs on the macOS CI runner.
func TestAcceptanceGroundTruthAgainstHdiutil(t *testing.T) {
	dmg := acceptanceDMG(t)
	if runtime.GOOS != "darwin" {
		t.Skip("hdiutil ground-truth comparison requires macOS")
	}

	dest := t.TempDir()
	mustRun(t, "extract", dmg, "-C", dest)

	mountPoint := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatal(err)
	}
	attach := exec.Command("hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", mountPoint, dmg)
	if out, err := attach.CombinedOutput(); err != nil {
		t.Fatalf("hdiutil attach failed: %v\n%s", err, out)
	}
	defer exec.Command("hdiutil", "detach", mountPoint).Run()

	var checked int
	err := filepath.WalkDir(mountPoint, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || !entry.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(mountPoint, path)
		if err != nil {
			return err
		}

		truthSum, err := sha256File(path)
		if err != nil {
			return nil // unreadable via mount (permissions); not our bug
		}
		ourSum, err := sha256File(filepath.Join(dest, rel))
		if err != nil {
			t.Errorf("%s: missing from extraction: %v", rel, err)
			return nil
		}
		if truthSum != ourSum {
			t.Errorf("%s: checksum mismatch vs hdiutil mount", rel)
		}
		checked++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("ground-truth walk compared zero files")
	}
	t.Logf("verified %d files against hdiutil ground truth", checked)
	stepSummary("- **hdiutil ground truth (macOS)**: %d files sha256-identical to the mounted image", checked)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// Test harness for the acceptance suite: locates the repository, builds the
// apfs binary under test, unpacks the committed fixtures in testdata/cli and
// provides the run helpers every acceptance test uses.
package acceptance

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/exitcode"
)

var (
	binPath      string
	repoRoot     string
	fixtureDMG   string
	fixtureBZ2   string
	fixtureLZFSE string
	fixtureRaw   string // decompressed from basic.img.gz into a temp dir
	fixtureHFS   string // committed HFS+ fixture DMG
	fixtureEnc   string // decompressed from encrypted.img.gz: a FileVault volume
	fixtureAPM   string // decompressed from hfs-apm.img.gz: a whole disk with an Apple Partition Map
	manifest     fixtureManifest
	hfsManifest  fixtureManifest
)

type fixtureManifest struct {
	VolumeName string                  `json:"volumeName"`
	Files      map[string]manifestFile `json:"files"`
}

type manifestFile struct {
	Type   string `json:"type"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   string `json:"mode"`
	Target string `json:"target"`

	// Compressed marks a file stored with transparent compression; the size
	// and hash above are of its decompressed content.
	Compressed bool `json:"compressed"`

	// Xattrs records the extended attributes macOS reported, by name. It is
	// not exhaustive -- macOS hides com.apple.decmpfs and the resource fork of
	// a compressed file from a normal listing -- so assert containment.
	Xattrs map[string]manifestXattr `json:"xattrs"`
}

type manifestXattr struct {
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

func TestMain(m *testing.M) {
	var err error
	repoRoot, err = findRepoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to find repo root: %v\n", err)
		os.Exit(1)
	}

	tempDir, err := os.MkdirTemp("", "apfs-acceptance")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer os.RemoveAll(tempDir)

	// Build the CLI binary under test
	binPath = filepath.Join(tempDir, "apfs")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	build := exec.Command("go", "build", "-o", binPath, "./cmd/apfs")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "unable to build CLI: %v\n%s", err, out)
		os.Exit(1)
	}

	fixtureDMG = filepath.Join(repoRoot, "testdata", "cli", "basic.dmg")
	fixtureBZ2 = filepath.Join(repoRoot, "testdata", "cli", "basic-bz2.dmg")
	fixtureLZFSE = filepath.Join(repoRoot, "testdata", "cli", "basic-lzfse.dmg")

	// Decompress the raw GPT image fixture
	fixtureRaw = filepath.Join(tempDir, "basic.img")
	if err := gunzipFile(filepath.Join(repoRoot, "testdata", "cli", "basic.img.gz"), fixtureRaw); err != nil {
		fmt.Fprintf(os.Stderr, "unable to decompress raw fixture: %v\n", err)
		os.Exit(1)
	}

	// Decompress the encrypted (FileVault) fixture. It is a real volume that
	// diskutil encrypted, so it is the only non-circular check that a supplied
	// password actually decrypts anything.
	fixtureEnc = filepath.Join(tempDir, "encrypted.img")
	if err := gunzipFile(filepath.Join(repoRoot, "testdata", "cli", "encrypted.img.gz"), fixtureEnc); err != nil {
		fmt.Fprintf(os.Stderr, "unable to decompress encrypted fixture: %v\n", err)
		os.Exit(1)
	}

	// Decompress the Apple Partition Map fixture: a whole-disk image with no
	// koly trailer, which is the only shape that reaches the APM locator.
	fixtureAPM = filepath.Join(tempDir, "hfs-apm.img")
	if err := gunzipFile(filepath.Join(repoRoot, "testdata", "cli", "hfs-apm.img.gz"), fixtureAPM); err != nil {
		fmt.Fprintf(os.Stderr, "unable to decompress the APM fixture: %v\n", err)
		os.Exit(1)
	}

	// Load the expected-contents manifest
	manifestData, err := os.ReadFile(filepath.Join(repoRoot, "testdata", "cli", "manifest.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to read manifest: %v\n", err)
		os.Exit(1)
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		fmt.Fprintf(os.Stderr, "unable to parse manifest: %v\n", err)
		os.Exit(1)
	}

	// The committed HFS+ fixture and its manifest (may be absent in older
	// checkouts; the HFS+ tests skip when it is). A manifest that is present
	// but unparseable is fatal rather than ignored: silently degrading to "no
	// HFS+ coverage" is how a whole tier of tests disappears unnoticed.
	fixtureHFS = filepath.Join(repoRoot, "testdata", "cli", "hfs-basic.dmg")
	if data, err := os.ReadFile(filepath.Join(repoRoot, "testdata", "cli", "hfs-manifest.json")); err == nil {
		if err := json.Unmarshal(data, &hfsManifest); err != nil {
			fmt.Fprintf(os.Stderr, "unable to parse HFS+ manifest: %v\n", err)
			os.Exit(1)
		}
	}

	os.Exit(m.Run())
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above %s", dir)
		}
		dir = parent
	}
}

func gunzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	gz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer gz.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, gz)
	return err
}

// cleanEnv returns the ambient environment with the variables the CLI reads
// blanked, so a value set in the developer's shell or by a CI reproducible-build
// wrapper cannot perturb a test. SOURCE_DATE_EPOCH matters as much as the APFS_
// variables here, because it changes the bytes every write command produces.
func cleanEnv(extra ...string) []string {
	env := append(os.Environ(),
		"APFS_OUTPUT=",
		"SOURCE_DATE_EPOCH=",
		"APFS_SOURCE_DATE_EPOCH=",
	)
	return append(env, extra...)
}

// run executes the CLI and returns stdout, stderr and the exit code.
func run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	return runEnv(t, nil, args...)
}

// runTimeout is run() with a deadline, for tests whose failure mode is the
// command never returning. Without it a regression that reintroduces a hang
// stalls the whole suite until the package timeout fires, and reports as a
// panic in whichever test happened to be running rather than as a failure here.
func runTimeout(t *testing.T, limit time.Duration, args ...string) (string, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Env = cleanEnv()
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("%v did not finish within %s; it is hanging\nstderr: %s", args, limit, stderr.String())
	}
	exitCode := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("unable to run %v: %v", args, err)
	}
	return stdout.String(), stderr.String(), exitCode
}

// runEnv is run() with extra environment entries appended, for the tests that
// exercise SOURCE_DATE_EPOCH and its precedence.
func runEnv(t *testing.T, env []string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = cleanEnv(env...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("unable to run %v: %v", args, err)
	}
	return stdout.String(), stderr.String(), exitCode
}

// mustRun executes the CLI and fails the test on a non-zero exit.
// runWithStdin is run() with input piped to the command's stdin, for the
// interactive `inspect IMAGE fstree` explorer.
func runWithStdin(t *testing.T, stdin string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = cleanEnv()
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("unable to run %v: %v", args, err)
	}
	return stdout.String(), stderr.String(), exitCode
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()
	stdout, stderr, code := run(t, args...)
	if code != exitcode.OK {
		t.Fatalf("%v exited %d\nstderr: %s", args, code, stderr)
	}
	return stdout
}

// manifestFilePaths returns the sorted paths of regular files in the manifest.
func manifestFilePaths() []string {
	var paths []string
	for p, f := range manifest.Files {
		if f.Type == "file" {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	return paths
}

// --- helpers ---

func nonEmptyLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// containsLinePrefix reports whether any line equals want or begins with
// want followed by a space (symlink lines are "name -> target").
func containsLinePrefix(lines []string, want string) bool {
	for _, line := range lines {
		if line == want || strings.HasPrefix(line, want+" ") {
			return true
		}
	}
	return false
}

func fileSHA256(path string) (string, error) {
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

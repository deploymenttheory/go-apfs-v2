// Acceptance coverage for write-side fidelity reporting: packing a directory
// is lossy, and the tool must say so rather than producing a quietly incomplete
// image. Also covers extract --xattrs, without which extract-then-pack
// discards every attribute however capable the writer is.
package acceptance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/exitcode"
	"github.com/deploymenttheory/go-apfs-v2/pkg/fidelity"
)

// packTimeout bounds a pack that should complete promptly. Reading a special
// file rather than skipping it used to hang forever, so the deadline is part of
// the assertion.
const packTimeout = 60 * time.Second

// lossyTree builds a directory holding, as far as the platform allows, one of
// everything a volume cannot carry. It reports which it managed to create.
type lossyTree struct {
	dir      string
	fifo     bool
	socket   bool
	hardlink bool
	xattr    bool
}

func buildLossyTree(t *testing.T) lossyTree {
	t.Helper()
	tree := lossyTree{dir: t.TempDir()}

	regular := filepath.Join(tree.dir, "regular.txt")
	if err := os.WriteFile(regular, []byte("ordinary content\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tree.dir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree.dir, "sub", "nested.txt"), []byte("nested\n"), 0644); err != nil {
		t.Fatal(err)
	}

	tree.fifo = makeFIFO(t, filepath.Join(tree.dir, "pipe"))
	tree.socket = makeSocket(t, filepath.Join(tree.dir, "sock"))
	tree.hardlink = os.Link(regular, filepath.Join(tree.dir, "linked.txt")) == nil
	tree.xattr = setXattr(t, regular, "user.marker", []byte("value"))

	return tree
}

// packJSON runs pack with JSON output and returns the decoded report fields.
func packJSON(t *testing.T, args ...string) (map[string]any, int) {
	t.Helper()
	stdout, stderr, code := run(t, append([]string{"pack"}, args...)...)
	var decoded map[string]any
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
		t.Fatalf("pack JSON invalid: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	return decoded, code
}

func intField(t *testing.T, m map[string]any, key string) int {
	t.Helper()
	value, ok := m[key]
	if !ok {
		t.Fatalf("key %q missing from the report; keys present: %v", key, sortedKeys(m))
	}
	number, ok := value.(float64)
	if !ok {
		t.Fatalf("key %q = %v, want a number", key, value)
	}
	return int(number)
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

// TestPackReportsFidelityLoss checks every loss is counted and exposed in JSON,
// under the stable schema pkg/fidelity defines.
func TestPackReportsFidelityLoss(t *testing.T) {
	tree := buildLossyTree(t)
	out := filepath.Join(t.TempDir(), "packed.dmg")

	report, code := packJSON(t, tree.dir, out, "--fs", "apfs", "--volname", "LOSSY", "-o", "json")

	// Every key is always present, so a consumer can rely on the shape.
	for _, key := range fidelity.Keys() {
		if _, ok := report[key]; !ok {
			t.Errorf("key %q missing from the pack report", key)
		}
	}

	if tree.fifo || tree.socket {
		want := 0
		if tree.fifo {
			want++
		}
		if tree.socket {
			want++
		}
		if got := intField(t, report, "specialFilesSkipped"); got != want {
			t.Errorf("specialFilesSkipped = %d, want %d", got, want)
		}
		// Entries omitted altogether make the result partial.
		if code != exitcode.Partial {
			t.Errorf("exited %s with skipped entries, want %s", exitcode.Name(code), exitcode.Name(exitcode.Partial))
		}
	}

	if tree.hardlink {
		if got := intField(t, report, "hardLinksCollapsed"); got != 1 {
			t.Errorf("hardLinksCollapsed = %d, want 1", got)
		}
	}
	if tree.xattr {
		if got := intField(t, report, "xattrsDropped"); got == 0 {
			t.Error("xattrsDropped = 0, want at least the attribute that was set")
		}
	}
	if lossless, _ := report["lossless"].(bool); lossless {
		t.Error("a lossy pack reported itself lossless")
	}
}

// TestPackCleanTreeExitsZero is the guard on the exit-code contract. macOS
// attaches com.apple.provenance to files as they are written, so an ordinary
// tree always has extended attributes. Treating a dropped attribute as failure
// would make almost every pack exit non-zero and break existing scripts.
func TestPackCleanTreeExitsZero(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("content\n"), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "clean.dmg")

	_, stderr, code := run(t, "pack", dir, out, "--fs", "apfs", "--volname", "CLEAN")
	if code != exitcode.OK {
		t.Errorf("packing a tree with no skipped entries exited %s, want %s\nstderr: %s",
			exitcode.Name(code), exitcode.Name(exitcode.OK), stderr)
	}
}

// TestPackStrictRefusesToWrite checks --strict fails before anything is
// written. A half-faithful image that exists is worse than no image, so the
// destination must not be left behind.
func TestPackStrictRefusesToWrite(t *testing.T) {
	tree := buildLossyTree(t)
	if !tree.fifo && !tree.socket && !tree.hardlink && !tree.xattr {
		t.Skip("this platform can create nothing the volume would drop")
	}

	for _, fs := range []string{"apfs", "hfs+"} {
		t.Run(fs, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "strict.dmg")

			_, stderr, code := runTimeout(t, packTimeout, "pack", tree.dir, out, "--fs", fs, "--volname", "STRICT", "--strict")
			if code != exitcode.Unsupported {
				t.Errorf("--strict exited %s, want %s\nstderr: %s",
					exitcode.Name(code), exitcode.Name(exitcode.Unsupported), stderr)
			}
			if _, err := os.Stat(out); err == nil {
				t.Error("--strict wrote the destination; it must refuse before writing anything")
			}
			if !strings.Contains(stderr, "nothing was written") {
				t.Errorf("the error does not say nothing was written: %s", stderr)
			}
		})
	}
}

// TestPackStrictAcceptsACleanTree checks --strict is satisfiable: a tree with
// nothing to lose packs normally. Without an attribute on the file, an
// ordinary tree on Linux qualifies; on macOS com.apple.provenance means it
// generally does not, which is itself worth demonstrating.
func TestPackStrictAcceptsACleanTree(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("content\n"), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "strict-clean.dmg")

	_, stderr, code := runTimeout(t, packTimeout, "pack", dir, out, "--fs", "apfs", "--volname", "CLEAN", "--strict")
	switch code {
	case exitcode.OK:
		if _, err := os.Stat(out); err != nil {
			t.Errorf("--strict succeeded but wrote nothing: %v", err)
		}
	case exitcode.Unsupported:
		// The platform attached an attribute of its own. Say so rather than
		// failing: it is the documented reason --strict is opt-in.
		t.Logf("this platform attaches extended attributes to new files, so --strict refuses even here: %s", stderr)
	default:
		t.Errorf("exited %s, want OK or Unsupported\nstderr: %s", exitcode.Name(code), stderr)
	}
}

// TestPackStrictOnRepackSucceeds checks a repack, which copies the file system
// image through bit-for-bit, is not caught by --strict.
func TestPackStrictOnRepackSucceeds(t *testing.T) {
	out := filepath.Join(t.TempDir(), "repacked.dmg")
	_, stderr, code := run(t, "pack", fixtureDMG, out, "--strict", "-q")
	if code != exitcode.OK {
		t.Errorf("repack --strict exited %s, want OK\nstderr: %s", exitcode.Name(code), stderr)
	}
}

// TestExtractXattrsRestoresAttributes checks --xattrs actually writes the
// attributes onto the extracted files, and that omitting it leaves them off.
func TestExtractXattrsRestoresAttributes(t *testing.T) {
	if !xattrsReadable() {
		t.Skip("extended attributes are not readable on this platform")
	}

	withFlag := t.TempDir()
	mustRun(t, "extract", fixtureDMG, "-C", withFlag, "--xattrs", "-q")

	without := t.TempDir()
	mustRun(t, "extract", fixtureDMG, "-C", without, "-q")

	// The extracted content must be identical either way: restoring metadata
	// must not disturb the data.
	for _, rel := range []string{"compressed.txt", "empty.txt"} {
		a := filepath.Join(withFlag, rel)
		b := filepath.Join(without, rel)
		if _, err := os.Stat(a); err != nil {
			continue // not every fixture has every file
		}
		sumA, err := fileSHA256(a)
		if err != nil {
			t.Fatal(err)
		}
		sumB, err := fileSHA256(b)
		if err != nil {
			t.Fatal(err)
		}
		if sumA != sumB {
			t.Errorf("%s differs between extractions with and without --xattrs", rel)
		}
	}

	// A transparently compressed file must not come back carrying its
	// compression metadata: extraction decompressed it, so that metadata would
	// describe content the file no longer holds.
	compressed := filepath.Join(withFlag, "compressed.txt")
	if _, err := os.Stat(compressed); err == nil {
		attrs, err := readXattrNames(compressed)
		if err != nil {
			t.Fatalf("reading attributes of %s: %v", compressed, err)
		}
		for _, name := range attrs {
			if name == "com.apple.decmpfs" || name == "com.apple.ResourceFork" {
				t.Errorf("%s was restored onto a decompressed file; it describes content that is no longer there", name)
			}
		}
	}
}

// TestExtractXattrsReports checks the counts reach the user.
func TestExtractXattrsReports(t *testing.T) {
	if !xattrsReadable() {
		t.Skip("extended attributes are not readable on this platform")
	}
	dest := t.TempDir()

	stdout := mustRun(t, "extract", fixtureDMG, "-C", dest, "--xattrs", "-o", "json")
	var summary map[string]any
	if err := json.Unmarshal([]byte(stdout), &summary); err != nil {
		t.Fatalf("extract JSON invalid: %v\n%s", err, stdout)
	}
	if _, ok := summary["xattrsRestored"]; !ok {
		t.Error("xattrsRestored missing from the extract report")
	}
	if _, ok := summary["xattrsUnwritable"]; !ok {
		t.Error("xattrsUnwritable missing from the extract report")
	}
}

// TestExtractCompletesWithXattrs is the regression test for an infinite loop:
// ExtendedAttribute.Read relied on its underlying stream to report io.EOF, so
// reading an attribute whose stream signalled the end differently never
// terminated. Nothing reached that path until --xattrs existed.
func TestExtractCompletesWithXattrs(t *testing.T) {
	dest := t.TempDir()
	_, stderr, code := runTimeout(t, packTimeout, "extract", fixtureDMG, "-C", dest, "--xattrs", "-q")
	if code != exitcode.OK {
		t.Errorf("extract --xattrs exited %s\nstderr: %s", exitcode.Name(code), stderr)
	}
}

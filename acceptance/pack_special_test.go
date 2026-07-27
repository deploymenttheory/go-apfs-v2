// Acceptance coverage for special files in a packed directory. The writers
// model regular files, directories and symbolic links; a device node, FIFO or
// socket must be skipped rather than read, because reading one does not fail
// cleanly — a FIFO blocks until a writer appears, a character device reads
// until memory runs out, and a socket errors and aborts the whole pack.
package acceptance

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/exitcode"
)

// packTimeout bounds a pack that should complete promptly. The failure this
// guards against is the command never returning, so the value only has to be
// far above a normal run of a handful of small files.
const packTimeout = 60 * time.Second

// buildSpecialTree writes a directory holding a regular file, a subdirectory
// and whichever special files the platform can create, and reports which of
// them it managed to make.
func buildSpecialTree(t *testing.T) (dir string, madeFIFO, madeSocket bool) {
	t.Helper()
	dir = t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "regular.txt"), []byte("ordinary content\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "nested.txt"), []byte("nested\n"), 0644); err != nil {
		t.Fatal(err)
	}

	madeFIFO = makeFIFO(t, filepath.Join(dir, "pipe"))
	madeSocket = makeSocket(t, filepath.Join(dir, "sock"))
	return dir, madeFIFO, madeSocket
}

// TestPackSkipsSpecialFiles is the regression test for a pack that never
// returned. A FIFO in the source tree used to hang the command indefinitely,
// because the walk fell through to reading it as a regular file.
func TestPackSkipsSpecialFiles(t *testing.T) {
	dir, madeFIFO, madeSocket := buildSpecialTree(t)
	if !madeFIFO && !madeSocket {
		t.Skip("this platform can create neither a FIFO nor a unix socket")
	}
	t.Logf("special files created: fifo=%v socket=%v", madeFIFO, madeSocket)

	for _, fs := range []string{"apfs", "hfs+"} {
		t.Run(fs, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "packed.dmg")

			// The deadline is the assertion: before the fix this never returned.
			//
			// Skipping an entry is a partial result, so the exit code is 6 —
			// the same meaning extract gives when it cannot handle everything.
			// The image is still written and still usable, which is what the
			// rest of this test checks.
			_, stderr, code := runTimeout(t, packTimeout, "pack", dir, out, "--fs", fs, "--volname", "SPECIAL", "-q")
			if code != exitcode.Partial {
				t.Fatalf("pack exited %s, want %s\nstderr: %s",
					exitcode.Name(code), exitcode.Name(exitcode.Partial), stderr)
			}

			// The ordinary contents must still be there: skipping the special
			// files must not have skipped the rest of the directory.
			dest := t.TempDir()
			mustRun(t, "extract", out, "-C", dest)

			for _, rel := range []string{"regular.txt", filepath.Join("sub", "nested.txt")} {
				if _, err := os.Stat(filepath.Join(dest, rel)); err != nil {
					t.Errorf("%s missing after pack and extract: %v", rel, err)
				}
			}

			// The special files must not have been written as empty regular
			// files, which is what a naive skip would produce.
			for _, rel := range []string{"pipe", "sock"} {
				if _, err := os.Stat(filepath.Join(dest, rel)); err == nil {
					t.Errorf("%s was written into the image; special files must be skipped, not stubbed", rel)
				}
			}
		})
	}
}

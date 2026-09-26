// Independent checks of the APFS writer's large trees. The writer used to
// refuse a file-system tree of more than two levels (about 850 small files),
// wrote a corrupt extentref tree at 111 and 112 non-empty files, and refused
// snapshots past 112 of them. pkg/apfswrite reads such volumes back with our
// own reader; these tests hand them to fsck_apfs (macOS) and apfsck (Linux).
package acceptance

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/exitcode"
)

// flatDir creates a directory of n small files with 12-byte names.
func flatDir(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	for i := range n {
		name := filepath.Join(dir, fmt.Sprintf("file%08d", i))
		if err := os.WriteFile(name, fmt.Appendf(nil, "file %d\n", i), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// flatEntries returns a root of n small files named by name(i).
func flatEntries(n int, name func(i int) string) *apfswrite.Entry {
	root := &apfswrite.Entry{}
	for i := range n {
		root.Children = append(root.Children, &apfswrite.Entry{Name: name(i), Data: fmt.Appendf(nil, "file %d\n", i)})
	}
	return root
}

// TestPackAPFSManyFiles packs a directory of 50,000 small files through the
// real binary and checks the result.
func TestPackAPFSManyFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("packs 50,000 files")
	}
	const n = 50_000
	dmg := filepath.Join(t.TempDir(), "many.dmg")
	_, stderr, code := run(t, "pack", flatDir(t, n), dmg, "--fs", "apfs", "--volname", "Many")
	if code != exitcode.OK {
		t.Fatalf("pack of %d files: %s: %s", n, exitcode.Name(code), stderr)
	}
	raw, err := disk.ReconstructRawImage(dmg)
	if err != nil {
		t.Fatal(err)
	}
	rawPath := filepath.Join(t.TempDir(), "raw.img")
	if err := os.WriteFile(rawPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	checkAPFSImage(t, rawPath)
	attest(t, "pack --fs apfs on %s wrote %d small files", runtime.GOOS, n)

	// macOS mounts it and sees every file with its content.
	if runtime.GOOS != "darwin" {
		return
	}
	mnt, dev := attachAndMount(t, rawPath)
	defer detach(t, dev)
	entries, err := os.ReadDir(mnt)
	if err != nil {
		t.Fatal(err)
	}
	files := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "file") {
			files++
		}
	}
	if files != n {
		t.Fatalf("the mounted volume lists %d files, want %d", files, n)
	}
	for i := 0; i < n; i += 997 {
		got, err := os.ReadFile(filepath.Join(mnt, fmt.Sprintf("file%08d", i)))
		if err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf("file %d\n", i); string(got) != want {
			t.Fatalf("file%08d holds %q, want %q", i, got, want)
		}
	}
	attest(t, "macOS mounted the volume and listed all %d files", n)
}

// TestLargeTreesCheckerClean writes the shapes the writer used to refuse or
// corrupt and checks each one.
func TestLargeTreesCheckerClean(t *testing.T) {
	name := func(i int) string { return fmt.Sprintf("file%08d", i) }
	longName := func(i int) string {
		prefix := fmt.Sprintf("%08d", i)
		return prefix + strings.Repeat("n", 255-len(prefix))
	}
	snaps := []apfswrite.SnapshotSpec{{Name: "one"}, {Name: "two"}}
	cases := []struct {
		name string
		size int64
		opts *apfswrite.CreateOptions
	}{
		{"extentref root-leaf at 111 files", 0, &apfswrite.CreateOptions{VolumeName: "E111", Root: flatEntries(111, name)}},
		{"extentref root-leaf at 112 files", 0, &apfswrite.CreateOptions{VolumeName: "E112", Root: flatEntries(112, name)}},
		{"5,000 long names", 0, &apfswrite.CreateOptions{VolumeName: "Long", Root: flatEntries(5_000, longName)}},
		{"snapshots of 5,000 files", 0, &apfswrite.CreateOptions{VolumeName: "Snap", Root: flatEntries(5_000, name), Snapshots: snaps}},
		{"two volumes past their reserved oids", 1 << 30, &apfswrite.CreateOptions{Volumes: []apfswrite.VolumeSpec{
			{Name: "One", Root: flatEntries(3_000, name)},
			{Name: "Two", Root: flatEntries(4_000, name), Snapshots: snaps[:1]},
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "large.img")
			writeImage(t, path, tc.size, tc.opts)
			checkAPFSImage(t, path)
		})
	}
}

// checkAPFSImage runs whichever independent APFS checkers this platform has
// against a raw container image, and skips when it has none.
func checkAPFSImage(t *testing.T, rawPath string) {
	t.Helper()
	checked := false
	if _, err := exec.LookPath("apfsck"); err == nil {
		out, err := exec.Command("apfsck", "-cw", rawPath).CombinedOutput()
		if err != nil {
			t.Fatalf("apfsck reported problems (exit %v):\n%s", err, out)
		}
		attest(t, "apfsck clean")
		checked = true
	}
	if runtime.GOOS == "darwin" {
		requireTools(t, "hdiutil", "fsck_apfs")
		dev := attachRaw(t, rawPath)
		defer detach(t, dev)
		out, err := exec.Command("fsck_apfs", "-n", dev).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "appears to be OK") {
			t.Fatalf("fsck_apfs did not report the container clean (%v):\n%s", err, out)
		}
		attest(t, "fsck_apfs clean")
		checked = true
	}
	if !checked {
		t.Skip("no APFS checker on this platform")
	}
}

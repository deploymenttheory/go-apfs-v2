//go:build darwin

// Hard links on a written HFS+ volume, judged by fsck_hfs and the macOS driver.
//
// These exist because the unit tests could not have caught what was wrong. This
// toolkit's reader resolves a hard link through the BSD info's special field
// alone, so it read a volume back correctly while macOS read every linked name
// as an empty file and fsck_hfs called the volume corrupt. Only a tool that did
// not write the volume could tell.
package acceptance

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const hardLinkBody = "shared content, stored once\n"

// linkedTree builds a source tree with one file under three names and one
// ordinary file beside it.
func linkedTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	first := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(first, []byte(hardLinkBody), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"b.txt", "c.txt"} {
		if err := os.Link(first, filepath.Join(dir, name)); err != nil {
			t.Skipf("cannot create a hard link here: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "plain.txt"), []byte("ordinary\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestPackHFSPlusHardLinksAreFsckClean is the check that was missing. A volume
// whose links lack the chain draws "found N pre-Leopard file inodes" and "Hard
// Link catalog entry N has bad time", and is declared corrupt.
func TestPackHFSPlusHardLinksAreFsckClean(t *testing.T) {
	requireTools(t, "hdiutil", "fsck_hfs")

	dmg := filepath.Join(t.TempDir(), "links.dmg")
	mustRun(t, "pack", linkedTree(t), dmg, "--fs", "hfs+", "--volname", "Links")

	_, dev := attachHFS(t, dmg)
	defer detach(t, dev)

	out, _ := exec.Command("fsck_hfs", "-n", dev).CombinedOutput()
	text := string(out)
	t.Logf("fsck_hfs output:\n%s", text)
	if !strings.Contains(text, "appears to be OK") {
		t.Errorf("fsck_hfs did not report the volume clean")
	}
	for _, marker := range []string{"pre-Leopard", "bad time", "corrupt"} {
		if strings.Contains(text, marker) {
			t.Errorf("fsck_hfs reported %q", marker)
		}
	}
}

// TestPackHFSPlusHardLinksReadThroughMacOS is the other half: the driver must
// return the content, and see one file under several names rather than several
// files.
func TestPackHFSPlusHardLinksReadThroughMacOS(t *testing.T) {
	requireTools(t, "hdiutil")

	dmg := filepath.Join(t.TempDir(), "links-read.dmg")
	mustRun(t, "pack", linkedTree(t), dmg, "--fs", "hfs+", "--volname", "LinksRead")

	mountPoint, dev := attachHFS(t, dmg)
	defer detach(t, dev)

	names := []string{"a.txt", "b.txt", "c.txt"}
	var firstIno uint64
	for i, name := range names {
		path := filepath.Join(mountPoint, name)

		got, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		// An empty read is the symptom of a missing link chain: macOS resolves
		// the link, finds nothing it recognises, and hands back nothing.
		if string(got) != hardLinkBody {
			t.Errorf("%s = %q, want %q", name, got, hardLinkBody)
		}

		ino, nlink, ok := linkIdentity(t, path)
		if !ok {
			continue
		}
		if nlink != uint64(len(names)) {
			t.Errorf("%s: link count = %d, want %d", name, nlink, len(names))
		}
		if i == 0 {
			firstIno = ino
		} else if ino != firstIno {
			t.Errorf("%s has inode %d, want %d: the names are not one file", name, ino, firstIno)
		}
	}

	// The private metadata directory is volume housekeeping and must not show
	// up in a listing.
	entries, err := os.ReadDir(mountPoint)
	if err != nil {
		t.Fatalf("reading the mounted root: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "HFS+ Private Data") {
			t.Errorf("the private metadata directory is visible: %q", e.Name())
		}
	}
}

// TestPackHFSPlusCompressedHardLinks is the interaction: a compressed file
// under several names. The compression flag must follow the content to the
// indirect node, and the links must still resolve.
func TestPackHFSPlusCompressedHardLinks(t *testing.T) {
	requireTools(t, "hdiutil", "fsck_hfs")
	src, wantSum, wantSize := compressibleTree(t)

	// Give the compressed file a second name.
	if err := os.Link(filepath.Join(src, "big.txt"), filepath.Join(src, "big-again.txt")); err != nil {
		t.Skipf("cannot create a hard link here: %v", err)
	}

	dmg := filepath.Join(t.TempDir(), "clinks.dmg")
	mustRun(t, "pack", src, dmg, "--fs", "hfs+", "--volname", "CLinks")

	mountPoint, dev := attachHFS(t, dmg)
	defer detach(t, dev)

	for _, name := range []string{"big.txt", "big-again.txt"} {
		path := filepath.Join(mountPoint, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("stat %s: %v", name, err)
			continue
		}
		if info.Size() != wantSize {
			t.Errorf("%s: size = %d, want %d", name, info.Size(), wantSize)
		}
		if _, _, compressed := compressedAttributes(t, path); !compressed {
			t.Errorf("%s is not compressed", name)
		}
		sum, err := sha256File(path)
		if err != nil {
			t.Errorf("checksumming %s: %v", name, err)
		} else if sum != wantSum {
			t.Errorf("%s content does not match the source", name)
		}
	}

	out, _ := exec.Command("fsck_hfs", "-n", dev).CombinedOutput()
	if !strings.Contains(string(out), "appears to be OK") {
		t.Errorf("fsck_hfs did not report the volume clean:\n%s", out)
	}
}

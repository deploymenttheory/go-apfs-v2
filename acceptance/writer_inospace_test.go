// Checker tests for the volume-group inode space. The unit tests in
// pkg/apfswrite read a grouped volume back with our own reader, which cannot
// tell a correct layout from one we consistently misunderstand. Only Apple's
// fsck_apfs and the macOS driver can, and it was fsck_apfs that settled where
// the boundary between the reserved and the shifted numbers falls — the spec
// says something the checker rejects. These tests keep that answer pinned.
package acceptance

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// groupedImageSize is comfortably above the minimum the macOS raw-disk driver
// will attach; the same 32 MiB the other checker tests use.
// Two volumes, and APFS allows one per 512 MiB. The image is sparse, so this
// costs a few MiB on disk rather than a gigabyte.
const groupedImageSize = 2 * 512 * 1024 * 1024

// writeGroupedImage formats a populated system volume carrying a group
// identifier, which is what obliges it to number inodes in the group's upper
// half.
func writeGroupedImage(t *testing.T, path string) {
	t.Helper()
	groupID := [16]byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	tree := func() *apfswrite.Entry {
		return &apfswrite.Entry{Children: []*apfswrite.Entry{
			{Name: "hello.txt", Data: []byte("hello\n")},
			{Name: "dir", Mode: fs.ModeDir, Children: []*apfswrite.Entry{
				{Name: "nested.txt", Data: []byte("nested\n")},
			}},
		}}
	}
	// A group is a system/data pair. The system half is the one examined; the
	// data half has to exist for the group to be well formed at all.
	writeImage(t, path, groupedImageSize, &apfswrite.CreateOptions{
		Volumes: []apfswrite.VolumeSpec{
			{Name: "GroupVol", Role: apfs.VolumeRoleSystem, VolumeGroupID: groupID, Root: tree()},
			{Name: "GroupData", Role: apfs.VolumeRoleData, VolumeGroupID: groupID, Root: tree()},
		},
	})
}

// TestGroupedVolumeFsckClean is the test that decided the layout. Three of the
// four arrangements we tried are rejected here:
//
//   - numbering user inodes below the mark (what the writer used to do) is
//     accepted by fsck but puts the system volume's files in the data volume's
//     half of a shared space;
//   - shifting ROOT_DIR_INO_NUM and PRIV_DIR_INO_NUM up by the mark, which is
//     what the spec's Inode Numbers section describes, makes fsck count them as
//     ordinary directories: "apfs_num_directories is not valid (expected 3,
//     actual 1)";
//   - shifting ROOT_DIR_PARENT as well produces "orphan directory record" for
//     both special dentries, because fsck looks for the root's parent at 1.
//
// Only shifting the user inodes satisfies the shared-space rule and passes.
func TestGroupedVolumeFsckClean(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fsck_apfs is only available on macOS")
	}
	requireTools(t, "hdiutil", "fsck_apfs")

	imgPath := filepath.Join(t.TempDir(), "group.img")
	writeGroupedImage(t, imgPath)

	dev := attachRaw(t, imgPath)
	defer detach(t, dev)

	out, err := exec.Command("fsck_apfs", "-n", dev).CombinedOutput()
	text := string(out)
	t.Logf("fsck_apfs output:\n%s", text)
	if err != nil {
		t.Fatalf("fsck_apfs reported errors (exit %v)", err)
	}
	// fsck_apfs exits 0 even when it finds a volume corrupt, so the text is
	// what has to be checked, not the status.
	if strings.Contains(text, "corrupt") {
		t.Errorf("fsck_apfs found the grouped volume corrupt")
	}
	for _, marker := range []string{"orphan directory record", "apfs_num_directories is not valid"} {
		if strings.Contains(text, marker) {
			t.Errorf("fsck_apfs reported %q: the reserved inode numbers must not "+
				"shift by UNIFIED_ID_SPACE_MARK, only the user ones", marker)
		}
	}
	if !strings.Contains(text, "appears to be OK") {
		t.Errorf("fsck_apfs did not report the grouped container clean")
	}
}

// TestGroupedVolumeApfsckClean is the always-on gate, and it now has teeth it
// did not before: a lone system volume drew "Volume group with no data" and had
// to be tolerated, which meant apfsck's group checks never actually ran. With
// both halves present they do, and must pass outright.
func TestGroupedVolumeApfsckClean(t *testing.T) {
	if _, err := exec.LookPath("apfsck"); err != nil {
		t.Skip("apfsck not installed; skipping (install apfsprogs)")
	}

	imgPath := filepath.Join(t.TempDir(), "group-apfsck.img")
	writeGroupedImage(t, imgPath)

	out, err := exec.Command("apfsck", "-cw", imgPath).CombinedOutput()
	t.Logf("apfsck output:\n%s", out)
	if err != nil {
		t.Fatalf("apfsck reported problems (exit %v)", err)
	}
}

// TestGroupedVolumeMountsWithShiftedInodes is the driver's verdict, and the
// only place the shifted numbers are observed from outside our own code: macOS
// reports them verbatim, so the root comes back as 2 and the entries at
// UNIFIED_ID_SPACE_MARK + MIN_USER_INO_NUM and upward.
func TestGroupedVolumeMountsWithShiftedInodes(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the APFS driver is only available on macOS")
	}
	requireTools(t, "hdiutil")

	imgPath := filepath.Join(t.TempDir(), "group-mount.img")
	writeGroupedImage(t, imgPath)

	out, err := exec.Command("hdiutil", "attach",
		"-imagekey", "diskimage-class=CRawDiskImage", "-readonly", imgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach: %v\n%s", err, out)
	}
	dev := devRe.FindString(string(out))
	defer detach(t, dev)

	mountPoint := mountPointFrom(out)
	if mountPoint == "" {
		t.Fatalf("the grouped volume did not mount:\n%s", out)
	}
	// Both halves mount; the system one carries the tree examined here.
	if !strings.Contains(mountPoint, "GroupVol") {
		t.Fatalf("mounted %q, want the system half:\n%s", mountPoint, out)
	}

	// The root keeps the ordinary reserved number.
	rootIno, _, ok := linkIdentity(t, mountPoint)
	if !ok {
		t.Skip("inode numbers are not observable here")
	}
	if rootIno != apfs.RootDirInoNum {
		t.Errorf("the driver reports the root as inode %#x, want %d", rootIno, apfs.RootDirInoNum)
	}

	// Everything the volume allocated sits in the system half.
	floor := apfs.UnifiedIDSpaceMark + apfs.MinUserInoNum
	entries, err := os.ReadDir(mountPoint)
	if err != nil {
		t.Fatalf("read the mounted root: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("the mounted volume listed nothing")
	}
	for _, e := range entries {
		ino, _, ok := linkIdentity(t, filepath.Join(mountPoint, e.Name()))
		if !ok {
			continue
		}
		if ino < floor {
			t.Errorf("the driver reports %s as inode %#x, below the system volume's floor %#x",
				e.Name(), ino, floor)
		}
	}

	// The contents survived the renumbering, read through the real driver.
	data, err := os.ReadFile(filepath.Join(mountPoint, "dir", "nested.txt"))
	if err != nil {
		t.Fatalf("read a nested file through the mount: %v", err)
	}
	if string(data) != "nested\n" {
		t.Errorf("nested.txt = %q, want %q", data, "nested\n")
	}
}

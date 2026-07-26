// apfs snapshot — inspect APFS volume snapshots.
package cli

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

// Volume-superblock field offsets (bytes) used by in-place revert.
const (
	apsbRevertToXIDOffset    = 160
	apsbRevertToSblockOffset = 168
	nxMagicLE                = 0x4253584e // 'NXSB'
)

var snapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Inspect APFS volume snapshots",
	Long: `Work with APFS snapshots.

Snapshots are created at build time with 'create --fs apfs --snapshot NAME' or
'pack <dir> --fs apfs --snapshot NAME'. This command group inspects them.`,
}

func init() {
	snapshotCmd.AddCommand(snapshotListCmd)
	snapshotCmd.AddCommand(snapshotCreateCmd)
	snapshotCmd.AddCommand(snapshotVerifyCmd)
	snapshotCmd.AddCommand(snapshotRevertCmd)

	snapshotCreateCmd.Flags().StringVar(&snapCreateName, "name", "", "snapshot name (required)")
	snapshotCreateCmd.Flags().StringVarP(&snapCreateOutput, "output", "O", "", "write the result here (a new DMG)")
	snapshotCreateCmd.Flags().BoolVar(&snapCreateForce, "force", false, "overwrite the source image in place")

	snapshotRevertCmd.Flags().StringVar(&snapRevertName, "name", "", "snapshot to revert to (required)")
	snapshotRevertCmd.Flags().StringVarP(&snapRevertOutput, "output", "O", "", "write the result here (a new DMG)")
	snapshotRevertCmd.Flags().BoolVar(&snapRevertForce, "force", false, "overwrite the source image in place")
}

var (
	snapCreateName   string
	snapCreateOutput string
	snapCreateForce  bool
)

var snapshotCreateCmd = &cobra.Command{
	Use:   "create IMAGE --name NAME",
	Short: "Rebuild an APFS image carrying a snapshot of its current state",
	Long: `Read the APFS volume in IMAGE, rebuild it into a new APFS container that
additionally carries a snapshot named NAME capturing that state, and write the
result. The snapshot is a real, macOS-recognized APFS snapshot.

Because the writer rebuilds the volume from its contents (rather than preserving
the original on-disk bytes), this is not a byte-for-byte copy of the source. To
protect evidence, the result is written to --output by default; overwriting the
source in place requires --force.`,
	Args: exactArgs(1, "IMAGE"),
	RunE: runSnapshotCreate,
}

// resolveRebuildOutput returns where a rebuild command should write. To avoid
// destroying evidence, overwriting the source image requires --force.
func resolveRebuildOutput(image, output string, force bool) (string, error) {
	if output != "" {
		if output == image && !force {
			return "", usageErrorf("--output is the source image; pass --force to overwrite it in place")
		}
		return output, nil
	}
	if force {
		return image, nil
	}
	return "", usageErrorf("refusing to overwrite the source image; pass --output FILE (or --force to overwrite in place)")
}

func runSnapshotCreate(cmd *cobra.Command, args []string) error {
	if snapCreateName == "" {
		return usageErrorf("--name is required")
	}
	imagePath := args[0]
	outPath, err := resolveRebuildOutput(imagePath, snapCreateOutput, snapCreateForce)
	if err != nil {
		return err
	}

	container, cleanup, err := openAPFSContainer(imagePath)
	if err != nil {
		return err
	}
	defer cleanup()

	sel := opts.Volume
	if sel == "" {
		sel = "0"
	}
	volume, err := container.VolumeBySelector(sel)
	if err != nil {
		return withCode(ExitBadImage, fmt.Errorf("unable to open volume %q: %w", sel, err))
	}
	volName, _ := volume.GetUTF8Name()

	tree, err := entryTreeFromVolume(volume)
	if err != nil {
		return fmt.Errorf("unable to read volume contents: %w", err)
	}

	copts := &apfswrite.CreateOptions{
		VolumeName: volName,
		Root:       tree,
		Snapshots:  []apfswrite.SnapshotSpec{{Name: snapCreateName}},
	}
	if ci, err := volume.IsCaseInsensitive(); err == nil {
		copts.CaseSensitive = !ci
	}

	var buf writeAtBuffer
	if err := apfswrite.CreateContainer(&buf, 0, copts); err != nil {
		return fmt.Errorf("unable to build APFS container with snapshot: %w", err)
	}
	if err := disk.WrapRawImageDMG(outPath, buf.Bytes(), "Apple_APFS", nil); err != nil {
		return fmt.Errorf("unable to write %s: %w", outPath, err)
	}

	if opts.Output == "json" {
		return jsonOut(map[string]any{"source": imagePath, "destination": outPath, "snapshot": snapCreateName, "volume": volName})
	}
	if !opts.Quiet {
		fmt.Printf("Wrote %s with snapshot %q of volume %q\n", outPath, snapCreateName, volName)
	}
	return nil
}

// entryTreeFromVolume walks an APFS volume and builds an apfswrite.Entry tree
// (files, directories, symlinks with their modes and modification times) that
// the writer can rebuild. Only the root's children are used by the writer.
func entryTreeFromVolume(vol *apfs.Volume) (*apfswrite.Entry, error) {
	children, err := volumeEntries(vol, ".")
	if err != nil {
		return nil, err
	}
	return &apfswrite.Entry{Children: children}, nil
}

func volumeEntries(vol *apfs.Volume, dir string) ([]*apfswrite.Entry, error) {
	des, err := vol.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*apfswrite.Entry
	for _, de := range des {
		name := de.Name()
		full := name
		if dir != "." {
			full = dir + "/" + name
		}
		info, err := de.Info()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", full, err)
		}
		mode := info.Mode()
		e := &apfswrite.Entry{Name: name, Mode: mode, ModTime: info.ModTime()}
		if inode, ok := info.Sys().(*apfs.Inode); ok {
			e.UID, e.GID = inode.OwnerIdentifier, inode.GroupIdentifier
		}
		switch {
		case mode&fs.ModeSymlink != 0:
			target, err := vol.Readlink(full)
			if err != nil {
				return nil, fmt.Errorf("%s: reading symlink: %w", full, err)
			}
			e.Data = []byte(target)
		case mode.IsDir():
			kids, err := volumeEntries(vol, full)
			if err != nil {
				return nil, err
			}
			e.Children = kids
		case mode.IsRegular():
			data, err := vol.ReadFile(full)
			if err != nil {
				return nil, fmt.Errorf("%s: reading file: %w", full, err)
			}
			e.Data = data
		default:
			// Skip special files (devices, fifos, sockets) — the writer only
			// models files, directories and symlinks.
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

var snapshotVerifyCmd = &cobra.Command{
	Use:   "verify IMAGE",
	Short: "Verify that each snapshot in an APFS image is readable",
	Long: `Open each snapshot on each APFS volume and confirm its frozen superblock and
metadata are readable. Reports the number of snapshots verified; exits non-zero
if any snapshot cannot be opened.`,
	Args: exactArgs(1, "IMAGE"),
	RunE: runSnapshotVerify,
}

func runSnapshotVerify(cmd *cobra.Command, args []string) error {
	container, cleanup, err := openAPFSContainer(args[0])
	if err != nil {
		return err
	}
	defer cleanup()

	volumes, err := container.Volumes()
	if err != nil {
		return fmt.Errorf("unable to enumerate volumes: %w", err)
	}

	var verified int
	var problems []string
	for vi, volume := range volumes {
		n, err := volume.GetNumberOfSnapshots()
		if err != nil {
			problems = append(problems, fmt.Sprintf("volume %d: %v", vi, err))
			continue
		}
		for i := 0; i < n; i++ {
			snap, err := volume.GetSnapshot(i)
			if err != nil {
				problems = append(problems, fmt.Sprintf("volume %d snapshot %d: %v", vi, i, err))
				continue
			}
			if snap.VolumeSuperblock == nil {
				problems = append(problems, fmt.Sprintf("volume %d snapshot %d: no superblock", vi, i))
				continue
			}
			verified++
		}
	}

	if opts.Output == "json" {
		if err := jsonOut(map[string]any{"verified": verified, "problems": problems}); err != nil {
			return err
		}
	} else if !opts.Quiet {
		fmt.Printf("Verified %d snapshot(s).\n", verified)
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "problem: %s\n", p)
		}
	}
	if len(problems) > 0 {
		return withCode(ExitError, fmt.Errorf("%d snapshot problem(s)", len(problems)))
	}
	return nil
}

var (
	snapRevertName   string
	snapRevertOutput string
	snapRevertForce  bool
)

var snapshotRevertCmd = &cobra.Command{
	Use:   "revert IMAGE --name NAME",
	Short: "Mark an APFS image to revert to a snapshot on next mount",
	Long: `Set the live volume's revert-to fields (apfs_revert_to_xid and
apfs_revert_to_sblock_oid) so that APFS rolls the volume back to snapshot NAME
the next time it is mounted — the spec's snapshot-revert mechanism.

The revert intent is patched into the live volume superblock in place (the rest
of the image is copied unchanged, so it is byte-faithful except for that one
block). The result is written to --output by default; overwriting the source in
place requires --force. Currently supports a DMG wrapping an APFS container at
offset zero (as produced by 'create'/'pack').`,
	Args: exactArgs(1, "IMAGE"),
	RunE: runSnapshotRevert,
}

// resolveLiveVolumeBlock returns the physical block of the live volume
// superblock for the given volume object id, mirroring how the container opens
// a volume (checkpoint map first, then the object map).
func resolveLiveVolumeBlock(c *apfs.Container, volID uint64) (uint64, error) {
	if addr, err := c.CheckpointMap.GetPhysicalAddressByObjectIdentifier(volID); err == nil && addr != 0 {
		return addr, nil
	}
	desc, err := c.ObjectMapBTree.GetDescriptorByObjectIdentifier(c.FileIOHandle, volID, c.Superblock.ObjectTransactionIdentifier)
	if err != nil {
		return 0, err
	}
	return desc.Value.ObjectPhysicalAddress, nil
}

func runSnapshotRevert(cmd *cobra.Command, args []string) error {
	if snapRevertName == "" {
		return usageErrorf("--name is required")
	}
	imagePath := args[0]
	outPath, err := resolveRebuildOutput(imagePath, snapRevertOutput, snapRevertForce)
	if err != nil {
		return err
	}

	container, cleanup, err := openAPFSContainer(imagePath)
	if err != nil {
		return err
	}

	// Find the named snapshot (its xid and frozen superblock block) and the live
	// volume's superblock block.
	volIDs, err := container.GetVolumeObjectIdentifiers()
	if err != nil || len(volIDs) == 0 {
		cleanup()
		return withCode(ExitBadImage, fmt.Errorf("unable to read volumes: %w", err))
	}
	volID := volIDs[0]
	volume, err := container.VolumeBySelector("0")
	if err != nil {
		cleanup()
		return withCode(ExitBadImage, fmt.Errorf("unable to open volume: %w", err))
	}

	var snapXID, snapSblock uint64
	found := false
	if n, _ := volume.GetNumberOfSnapshots(); n > 0 {
		for i := 0; i < n; i++ {
			snap, err := volume.GetSnapshot(i)
			if err != nil {
				continue
			}
			if name, _ := snap.GetUTF8Name(); name == snapRevertName && snap.SnapshotMetadata != nil {
				snapXID = snap.SnapshotMetadata.ObjectIdentifier
				snapSblock = snap.SnapshotMetadata.VolumeSuperblockBlockNumber
				found = true
				break
			}
		}
	}
	if !found {
		cleanup()
		return withCode(ExitError, fmt.Errorf("no snapshot named %q on the volume", snapRevertName))
	}

	liveBlock, err := resolveLiveVolumeBlock(container, volID)
	if err != nil {
		cleanup()
		return fmt.Errorf("unable to locate the live volume superblock: %w", err)
	}
	blockSize := uint64(container.IOHandle.BlockSize)
	cleanup() // done reading; reconstruct and patch the raw image below

	raw, err := disk.ReconstructRawImage(imagePath)
	if err != nil {
		return fmt.Errorf("revert currently requires a DMG image: %w", err)
	}
	// This patch addresses the container at offset zero in the raw image.
	if len(raw) < 36 || binary.LittleEndian.Uint32(raw[32:36]) != nxMagicLE {
		return withCode(ExitUnsupported, fmt.Errorf("revert supports a DMG wrapping an APFS container at offset zero"))
	}

	off := liveBlock * blockSize
	if off+blockSize > uint64(len(raw)) {
		return fmt.Errorf("live volume superblock block %d is out of range", liveBlock)
	}
	block := raw[off : off+blockSize]
	binary.LittleEndian.PutUint64(block[apsbRevertToXIDOffset:], snapXID)
	binary.LittleEndian.PutUint64(block[apsbRevertToSblockOffset:], snapSblock)
	// Reseal the block: Fletcher-64 over everything after the 8-byte checksum.
	cksum, err := apfs.CalculateFletcher64(block[8:], 0)
	if err != nil {
		return fmt.Errorf("recomputing superblock checksum: %w", err)
	}
	binary.LittleEndian.PutUint64(block[0:], cksum)

	if err := disk.WrapRawImageDMG(outPath, raw, "Apple_APFS", nil); err != nil {
		return fmt.Errorf("unable to write %s: %w", outPath, err)
	}

	if opts.Output == "json" {
		return jsonOut(map[string]any{"source": imagePath, "destination": outPath, "revertTo": snapRevertName, "xid": snapXID})
	}
	if !opts.Quiet {
		fmt.Printf("Wrote %s marked to revert to snapshot %q (xid %d) on next mount\n", outPath, snapRevertName, snapXID)
	}
	return nil
}

var snapshotListCmd = &cobra.Command{
	Use:   "list IMAGE",
	Short: "List the snapshots on each APFS volume in an image",
	Args:  exactArgs(1, "IMAGE"),
	RunE:  runSnapshotList,
}

// openAPFSContainer opens imagePath as an APFS container (sniffing the DMG/raw
// layout and applying --offset), returning the container and a cleanup function.
// It is APFS-only: snapshots are an APFS concept.
func openAPFSContainer(imagePath string) (*apfs.Container, func(), error) {
	if _, err := os.Stat(imagePath); err != nil {
		return nil, nil, withCode(ExitBadImage, fmt.Errorf("unable to open image: %w", err))
	}
	reader, sniffedOffset, closer, err := disk.OpenWithOffset(imagePath)
	if err != nil {
		return nil, nil, withCode(ExitBadImage, fmt.Errorf("unable to open image: %w", err))
	}

	offset := opts.Offset
	if offset == 0 {
		offset = sniffedOffset
	}
	base := io.ReaderAt(reader)
	if offset != 0 {
		base = io.NewSectionReader(reader, offset, math.MaxInt64-offset)
	}
	if sniffFilesystem(base) != "apfs" {
		closer.Close()
		return nil, nil, withCode(ExitUnsupported, fmt.Errorf("%s is not an APFS image; snapshots are APFS-only", imagePath))
	}

	container, err := apfs.Open(base, &apfs.OpenOptions{
		Password:         opts.Password,
		RecoveryPassword: opts.RecoveryPassword,
	})
	if err != nil {
		closer.Close()
		return nil, nil, withCode(ExitBadImage, fmt.Errorf("unable to open APFS container: %w", err))
	}
	return container, func() { container.Free(); closer.Close() }, nil
}

// snapshotJSON is one snapshot in the JSON output.
type snapshotJSON struct {
	Volume      int       `json:"volume"`
	VolumeName  string    `json:"volumeName"`
	Name        string    `json:"name"`
	XID         uint64    `json:"xid"`
	CreatedTime time.Time `json:"created,omitempty"`
}

func runSnapshotList(cmd *cobra.Command, args []string) error {
	container, cleanup, err := openAPFSContainer(args[0])
	if err != nil {
		return err
	}
	defer cleanup()

	volumes, err := container.Volumes()
	if err != nil {
		return fmt.Errorf("unable to enumerate volumes: %w", err)
	}

	var out []snapshotJSON
	for vi, volume := range volumes {
		volName, _ := volume.GetUTF8Name()
		n, err := volume.GetNumberOfSnapshots()
		if err != nil {
			return fmt.Errorf("volume %d: unable to read snapshots: %w", vi, err)
		}
		for i := 0; i < n; i++ {
			snap, err := volume.GetSnapshot(i)
			if err != nil {
				return fmt.Errorf("volume %d snapshot %d: %w", vi, i, err)
			}
			name, _ := snap.GetUTF8Name()
			s := snapshotJSON{Volume: vi, VolumeName: volName, Name: name}
			if snap.SnapshotMetadata != nil {
				s.XID = snap.SnapshotMetadata.ObjectIdentifier
				if t := snap.SnapshotMetadata.CreationTime; t != 0 {
					s.CreatedTime = time.Unix(0, int64(t)).UTC()
				}
			}
			out = append(out, s)
		}
	}

	if opts.Output == "json" {
		return jsonOut(out)
	}
	if len(out) == 0 {
		if !opts.Quiet {
			fmt.Println("No snapshots.")
		}
		return nil
	}
	for _, s := range out {
		created := ""
		if !s.CreatedTime.IsZero() {
			created = "  " + s.CreatedTime.Format(time.RFC3339)
		}
		fmt.Printf("Volume %d (%s): %s  (xid %d)%s\n", s.Volume, s.VolumeName, s.Name, s.XID, created)
	}
	return nil
}

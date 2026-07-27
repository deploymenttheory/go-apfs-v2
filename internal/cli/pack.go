// apfs pack SOURCE OUT.dmg — build a DMG from a directory (HFS+), or repack an
// existing DMG/raw image.
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/imagefile"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/fidelity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/spf13/cobra"
)

var (
	packCompression string
	packChunkKiB    uint
	packVolumeName  string
	packFS          string
	packSnapshot    string
	packStrict      bool
	packUUIDs       writeIdentityFlags
)

var packCmd = &cobra.Command{
	Use:   "pack SOURCE OUT.dmg",
	Short: "Build a DMG from a directory, or repack an existing DMG",
	Long: `Pack SOURCE into a new UDIF DMG at OUT.dmg.

If SOURCE is a directory, its contents are written into a new volume and
wrapped in a DMG (this is the write/inverse of extract). The volume file system
is chosen with --fs:

  --fs hfs+  writes an HFS+ (HFSX) volume (default).
  --fs apfs  writes an APFS container.

If SOURCE is an existing DMG, its exact block layout is preserved while its
chunks are recompressed. A repack is not byte-identical to the original —
different compressors produce different container bytes — but the raw
file system image round-trips bit-for-bit and the result mounts under both this
tool and macOS.

Fidelity: packing a directory is lossy. The new volume carries regular files,
directories and symbolic links with their mode, owner, group and modification
time. It does not carry extended attributes (including resource forks and
ACLs), hard links (each name becomes a separate copy), device nodes, FIFOs or
sockets (skipped), BSD flags, or a distinct creation time. Each loss is counted
and reported, and --output json exposes the counts. --strict refuses to write
anything at all when the source contains something the volume cannot carry.
Repacking an existing DMG loses nothing. See docs/write-fidelity.md.

Exit codes: 6 means entries were skipped entirely and the image is incomplete;
5 means --strict refused to write. Metadata that could not be carried is
reported but does not on its own change the exit code.

Examples:
  apfs pack ./mytree out.dmg --volname "My Data"   # directory -> HFS+ DMG
  apfs pack ./mytree out.dmg --fs apfs --strict    # fail rather than lose data
  apfs pack original.dmg repacked.dmg              # repack a DMG
  apfs pack original.dmg smaller.dmg --compression none`,
	Args: exactArgs(2, "SOURCE OUT.dmg"),
	RunE: runPack,
}

func init() {
	packCmd.Flags().StringVar(&packCompression, "compression", "zlib", "chunk compression: zlib or none")
	packCmd.Flags().UintVar(&packChunkKiB, "chunk-size", 1024, "chunk size in KiB (must be a multiple of 512 bytes)")
	packCmd.Flags().StringVar(&packVolumeName, "volname", "", "volume name when packing a directory (default: directory name)")
	packCmd.Flags().StringVar(&packFS, "fs", "hfs+", "file system when packing a directory: HFS+ or APFS (case-insensitive)")
	packCmd.Flags().StringVar(&packSnapshot, "snapshot", "", "APFS only: also create a snapshot with this name capturing the packed volume")
	packCmd.Flags().BoolVar(&packStrict, "strict", false, "refuse to write anything if the source contains something the volume cannot carry")
	packUUIDs.register(packCmd)
}

func runPack(cmd *cobra.Command, args []string) error {
	srcPath := args[0]
	dstPath := args[1]

	info, err := os.Stat(srcPath)
	if err != nil {
		return withCode(ExitBadImage, fmt.Errorf("unable to open source: %w", err))
	}

	encOpts, err := packEncodeOptions()
	if err != nil {
		return err
	}

	if info.IsDir() {
		return packDirectory(srcPath, dstPath, encOpts)
	}
	return packRepack(srcPath, dstPath, encOpts)
}

func packEncodeOptions() (*disk.EncodeOptions, error) {
	encOpts := &disk.EncodeOptions{}
	switch packCompression {
	case "zlib":
		encOpts.Compression = disk.CompressionZlib
	case "none":
		encOpts.Compression = disk.CompressionNone
	default:
		return nil, usageErrorf("invalid --compression %q: must be zlib or none", packCompression)
	}
	if packChunkKiB == 0 || (packChunkKiB*1024)%512 != 0 {
		return nil, usageErrorf("invalid --chunk-size %d KiB: must be a positive multiple of 512 bytes", packChunkKiB)
	}
	encOpts.ChunkSectors = uint64(packChunkKiB) * 1024 / 512
	return encOpts, nil
}

// packDirectory writes srcDir into a new volume (HFS+ or APFS) and wraps it in
// a DMG.
func packDirectory(srcDir, dstPath string, encOpts *disk.EncodeOptions) error {
	volname := packVolumeName
	if volname == "" {
		volname = filepath.Base(filepath.Clean(srcDir))
		if volname == "." || volname == string(filepath.Separator) {
			volname = "Untitled"
		}
	}

	switch strings.ToLower(packFS) {
	case "hfs+", "hfsx":
		return packDirectoryHFS(srcDir, dstPath, volname, encOpts)
	case "apfs":
		return packDirectoryAPFS(srcDir, dstPath, volname, encOpts)
	default:
		return usageErrorf("invalid --fs %q: must be HFS+ or APFS", packFS)
	}
}

// packDirectoryHFS writes srcDir into a new HFS+ volume and wraps it in a DMG.
func packDirectoryHFS(srcDir, dstPath, volname string, encOpts *disk.EncodeOptions) error {
	volumeUUID, err := packUUIDs.resolveVolumeOnly("HFS+")
	if err != nil {
		return err
	}
	fixed, clamp := writerTimes()

	// Walk before writing, so --strict can refuse without leaving a file behind.
	root, report, err := hfsplus.EntryTreeFromDir(srcDir, &hfsplus.WalkOptions{
		Xattrs: true,
		Warn:   fidelityWarner(),
	})
	if err != nil {
		return fmt.Errorf("unable to read %s: %w", srcDir, err)
	}
	if err := enforceStrict(report, packStrict, srcDir); err != nil {
		return err
	}

	img, err := newScratchImage(dstPath)
	if err != nil {
		return err
	}
	defer img.Close()

	createOpts := &hfsplus.CreateOptions{FixedTime: fixed, ClampModTimes: clamp, VolumeUUID: volumeUUID}
	if err := hfsplus.CreateImage(img, 0, volname, root, createOpts); err != nil {
		return fmt.Errorf("unable to build HFS+ volume from %s: %w", srcDir, err)
	}

	if err := disk.WrapRawImageDMGFrom(dstPath, img, img.Size(), "Apple_HFS", encOpts); err != nil {
		return fmt.Errorf("unable to write DMG %s: %w", dstPath, err)
	}

	return packReport(srcDir, dstPath, img.Size(), report)
}

// packRepack recompresses an existing DMG preserving its block layout.
func packRepack(srcPath, dstPath string, encOpts *disk.EncodeOptions) error {
	// A repack copies the source's file system image through unchanged, so
	// there is no writer to hand a UUID to. Say so rather than accepting the
	// flag and silently doing nothing with it.
	if packUUIDs.changed() {
		return usageErrorf("the UUID flags apply only when packing a directory; %s is an existing image whose file system is copied through unchanged", srcPath)
	}
	if err := disk.RepackDMG(srcPath, dstPath, encOpts); err != nil {
		return fmt.Errorf("unable to repack %s: %w", srcPath, err)
	}
	srcInfo, _ := os.Stat(srcPath)
	srcSize := int64(0)
	if srcInfo != nil {
		srcSize = srcInfo.Size()
	}
	// A repack copies the file system image through bit-for-bit, so there is
	// nothing to lose and --strict passes trivially.
	return packReport(srcPath, dstPath, srcSize, nil)
}

func packReport(srcPath, dstPath string, srcSize int64, report *fidelity.Report) error {
	dstInfo, _ := os.Stat(dstPath)
	dstSize := int64(0)
	if dstInfo != nil {
		dstSize = dstInfo.Size()
	}

	if opts.Output == "json" {
		out := map[string]any{
			"source":           srcPath,
			"destination":      dstPath,
			"sourceBytes":      srcSize,
			"destinationBytes": dstSize,
		}
		for key, value := range report.JSON() {
			out[key] = value
		}
		if err := jsonOut(out); err != nil {
			return err
		}
		return fidelityExit(report)
	}
	if !opts.Quiet {
		fmt.Printf("Packed %s -> %s (%s)\n", srcPath, dstPath, formatSize(uint64(dstSize)))
	}
	printFidelityNotes(report)
	return fidelityExit(report)
}

// newScratchImage creates the temporary file a raw file system image is built
// into before being wrapped in a DMG.
//
// It goes beside the output by default rather than in the system temporary
// directory. That directory is often small, and on many Linux images it is
// tmpfs — backed by RAM — so building a large image there would reproduce the
// very memory problem the scratch file exists to avoid. The output directory,
// by contrast, is somewhere the user has already committed to holding an image
// of this size. --temp-dir overrides it.
func newScratchImage(dstPath string) (*imagefile.File, error) {
	dir := opts.TempDir
	if dir == "" {
		dir = filepath.Dir(dstPath)
	}
	// Dot-prefixed so a file left behind by a hard kill is hidden and obviously
	// transient rather than looking like an output.
	return imagefile.New(dir, ".apfs-image-*.tmp")
}

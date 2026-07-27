// apfs pack SOURCE OUT.dmg — build a DMG from a directory (HFS+), or repack an
// existing DMG/raw image.
package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/spf13/cobra"
)

var (
	packCompression string
	packChunkKiB    uint
	packVolumeName  string
	packFS          string
	packSnapshot    string
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

Examples:
  apfs pack ./mytree out.dmg --volname "My Data"   # directory -> HFS+ DMG
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
	var buf writeAtBuffer
	if err := hfsplus.CreateImageFromDir(&buf, 0, volname, srcDir, nil); err != nil {
		return fmt.Errorf("unable to build HFS+ volume from %s: %w", srcDir, err)
	}

	if err := disk.WrapRawImageDMG(dstPath, buf.Bytes(), "Apple_HFS", encOpts); err != nil {
		return fmt.Errorf("unable to write DMG %s: %w", dstPath, err)
	}

	return packReport(srcDir, dstPath, int64(len(buf.Bytes())))
}

// packRepack recompresses an existing DMG preserving its block layout.
func packRepack(srcPath, dstPath string, encOpts *disk.EncodeOptions) error {
	if err := disk.RepackDMG(srcPath, dstPath, encOpts); err != nil {
		return fmt.Errorf("unable to repack %s: %w", srcPath, err)
	}
	srcInfo, _ := os.Stat(srcPath)
	srcSize := int64(0)
	if srcInfo != nil {
		srcSize = srcInfo.Size()
	}
	return packReport(srcPath, dstPath, srcSize)
}

func packReport(srcPath, dstPath string, srcSize int64) error {
	dstInfo, _ := os.Stat(dstPath)
	dstSize := int64(0)
	if dstInfo != nil {
		dstSize = dstInfo.Size()
	}

	if opts.Output == "json" {
		return jsonOut(map[string]any{
			"source":           srcPath,
			"destination":      dstPath,
			"sourceBytes":      srcSize,
			"destinationBytes": dstSize,
		})
	}
	if !opts.Quiet {
		fmt.Printf("Packed %s -> %s (%s)\n", srcPath, dstPath, formatSize(uint64(dstSize)))
	}
	return nil
}

// writeAtBuffer is a growable in-memory io.WriterAt used to capture a raw
// file system image before wrapping it in a DMG.
type writeAtBuffer struct {
	buf bytes.Buffer
}

func (w *writeAtBuffer) WriteAt(p []byte, off int64) (int, error) {
	end := off + int64(len(p))
	if int64(w.buf.Len()) < end {
		w.buf.Write(make([]byte, end-int64(w.buf.Len())))
	}
	copy(w.buf.Bytes()[off:end], p)
	return len(p), nil
}

func (w *writeAtBuffer) Bytes() []byte { return w.buf.Bytes() }

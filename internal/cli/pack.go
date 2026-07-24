// apfs pack SOURCE OUT.dmg — repack a DMG (or its raw image) into a new DMG.
package cli

import (
	"fmt"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/spf13/cobra"
)

var (
	packCompression string
	packChunkKiB    uint
)

var packCmd = &cobra.Command{
	Use:   "pack SOURCE OUT.dmg",
	Short: "Repack a DMG into a new DMG (lossless at the filesystem-image level)",
	Long: `Repack SOURCE into a new UDIF DMG at OUT.dmg. SOURCE is an existing
DMG whose exact block layout is preserved while its chunks are recompressed.

The repacked DMG is not byte-identical to the original — different compressors
produce different container bytes and sizes — but the raw filesystem image it
contains round-trips bit-for-bit, and the result mounts under both this tool
and macOS.

Examples:
  apfs pack original.dmg repacked.dmg
  apfs pack original.dmg smaller.dmg --compression none   # store uncompressed`,
	Args: exactArgs(2, "SOURCE OUT.dmg"),
	RunE: runPack,
}

func init() {
	packCmd.Flags().StringVar(&packCompression, "compression", "zlib", "chunk compression: zlib or none")
	packCmd.Flags().UintVar(&packChunkKiB, "chunk-size", 1024, "chunk size in KiB (must be a multiple of 512 bytes)")
}

func runPack(cmd *cobra.Command, args []string) error {
	srcPath := args[0]
	dstPath := args[1]

	if _, err := os.Stat(srcPath); err != nil {
		return withCode(ExitBadImage, fmt.Errorf("unable to open source: %w", err))
	}

	encOpts := &disk.EncodeOptions{}
	switch packCompression {
	case "zlib":
		encOpts.Compression = disk.CompressionZlib
	case "none":
		encOpts.Compression = disk.CompressionNone
	default:
		return usageErrorf("invalid --compression %q: must be zlib or none", packCompression)
	}

	if packChunkKiB == 0 || (packChunkKiB*1024)%512 != 0 {
		return usageErrorf("invalid --chunk-size %d KiB: must be a positive multiple of 512 bytes", packChunkKiB)
	}
	encOpts.ChunkSectors = uint64(packChunkKiB) * 1024 / 512

	if err := disk.RepackDMG(srcPath, dstPath, encOpts); err != nil {
		return fmt.Errorf("unable to repack %s: %w", srcPath, err)
	}

	srcInfo, _ := os.Stat(srcPath)
	dstInfo, _ := os.Stat(dstPath)

	if opts.Output == "json" {
		summary := map[string]any{"source": srcPath, "destination": dstPath}
		if srcInfo != nil {
			summary["sourceBytes"] = srcInfo.Size()
		}
		if dstInfo != nil {
			summary["destinationBytes"] = dstInfo.Size()
		}
		return jsonOut(summary)
	}

	if !opts.Quiet && srcInfo != nil && dstInfo != nil {
		fmt.Printf("Repacked %s (%s) -> %s (%s)\n",
			srcPath, formatSize(uint64(srcInfo.Size())),
			dstPath, formatSize(uint64(dstInfo.Size())))
	}

	return nil
}

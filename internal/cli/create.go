// apfs create OUT.dmg — create an empty formatted volume in a new DMG.
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/spf13/cobra"
)

var (
	createFS       string
	createVolName  string
	createSizeMiB  uint
	createCaseSens bool
	createSnapshot string
	createUUIDs    writeIdentityFlags
)

var createCmd = &cobra.Command{
	Use:   "create OUT.dmg",
	Short: "Create a new DMG containing an empty formatted volume",
	Long: `Create a new UDIF DMG at OUT.dmg containing a freshly formatted, empty
volume (no files). This is the format/mkfs operation.

--fs hfs+  creates an empty HFS+ (HFSX) volume.
--fs apfs  creates an empty APFS container.

Examples:
  apfs create blank.dmg --fs hfs+ --volname Scratch --size 16
  apfs create blank.dmg --fs apfs --volname Data`,
	Args: exactArgs(1, "OUT.dmg"),
	RunE: runCreate,
}

func init() {
	createCmd.Flags().StringVar(&createFS, "fs", "apfs", "file system to create: APFS or HFS+ (case-insensitive)")
	createCmd.Flags().StringVar(&createVolName, "volname", "untitled", "volume name")
	createCmd.Flags().UintVar(&createSizeMiB, "size", 0, "image size in MiB (0 = minimum for the file system)")
	createCmd.Flags().BoolVar(&createCaseSens, "case-sensitive", false, "create a case-sensitive volume")
	createCmd.Flags().StringVar(&createSnapshot, "snapshot", "", "APFS only: also create a snapshot with this name capturing the new volume")
	createUUIDs.register(createCmd)
}

func runCreate(cmd *cobra.Command, args []string) error {
	dstPath := args[0]

	var sizeBytes int64
	if createSizeMiB > 0 {
		sizeBytes = int64(createSizeMiB) * 1024 * 1024
	}

	switch strings.ToLower(createFS) {
	case "hfs+", "hfsx":
		return createHFS(dstPath, sizeBytes)
	case "apfs":
		return createAPFS(dstPath, sizeBytes)
	default:
		return usageErrorf("invalid --fs %q: must be APFS or HFS+", createFS)
	}
}

// createHFS writes an empty HFS+ volume wrapped in a DMG (MIT).
func createHFS(dstPath string, sizeBytes int64) error {
	volumeUUID, err := createUUIDs.resolveVolumeOnly("HFS+")
	if err != nil {
		return err
	}
	fixed, clamp := writerTimes()

	root := &hfsplus.Entry{Name: createVolName, Mode: os.ModeDir | 0755}
	var buf writeAtBuffer
	createOpts := &hfsplus.CreateOptions{FixedTime: fixed, ClampModTimes: clamp, VolumeUUID: volumeUUID}
	if err := hfsplus.CreateImage(&buf, sizeBytes, createVolName, root, createOpts); err != nil {
		return fmt.Errorf("unable to create HFS+ volume: %w", err)
	}
	if err := disk.WrapRawImageDMG(dstPath, buf.Bytes(), "Apple_HFS", nil); err != nil {
		return fmt.Errorf("unable to write DMG: %w", err)
	}
	return createReport(dstPath, "hfs+")
}

func createReport(dstPath, fsName string) error {
	info, _ := os.Stat(dstPath)
	size := int64(0)
	if info != nil {
		size = info.Size()
	}
	if opts.Output == "json" {
		return jsonOut(map[string]any{
			"destination": dstPath,
			"fileSystem":  fsName,
			"volume":      createVolName,
			"bytes":       size,
		})
	}
	if !opts.Quiet {
		fmt.Printf("Created empty %s volume %q -> %s (%s)\n", fsName, createVolName, dstPath, formatSize(uint64(size)))
	}
	return nil
}

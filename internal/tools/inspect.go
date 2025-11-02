package tools

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/internal/apfs"
	"github.com/spf13/cobra"
)

// InspectCmd represents the inspect command
var InspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect APFS container structure in detail",
	Long: `Inspect command walks through the APFS container structure step-by-step,
validating checksums, showing checkpoint descriptors, object maps, and B-trees.

This is similar to 'info' but provides more detailed diagnostic output,
showing the exact steps taken to mount a volume and locate objects.`,
	RunE: runInspect,
}

var (
	inspectContainer string
	inspectVolume    int
	inspectVerbose   bool
)

func init() {
	InspectCmd.PersistentFlags().StringVar(&inspectContainer, "container", "", "Path to the APFS container (required)")
	InspectCmd.PersistentFlags().IntVar(&inspectVolume, "volume", -1, "Volume index to inspect (optional, -1 for all)")
	InspectCmd.PersistentFlags().BoolVar(&inspectVerbose, "verbose", false, "Enable verbose output")
	InspectCmd.MarkPersistentFlagRequired("container")
}

func runInspect(cmd *cobra.Command, args []string) error {
	// Open the container file
	fmt.Printf("Opening container: %s\n\n", inspectContainer)
	fileHandle, err := os.Open(inspectContainer)
	if err != nil {
		return fmt.Errorf("unable to open container: %w", err)
	}
	defer fileHandle.Close()

	// Read block 0
	blockSize := uint32(4096) // Default, will be updated from actual superblock
	block0Data := make([]byte, blockSize)
	if _, err := fileHandle.ReadAt(block0Data, 0); err != nil {
		return fmt.Errorf("failed to read block 0: %w", err)
	}

	// Print block 0 header
	fmt.Println("╭─ Container Superblock (Block 0) ─────────────────────────────────╮")
	printContainerSuperblock(block0Data)
	fmt.Println("╰──────────────────────────────────────────────────────────────────╯")
	fmt.Println()

	// Parse container
	ioHandle, err := apfs.NewIOHandle()
	if err != nil {
		return fmt.Errorf("unable to create IO handle: %w", err)
	}

	container, err := apfs.NewContainer(ioHandle)
	if err != nil {
		return fmt.Errorf("unable to create container: %w", err)
	}
	if err := container.OpenRead(fileHandle, 0); err != nil {
		return fmt.Errorf("unable to parse container: %w", err)
	}

	// Print checkpoint and container info
	nxsb := container.Superblock
	xpDescBlocks := nxsb.CheckpointDescriptorAreaNumberOfBlocks & ^uint32(1<<31)

	fmt.Println("  Container Structure")
	fmt.Printf("    %-30s  %d blocks\n", "Checkpoint descriptor area", xpDescBlocks)
	fmt.Printf("    %-30s  %#x\n", "Checkpoint base address", nxsb.CheckpointDescriptorAreaBlockNumber)
	fmt.Printf("    %-30s  %#x\n", "Object map physical OID", nxsb.ObjectMapBlockNumber)
	fmt.Println()

	// List volumes
	volumeOIDs, err := nxsb.GetVolumeObjectIdentifiers()
	if err != nil {
		return fmt.Errorf("unable to get volume object identifiers: %w", err)
	}
	numVolumes := len(volumeOIDs)

	fmt.Printf("  Volumes: %d\n", numVolumes)
	for i := 0; i < numVolumes; i++ {
		fmt.Printf("    Volume %d OID: %#x\n", i, volumeOIDs[i])
	}
	fmt.Println()

	// Inspect each volume (or specific volume if requested)
	startVol, endVol := 0, numVolumes
	if inspectVolume >= 0 {
		if inspectVolume >= numVolumes {
			return fmt.Errorf("volume index %d out of range (0-%d)", inspectVolume, numVolumes-1)
		}
		startVol, endVol = inspectVolume, inspectVolume+1
	}

	for volIdx := startVol; volIdx < endVol; volIdx++ {
		// Get volume
		volume, err := container.GetVolume(volIdx)
		if err != nil {
			fmt.Printf("Error: unable to get volume %d: %v\n\n", volIdx, err)
			continue
		}

		vsb := volume.Superblock

		// Extract volume name
		volumeName := string(vsb.VolumeName[:])
		for i, b := range vsb.VolumeName {
			if b == 0 {
				volumeName = string(vsb.VolumeName[:i])
				break
			}
		}

		// Print boxed header like info tool
		headerText := fmt.Sprintf("Volume %d", volIdx)
		if volumeName != "" {
			headerText += fmt.Sprintf(": %s", volumeName)
		}
		uuid := formatVolumeUUID(vsb.VolumeIdentifier[:])

		boxWidth := max(len(headerText), len("UUID: "+uuid)) + 2
		fmt.Printf("╭─%s─╮\n", repeatChar('─', boxWidth))
		fmt.Printf("│ %-*s │\n", boxWidth, headerText)
		fmt.Printf("│ %-*s │\n", boxWidth, "UUID: "+uuid)
		fmt.Printf("╰─%s─╯\n\n", repeatChar('─', boxWidth))

		// Storage section
		fmt.Println("  Storage")
		volumeSize, _ := volume.GetSize()
		fmt.Printf("    %-30s  %s (%s bytes)\n", "Size", formatBytes(volumeSize), formatNumber(volumeSize))
		fmt.Printf("    %-30s  %s\n", "Allocated blocks", formatNumber(vsb.NumberOfAllocatedBlocks))
		fmt.Printf("    %-30s  %s\n", "Reserved blocks", formatNumber(vsb.NumberOfReservedBlocks))
		fmt.Printf("    %-30s  %s\n", "Quota blocks", formatNumber(vsb.NumberOfQuotaBlocks))

		totalAllocated, _ := vsb.GetTotalBlocksAllocated()
		totalFreed, _ := vsb.GetTotalBlocksFreed()
		fmt.Printf("    %-30s  %s\n", "Total blocks allocated ever", formatNumber(totalAllocated))
		fmt.Printf("    %-30s  %s\n", "Total blocks freed ever", formatNumber(totalFreed))
		fmt.Println()

		// Contents section
		fmt.Println("  Contents")
		numFiles, _ := vsb.GetNumberOfFiles()
		numDirs, _ := vsb.GetNumberOfDirectories()
		numSymlinks, _ := vsb.GetNumberOfSymlinks()
		numSnapshots, _ := vsb.GetNumberOfSnapshots()

		fmt.Printf("    %-30s  %s\n", "Files", formatNumber(numFiles))
		fmt.Printf("    %-30s  %s\n", "Directories", formatNumber(numDirs))
		fmt.Printf("    %-30s  %s\n", "Symlinks", formatNumber(numSymlinks))
		if numSnapshots > 0 {
			fmt.Printf("    %-30s  %s\n", "Snapshots", formatNumber(numSnapshots))
		}

		// Try to get root directory
		if rootEntry, err := volume.GetRootDirectory(); err == nil {
			if numRootEntries, err := rootEntry.GetNumberOfSubFileEntries(); err == nil {
				fmt.Printf("    %-30s  %s entries\n", "Root directory", formatNumber(uint64(numRootEntries)))
			}
		}
		fmt.Println()

		// Features section
		fmt.Println("  Features")
		compatFeatures, _ := volume.GetCompatibleFeatureNames()
		for _, feature := range compatFeatures {
			fmt.Printf("    ✓ %s\n", feature)
		}
		incompatFeatures, _ := volume.GetIncompatibleFeatureNames()
		for _, feature := range incompatFeatures {
			fmt.Printf("    ✓ %s\n", feature)
		}
		roCompatFeatures, _ := volume.GetReadOnlyCompatibleFeatureNames()
		for _, feature := range roCompatFeatures {
			fmt.Printf("    ✓ %s\n", feature)
		}
		fmt.Println()

		// Metadata section
		fmt.Println("  Metadata")
		fmt.Printf("    %-30s  %#x\n", "Object map OID", vsb.ObjectMapBlockNumber)
		fmt.Printf("    %-30s  %#x\n", "File-system tree root OID", vsb.FileSystemRootObjectIdentifier)
		caseInsensitive := (vsb.IncompatibleFeaturesFlags & 0x00000001) != 0
		caseSensitive := "Yes"
		if caseInsensitive {
			caseSensitive = "No"
		}
		fmt.Printf("    %-30s  %s\n", "Case sensitive", caseSensitive)
		encrypted := (vsb.IncompatibleFeaturesFlags & 0x00000004) != 0
		encryptedStr := "No"
		if encrypted {
			encryptedStr = "Yes"
		}
		fmt.Printf("    %-30s  %s\n", "Encrypted", encryptedStr)
		fmt.Printf("    %-30s  %s\n", "Formatted by", vsb.GetFormattedBy())
		fmt.Printf("    %-30s  %s\n", "Last modified by", vsb.GetLastModifiedBy())
		fmt.Println()

		// Modification History section
		modHistory := vsb.GetModifiedByHistory()
		if len(modHistory) > 1 {
			fmt.Println("  Modification History")
			for i, entry := range modHistory {
				if i == 0 {
					fmt.Printf("    %-30s  %s\n", "Most recent", entry)
				} else {
					fmt.Printf("    %-30s  %s\n", fmt.Sprintf("Previous (%d)", i), entry)
				}
			}
			fmt.Println()
		}
	}

	return nil
}

func printContainerSuperblock(data []byte) {
	// Parse basic fields
	magic := binary.LittleEndian.Uint32(data[32:36])
	blockSize := binary.LittleEndian.Uint32(data[36:40])
	blockCount := binary.LittleEndian.Uint64(data[40:48])

	fmt.Printf("  %-30s  %#x\n", "Magic", magic)
	fmt.Printf("  %-30s  %s bytes\n", "Block size", formatNumber(uint64(blockSize)))
	fmt.Printf("  %-30s  %s blocks\n", "Block count", formatNumber(blockCount))
}

func formatVolumeUUID(uuid []byte) string {
	if len(uuid) != 16 {
		return "(invalid UUID)"
	}
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3],
		uuid[4], uuid[5],
		uuid[6], uuid[7],
		uuid[8], uuid[9],
		uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15])
}

// Helper functions formatNumber, repeatChar, max, and formatBytes
// are already defined in info_handle.go and shared within the tools package

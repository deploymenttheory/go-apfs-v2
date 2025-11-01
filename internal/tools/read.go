package tools

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/internal/apfs"
	"github.com/spf13/cobra"
)

// ReadCmd represents the read command
var ReadCmd = &cobra.Command{
	Use:   "read",
	Short: "Read and display information about a specific block",
	Long: `Read a block from the APFS container and display information about it.

This command reads a specific block by its physical address and attempts to
interpret it based on its object type. It displays the object header, validates
checksums, and shows the block's raw data.

Example:
  apfs read --container /dev/disk0s2 --block 0x1234
  apfs read --container /dev/disk0s2 --block 1000 --verbose`,
	RunE: runRead,
}

var (
	readBlockAddr     uint64
	readContainerPath string
	readVerbose       bool
)

func init() {
	ReadCmd.Flags().Uint64VarP(&readBlockAddr, "block", "b", 0, "Block address to read (required)")
	ReadCmd.Flags().StringVarP(&readContainerPath, "container", "c", "", "Path to APFS container (required)")
	ReadCmd.Flags().BoolVarP(&readVerbose, "verbose", "v", false, "Enable verbose output")

	ReadCmd.MarkFlagRequired("block")
	ReadCmd.MarkFlagRequired("container")
}

// runRead executes the read command
func runRead(cmd *cobra.Command, args []string) error {
	// Open the container file
	file, err := os.Open(readContainerPath)
	if err != nil {
		return fmt.Errorf("unable to open container: %w", err)
	}
	defer file.Close()

	// Read block 0 to get block size
	block0 := make([]byte, 4096) // Start with default block size
	if _, err := file.ReadAt(block0, 0); err != nil {
		return fmt.Errorf("unable to read block 0: %w", err)
	}

	// Parse block size from container superblock
	// Block size is at offset 36 (4 bytes)
	blockSize := binary.LittleEndian.Uint32(block0[36:40])

	if readVerbose {
		fmt.Printf("Container block size: %d bytes\n", blockSize)
		fmt.Printf("Reading block at address: 0x%x (%d)\n\n", readBlockAddr, readBlockAddr)
	}

	// Calculate offset and read the requested block
	offset := int64(readBlockAddr) * int64(blockSize)
	blockData := make([]byte, blockSize)

	if _, err := file.ReadAt(blockData, offset); err != nil {
		if err == io.EOF {
			return fmt.Errorf("block address 0x%x is beyond container size", readBlockAddr)
		}
		return fmt.Errorf("unable to read block at 0x%x: %w", readBlockAddr, err)
	}

	// Display block information
	if err := displayBlockInfo(blockData, readBlockAddr, readVerbose); err != nil {
		return err
	}

	return nil
}

// displayBlockInfo analyzes and displays information about a block
func displayBlockInfo(blockData []byte, blockAddr uint64, verbose bool) error {
	if len(blockData) < 32 {
		return fmt.Errorf("block data too small (< 32 bytes)")
	}

	// Parse object header
	checksum := binary.LittleEndian.Uint64(blockData[0:8])
	objectID := binary.LittleEndian.Uint64(blockData[8:16])
	transactionID := binary.LittleEndian.Uint64(blockData[16:24])
	objectType := binary.LittleEndian.Uint32(blockData[24:28])
	objectSubtype := binary.LittleEndian.Uint32(blockData[28:32])

	// Display header information
	fmt.Println("╭─────────────────────────────────────────────────────╮")
	fmt.Printf("│ Block: 0x%-42x │\n", blockAddr)
	fmt.Println("╰─────────────────────────────────────────────────────╯")
	fmt.Println()

	fmt.Println("  Object Header")
	fmt.Printf("    %-20s  0x%016x\n", "Checksum", checksum)
	fmt.Printf("    %-20s  0x%016x (%d)\n", "Object ID", objectID, objectID)
	fmt.Printf("    %-20s  0x%016x (%d)\n", "Transaction ID", transactionID, transactionID)
	fmt.Printf("    %-20s  0x%08x (%s)\n", "Object Type", objectType, getObjectTypeName(objectType))
	fmt.Printf("    %-20s  0x%08x (%s)\n", "Object Subtype", objectSubtype, getObjectSubtypeName(objectSubtype))
	fmt.Println()

	// Validate checksum (Fletcher-64)
	// Save original checksum and zero it out for calculation
	blockDataCopy := make([]byte, len(blockData))
	copy(blockDataCopy, blockData)
	binary.LittleEndian.PutUint64(blockDataCopy[0:8], 0)

	calculatedChecksum, err := apfs.CalculateFletcher64(blockDataCopy, 0)
	if err != nil {
		fmt.Printf("  ! Unable to calculate checksum: %v\n", err)
	} else if calculatedChecksum == checksum {
		fmt.Println("  ✓ Checksum valid")
	} else {
		fmt.Printf("  ✗ Checksum invalid (expected: 0x%016x, calculated: 0x%016x)\n", checksum, calculatedChecksum)
	}
	fmt.Println()

	// Display type-specific information
	if err := displayTypeSpecificInfo(blockData, objectType, objectSubtype, verbose); err != nil {
		fmt.Printf("  Warning: Unable to parse type-specific data: %v\n\n", err)
	}

	// Display raw data if verbose
	if verbose {
		fmt.Println("  Raw Block Data")
		fmt.Println("  " + hex.Dump(blockData))
	}

	return nil
}

// displayTypeSpecificInfo displays information specific to the object type
func displayTypeSpecificInfo(blockData []byte, objectType, objectSubtype uint32, verbose bool) error {
	baseType := objectType & 0x0000FFFF

	switch baseType {
	case 0x0001: // NX_SUPERBLOCK
		return displayContainerSuperblock(blockData, verbose)
	case 0x0002: // BTREE_NODE (generic)
		return displayBTreeNode(blockData, verbose)
	case 0x0003: // SPACEMAN
		return displaySpaceManager(blockData, verbose)
	case 0x0009: // OMAP
		return displayObjectMap(blockData, verbose)
	case 0x000B: // FS (Volume Superblock)
		return displayVolumeSuperblock(blockData, verbose)
	case 0x000C: // FSTREE (Filesystem B-tree)
		return displayFSTree(blockData, verbose)
	case 0x000D: // BLOCKREFTREE
		return displayBTreeNode(blockData, verbose) // Generic B-tree display
	case 0x000E: // SNAPMETATREE
		return displayBTreeNode(blockData, verbose) // Generic B-tree display
	default:
		if verbose {
			fmt.Printf("  Type-specific parsing not implemented for type 0x%08x\n", objectType)
		}
		return nil
	}
}

// displayContainerSuperblock displays container superblock information
func displayContainerSuperblock(blockData []byte, verbose bool) error {
	if len(blockData) < 200 {
		return fmt.Errorf("insufficient data for container superblock")
	}

	magic := binary.LittleEndian.Uint32(blockData[32:36])
	blockSize := binary.LittleEndian.Uint32(blockData[36:40])
	blockCount := binary.LittleEndian.Uint64(blockData[40:48])

	fmt.Println("  Container Superblock")
	fmt.Printf("    %-20s  0x%08x (%c%c%c%c)\n", "Magic", magic,
		blockData[32], blockData[33], blockData[34], blockData[35])
	fmt.Printf("    %-20s  %d bytes\n", "Block size", blockSize)
	fmt.Printf("    %-20s  %d (%s)\n", "Block count", blockCount, formatNumber(blockCount))

	if verbose {
		features := binary.LittleEndian.Uint64(blockData[48:56])
		readOnlyFeatures := binary.LittleEndian.Uint64(blockData[56:64])
		incompatFeatures := binary.LittleEndian.Uint64(blockData[64:72])

		fmt.Printf("    %-20s  0x%016x\n", "Features", features)
		fmt.Printf("    %-20s  0x%016x\n", "Read-only features", readOnlyFeatures)
		fmt.Printf("    %-20s  0x%016x\n", "Incompat features", incompatFeatures)
	}

	fmt.Println()
	return nil
}

// displayBTreeNode displays B-tree node information
func displayBTreeNode(blockData []byte, verbose bool) error {
	if len(blockData) < 56 {
		return fmt.Errorf("insufficient data for B-tree node")
	}

	// Parse B-tree node header (starts at offset 32, after obj_phys_t)
	flags := binary.LittleEndian.Uint16(blockData[32:34])
	level := binary.LittleEndian.Uint16(blockData[34:36])
	keyCount := binary.LittleEndian.Uint32(blockData[36:40])
	tableSpaceOff := binary.LittleEndian.Uint16(blockData[40:42])
	tableSpaceLen := binary.LittleEndian.Uint16(blockData[42:44])
	freeSpaceOff := binary.LittleEndian.Uint16(blockData[44:46])
	freeSpaceLen := binary.LittleEndian.Uint16(blockData[46:48])

	fmt.Println("  B-Tree Node")
	fmt.Printf("    %-25s  0x%04x", "Flags", flags)

	// Decode flags
	var flagStrs []string
	if flags&0x0001 != 0 {
		flagStrs = append(flagStrs, "ROOT")
	}
	if flags&0x0002 != 0 {
		flagStrs = append(flagStrs, "LEAF")
	}
	if flags&0x0004 != 0 {
		flagStrs = append(flagStrs, "FIXED_KV_SIZE")
	}
	if flags&0x0008 != 0 {
		flagStrs = append(flagStrs, "HASHED")
	}
	if flags&0x0010 != 0 {
		flagStrs = append(flagStrs, "NOHEADER")
	}
	if flags&0x8000 != 0 {
		flagStrs = append(flagStrs, "CHECK_KOFF_INVAL")
	}

	if len(flagStrs) > 0 {
		fmt.Printf(" (%s)", formatList(flagStrs))
	}
	fmt.Println()

	// Node type
	nodeType := "Index node"
	if flags&0x0001 != 0 && flags&0x0002 != 0 {
		nodeType = "Root+Leaf node"
	} else if flags&0x0001 != 0 {
		nodeType = "Root node"
	} else if flags&0x0002 != 0 {
		nodeType = "Leaf node"
	}
	fmt.Printf("    %-25s  %s\n", "Node type", nodeType)

	fmt.Printf("    %-25s  %d\n", "Level", level)
	fmt.Printf("    %-25s  %d\n", "Key count", keyCount)

	if verbose {
		fmt.Printf("    %-25s  offset: %d, length: %d\n", "Table space", tableSpaceOff, tableSpaceLen)
		fmt.Printf("    %-25s  offset: %d, length: %d\n", "Free space", freeSpaceOff, freeSpaceLen)
	}

	fmt.Println()
	return nil
}

// displaySpaceManager displays space manager information
func displaySpaceManager(blockData []byte, verbose bool) error {
	fmt.Println("  Space Manager")
	fmt.Println("    (Detailed parsing not yet implemented)")
	fmt.Println()
	return nil
}

// displayObjectMap displays object map information
func displayObjectMap(blockData []byte, verbose bool) error {
	if len(blockData) < 64 {
		return fmt.Errorf("insufficient data for object map")
	}

	flags := binary.LittleEndian.Uint32(blockData[32:36])
	snapshotCount := binary.LittleEndian.Uint32(blockData[36:40])
	treeType := binary.LittleEndian.Uint32(blockData[40:44])
	snapshotTreeType := binary.LittleEndian.Uint32(blockData[44:48])
	treeOID := binary.LittleEndian.Uint64(blockData[48:56])
	snapshotTreeOID := binary.LittleEndian.Uint64(blockData[56:64])

	fmt.Println("  Object Map")
	fmt.Printf("    %-25s  0x%08x\n", "Flags", flags)
	fmt.Printf("    %-25s  %d\n", "Snapshot count", snapshotCount)
	fmt.Printf("    %-25s  0x%08x (%s)\n", "Tree type", treeType, getObjectTypeName(treeType))
	fmt.Printf("    %-25s  0x%08x (%s)\n", "Snapshot tree type", snapshotTreeType, getObjectTypeName(snapshotTreeType))
	fmt.Printf("    %-25s  0x%016x\n", "Tree OID", treeOID)
	if snapshotTreeOID != 0 {
		fmt.Printf("    %-25s  0x%016x\n", "Snapshot tree OID", snapshotTreeOID)
	}
	fmt.Println()
	return nil
}

// displayFSTree displays filesystem B-tree information
func displayFSTree(blockData []byte, verbose bool) error {
	fmt.Println("  Filesystem B-Tree")

	// First display the B-tree node structure
	if err := displayBTreeNode(blockData, verbose); err != nil {
		return err
	}

	// If verbose, try to parse and display the entries
	if verbose {
		if err := displayBTreeEntries(blockData); err != nil {
			fmt.Printf("    Warning: Unable to parse B-tree entries: %v\n", err)
		}
	}

	return nil
}

// displayBTreeEntries attempts to parse and display B-tree key-value entries
func displayBTreeEntries(blockData []byte) error {
	if len(blockData) < 56 {
		return fmt.Errorf("insufficient data")
	}

	// Parse header
	flags := binary.LittleEndian.Uint16(blockData[32:34])
	keyCount := binary.LittleEndian.Uint32(blockData[36:40])
	tableSpaceOff := binary.LittleEndian.Uint16(blockData[40:42])
	tableSpaceLen := binary.LittleEndian.Uint16(blockData[42:44])

	if keyCount == 0 {
		return nil
	}

	fmt.Println("\n  B-Tree Entries:")
	fmt.Printf("    Entry count: %d\n", keyCount)
	fmt.Printf("    Table space: offset %d, length %d\n", tableSpaceOff, tableSpaceLen)

	// Check if this is a fixed or variable key/value size node
	hasFixedKV := (flags & 0x0004) != 0

	// The btree_node_phys_t header is 56 bytes, btn_data starts there
	// The TOC starts at btn_data + table_space.off
	btnDataStart := 56
	tocOffset := btnDataStart + int(tableSpaceOff)

	if hasFixedKV {
		fmt.Println("    Format: Fixed key-value size")
		// For fixed size, TOC contains offsets (kvoff_t) relative to btn_data
		for i := uint32(0); i < keyCount && tocOffset+4 <= len(blockData); i++ {
			keyOff := binary.LittleEndian.Uint16(blockData[tocOffset : tocOffset+2])
			valOff := binary.LittleEndian.Uint16(blockData[tocOffset+2 : tocOffset+4])
			keyAbsoluteOff := btnDataStart + int(keyOff)
			valAbsoluteOff := btnDataStart + int(valOff)
			fmt.Printf("      Entry %d: key offset=%d (abs: %d), val offset=%d (abs: %d)\n",
				i, keyOff, keyAbsoluteOff, valOff, valAbsoluteOff)
			tocOffset += 4
		}
	} else {
		fmt.Println("    Format: Variable key-value size")
		// For variable size, TOC contains offset+length (kvloc_t)
		for i := uint32(0); i < keyCount && tocOffset+8 <= len(blockData); i++ {
			keyOff := binary.LittleEndian.Uint16(blockData[tocOffset : tocOffset+2])
			keyLen := binary.LittleEndian.Uint16(blockData[tocOffset+2 : tocOffset+4])
			valOff := binary.LittleEndian.Uint16(blockData[tocOffset+4 : tocOffset+6])
			valLen := binary.LittleEndian.Uint16(blockData[tocOffset+6 : tocOffset+8])

			fmt.Printf("      Entry %d:\n", i)
			fmt.Printf("        Key: offset=%d, length=%d\n", keyOff, keyLen)
			fmt.Printf("        Val: offset=%d, length=%d\n", valOff, valLen)

			// Per drat: key_start = toc_start + toc_len, keys are relative to key_start
			// Values are relative to val_end (grow backward from end)
			keyStart := btnDataStart + int(tableSpaceOff) + int(tableSpaceLen)
			keyAbsoluteOff := keyStart + int(keyOff)
			valAbsoluteOff := len(blockData) - int(valOff)
			if flags&0x0001 != 0 { // ROOT node has footer
				valAbsoluteOff -= 40 // sizeof(btree_info_t)
			}

			// Try to parse the key (j_key_t: first 8 bytes is obj_id_and_type)
			if keyAbsoluteOff+8 <= len(blockData) && keyLen >= 8 {
				objIDAndType := binary.LittleEndian.Uint64(blockData[keyAbsoluteOff : keyAbsoluteOff+8])
				objID := objIDAndType & 0x0FFFFFFFFFFFFFFF
				objType := (objIDAndType >> 60) & 0xF
				fmt.Printf("        Key: FSOID=%d, type=0x%x (%s)\n", objID, objType, getFSObjectTypeName(objType))
			}

			// For leaf nodes, show value data
			if flags&0x0002 != 0 && valAbsoluteOff+int(valLen) <= len(blockData) && valLen > 0 {
				// Show first few bytes of value
				maxShow := int(valLen)
				if maxShow > 32 {
					maxShow = 32
				}
				fmt.Printf("        Val data (first %d bytes): %x\n", maxShow, blockData[valAbsoluteOff:valAbsoluteOff+maxShow])
			}

			tocOffset += 8
		}
	}

	return nil
}

// getFSObjectTypeName returns the name of a filesystem object type
func getFSObjectTypeName(objType uint64) string {
	switch objType {
	case 0x0:
		return "ANY"
	case 0x1:
		return "SNAP_METADATA"
	case 0x2:
		return "EXTENT"
	case 0x3:
		return "INODE"
	case 0x4:
		return "XATTR"
	case 0x5:
		return "SIBLING_LINK"
	case 0x6:
		return "DSTREAM_ID"
	case 0x7:
		return "CRYPTO_STATE"
	case 0x8:
		return "FILE_EXTENT"
	case 0x9:
		return "DIR_REC"
	case 0xA:
		return "DIR_STATS"
	case 0xB:
		return "SNAP_NAME"
	case 0xC:
		return "SIBLING_MAP"
	case 0xD:
		return "FILE_INFO"
	default:
		return fmt.Sprintf("UNKNOWN_0x%x", objType)
	}
}

// formatList formats a string slice as a comma-separated list
func formatList(items []string) string {
	if len(items) == 0 {
		return ""
	}
	result := items[0]
	for i := 1; i < len(items); i++ {
		result += ", " + items[i]
	}
	return result
}

// displayVolumeSuperblock displays volume superblock information
func displayVolumeSuperblock(blockData []byte, verbose bool) error {
	if len(blockData) < 200 {
		return fmt.Errorf("insufficient data for volume superblock")
	}

	magic := binary.LittleEndian.Uint32(blockData[32:36])
	fsIndex := binary.LittleEndian.Uint32(blockData[36:40])
	features := binary.LittleEndian.Uint64(blockData[40:48])

	fmt.Println("  Volume Superblock")
	fmt.Printf("    %-20s  0x%08x (%c%c%c%c)\n", "Magic", magic,
		blockData[32], blockData[33], blockData[34], blockData[35])
	fmt.Printf("    %-20s  %d\n", "FS Index", fsIndex)
	fmt.Printf("    %-20s  0x%016x\n", "Features", features)

	if verbose {
		roFeatures := binary.LittleEndian.Uint64(blockData[48:56])
		incompatFeatures := binary.LittleEndian.Uint64(blockData[56:64])

		fmt.Printf("    %-20s  0x%016x\n", "Read-only features", roFeatures)
		fmt.Printf("    %-20s  0x%016x\n", "Incompat features", incompatFeatures)
	}

	fmt.Println()
	return nil
}

// getObjectTypeName returns a human-readable name for an object type
func getObjectTypeName(objectType uint32) string {
	typeValue := objectType & 0x0000FFFF

	names := map[uint32]string{
		0x0000: "INVALID",
		0x0001: "NX_SUPERBLOCK",
		0x0002: "BTREE_NODE",
		0x0003: "SPACEMAN",
		0x0004: "SPACEMAN_CAB",
		0x0005: "SPACEMAN_CIB",
		0x0006: "SPACEMAN_BITMAP",
		0x0007: "SPACEMAN_FREE_QUEUE",
		0x0008: "EXTENT_LIST_TREE",
		0x0009: "OMAP",
		0x000A: "CHECKPOINT_MAP",
		0x000B: "FS",
		0x000C: "FSTREE",
		0x000D: "BLOCKREFTREE",
		0x000E: "SNAPMETATREE",
		0x000F: "NX_REAPER",
		0x0010: "NX_REAP_LIST",
		0x0011: "OMAP_SNAPSHOT",
		0x0012: "EFI_JUMPSTART",
		0x0013: "FUSION_MIDDLE_TREE",
		0x0014: "NX_FUSION_WBC",
		0x0015: "NX_FUSION_WBC_LIST",
		0x0016: "ER_STATE",
		0x0017: "GBITMAP",
		0x0018: "GBITMAP_TREE",
		0x0019: "GBITMAP_BLOCK",
	}

	if name, ok := names[typeValue]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN_%d", typeValue)
}

// getObjectSubtypeName returns a human-readable name for an object subtype
func getObjectSubtypeName(objectSubtype uint32) string {
	if objectSubtype == 0 {
		return "NONE"
	}
	return fmt.Sprintf("SUBTYPE_%d", objectSubtype)
}

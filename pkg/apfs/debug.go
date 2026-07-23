// Debug functions for APFS
//go:build debug
// +build debug

package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
)

// Debug output enabled flag
// Deprecated: Use SetVerbose() and IsVerbose() instead
var DebugOutput = true

// PrintBTreeFlags prints the B-tree flags for debugging
// Corresponds to libfsapfs_debug_print_btree_flags
func PrintBTreeFlags(btreeFlags uint32) {
	if !IsVerbose() {
		return
	}

	if (btreeFlags & 0x00000001) != 0 {
		Printf("\t(BTREE_UINT64_KEYS)\n")
	}
	if (btreeFlags & 0x00000002) != 0 {
		Printf("\t(BTREE_SEQUENTIAL_INSERT)\n")
	}
	if (btreeFlags & 0x00000004) != 0 {
		Printf("\t(BTREE_ALLOW_GHOSTS)\n")
	}
	if (btreeFlags & 0x00000008) != 0 {
		Printf("\t(BTREE_EPHEMERAL)\n")
	}
	if (btreeFlags & 0x00000010) != 0 {
		Printf("\t(BTREE_PHYSICAL)\n")
	}
	if (btreeFlags & 0x00000020) != 0 {
		Printf("\t(BTREE_NONPERSISTENT)\n")
	}
	if (btreeFlags & 0x00000040) != 0 {
		Printf("\t(BTREE_KV_NONALIGNED)\n")
	}
	if (btreeFlags & 0x00000080) != 0 {
		Printf("\t(BTREE_HASHED)\n")
	}
	if (btreeFlags & 0x00000100) != 0 {
		Printf("\tHas no object header (BTREE_NOHEADER)\n")
	}
}

// PrintBTreeNodeFlags prints the B-tree node flags for debugging
// Corresponds to libfsapfs_debug_print_btree_node_flags
func PrintBTreeNodeFlags(btreeNodeFlags uint16) {
	if !IsVerbose() {
		return
	}

	if (btreeNodeFlags & 0x0001) != 0 {
		Printf("\tIs root (BTNODE_ROOT)\n")
	}
	if (btreeNodeFlags & 0x0002) != 0 {
		Printf("\tIs leaf (BTNODE_LEAF)\n")
	}
	if (btreeNodeFlags & 0x0004) != 0 {
		Printf("\tHas fixed-size entry (BTNODE_FIXED_KV_SIZE)\n")
	}
	if (btreeNodeFlags & 0x0008) != 0 {
		Printf("\t(BTNODE_HASHED)\n")
	}
	if (btreeNodeFlags & 0x0010) != 0 {
		Printf("\t(BTNODE_NOHEADER)\n")
	}
	if (btreeNodeFlags & 0x8000) != 0 {
		Printf("\tIn transient state (BTNODE_CHECK_KOFF_INVAL)\n")
	}
}

// PrintCheckpointFlags prints the checkpoint flags for debugging
// Corresponds to libfsapfs_debug_print_checkpoint_flags
func PrintCheckpointFlags(checkpointFlags uint32) {
	if !IsVerbose() {
		return
	}

	if (checkpointFlags & 0x00000001) != 0 {
		Printf("\t(CHECKPOINT_MAP_LAST)\n")
	}
}

// PrintContainerCompatibleFeaturesFlags prints the container compatible feature flags
// Corresponds to libfsapfs_debug_print_container_compatible_features_flags
func PrintContainerCompatibleFeaturesFlags(compatibleFeaturesFlags uint64) {
	if !IsVerbose() {
		return
	}

	if (compatibleFeaturesFlags & 0x0000000000000001) != 0 {
		Printf("\t(NX_FEATURE_DEFRAG)\n")
	}
	if (compatibleFeaturesFlags & 0x0000000000000002) != 0 {
		Printf("\t(NX_FEATURE_LCFD)\n")
	}
}

// PrintContainerIncompatibleFeaturesFlags prints the container incompatible feature flags
// Corresponds to libfsapfs_debug_print_container_incompatible_features_flags
func PrintContainerIncompatibleFeaturesFlags(incompatibleFeaturesFlags uint64) {
	if !IsVerbose() {
		return
	}

	if (incompatibleFeaturesFlags & 0x0000000000000001) != 0 {
		Printf("\t(NX_INCOMPAT_VERSION1)\n")
	}
	if (incompatibleFeaturesFlags & 0x0000000000000002) != 0 {
		Printf("\t(NX_INCOMPAT_VERSION2)\n")
	}
	if (incompatibleFeaturesFlags & 0x0000000000000100) != 0 {
		Printf("\t(NX_INCOMPAT_FUSION)\n")
	}
}

// PrintContainerReadOnlyCompatibleFeaturesFlags prints the container read-only compatible feature flags
// Corresponds to libfsapfs_debug_print_container_read_only_compatible_features_flags
func PrintContainerReadOnlyCompatibleFeaturesFlags(readOnlyCompatibleFeaturesFlags uint64) {
	if !IsVerbose() {
		return
	}
	// Currently there are no container read-only compatible feature flags defined
	_ = readOnlyCompatibleFeaturesFlags
}

// PrintDirectoryEntryFlags prints the directory entry flags for debugging
// Corresponds to libfsapfs_debug_print_directory_entry_flags
func PrintDirectoryEntryFlags(directoryEntryFlags uint16) {
	if !IsVerbose() {
		return
	}

	switch directoryEntryFlags & 0x000f {
	case 0x0000:
		Printf("\t(DT_UNKNOWN)\n")
	case 0x0001:
		Printf("\t(DT_FIFO)\n")
	case 0x0002:
		Printf("\t(DT_CHR)\n")
	case 0x0004:
		Printf("\t(DT_DIR)\n")
	case 0x0006:
		Printf("\t(DT_BLK)\n")
	case 0x0008:
		Printf("\t(DT_REG)\n")
	case 0x000a:
		Printf("\t(DT_LNK)\n")
	case 0x000c:
		Printf("\t(DT_SOCK)\n")
	case 0x000e:
		Printf("\t(DT_WHT)\n")
	default:
		Printf("\tUnknown: 0x%04x\n", directoryEntryFlags&0x000f)
	}

	if (directoryEntryFlags & 0x0010) != 0 {
		Printf("\t(RESERVED_10)\n")
	}
}

// PrintExtendedAttributeFlags prints the extended attribute flags for debugging
// Corresponds to libfsapfs_debug_print_extended_attribute_flags
func PrintExtendedAttributeFlags(extendedAttributeFlags uint16) {
	if !IsVerbose() {
		return
	}

	if (extendedAttributeFlags & 0x0001) != 0 {
		Printf("\t(XATTR_DATA_STREAM)\n")
	}
	if (extendedAttributeFlags & 0x0002) != 0 {
		Printf("\t(XATTR_DATA_EMBEDDED)\n")
	}
	if (extendedAttributeFlags & 0x0004) != 0 {
		Printf("\t(XATTR_FILE_SYSTEM_OWNED)\n")
	}
	if (extendedAttributeFlags & 0x0008) != 0 {
		Printf("\t(XATTR_RESERVED_8)\n")
	}
}

// PrintExtendedFieldFlags prints the extended field flags for debugging
// Corresponds to libfsapfs_debug_print_extended_field_flags
func PrintExtendedFieldFlags(extendedFieldFlags uint8) {
	if !IsVerbose() {
		return
	}

	if (extendedFieldFlags & 0x01) != 0 {
		Printf("\t(XF_DATA_DEPENDENT)\n")
	}
	if (extendedFieldFlags & 0x02) != 0 {
		Printf("\t(XF_DO_NOT_COPY)\n")
	}
	if (extendedFieldFlags & 0x04) != 0 {
		Printf("\t(XF_RESERVED_4)\n")
	}
	if (extendedFieldFlags & 0x08) != 0 {
		Printf("\t(XF_CHILDREN_INHERIT)\n")
	}
	if (extendedFieldFlags & 0x10) != 0 {
		Printf("\t(XF_USER_FIELD)\n")
	}
	if (extendedFieldFlags & 0x20) != 0 {
		Printf("\t(XF_SYSTEM_FIELD)\n")
	}
	if (extendedFieldFlags & 0x40) != 0 {
		Printf("\t(XF_RESERVED_40)\n")
	}
	if (extendedFieldFlags & 0x80) != 0 {
		Printf("\t(XF_RESERVED_80)\n")
	}
}

// PrintInodeFlags prints the inode flags for debugging
// Corresponds to libfsapfs_debug_print_inode_flags
func PrintInodeFlags(inodeFlags uint64) {
	if !IsVerbose() {
		return
	}

	if (inodeFlags & 0x00000001) != 0 {
		Printf("\t(INODE_IS_APFS_PRIVATE)\n")
	}
	if (inodeFlags & 0x00000002) != 0 {
		Printf("\t(INODE_MAINTAIN_DIR_STATS)\n")
	}
	if (inodeFlags & 0x00000004) != 0 {
		Printf("\t(INODE_DIR_STATS_ORIGIN)\n")
	}
	if (inodeFlags & 0x00000008) != 0 {
		Printf("\t(INODE_PROT_CLASS_EXPLICIT)\n")
	}
	if (inodeFlags & 0x00000010) != 0 {
		Printf("\t(INODE_WAS_CLONED)\n")
	}
	if (inodeFlags & 0x00000020) != 0 {
		Printf("\t(INODE_FLAG_UNUSED)\n")
	}
	if (inodeFlags & 0x00000040) != 0 {
		Printf("\t(INODE_HAS_SECURITY_EA)\n")
	}
	if (inodeFlags & 0x00000080) != 0 {
		Printf("\t(INODE_BEING_TRUNCATED)\n")
	}
	if (inodeFlags & 0x00000100) != 0 {
		Printf("\t(INODE_HAS_FINDER_INFO)\n")
	}
	if (inodeFlags & 0x00000200) != 0 {
		Printf("\t(INODE_IS_SPARSE)\n")
	}
	if (inodeFlags & 0x00000400) != 0 {
		Printf("\t(INODE_WAS_EVER_CLONED)\n")
	}
	if (inodeFlags & 0x00000800) != 0 {
		Printf("\t(INODE_ACTIVE_FILE_TRIMMED)\n")
	}
	if (inodeFlags & 0x00001000) != 0 {
		Printf("\t(INODE_PINNED_TO_MAIN)\n")
	}
	if (inodeFlags & 0x00002000) != 0 {
		Printf("\t(INODE_PINNED_TO_TIER2)\n")
	}
	if (inodeFlags & 0x00004000) != 0 {
		Printf("\t(INODE_HAS_RSRC_FORK)\n")
	}
	if (inodeFlags & 0x00008000) != 0 {
		Printf("\t(INODE_NO_RSRC_FORK)\n")
	}
	if (inodeFlags & 0x00010000) != 0 {
		Printf("\t(INODE_ALLOCATION_SPILLEDOVER)\n")
	}
}

// PrintVolumeCompatibleFeaturesFlags prints the volume compatible feature flags
// Corresponds to libfsapfs_debug_print_volume_compatible_features_flags
func PrintVolumeCompatibleFeaturesFlags(compatibleFeaturesFlags uint64) {
	if !IsVerbose() {
		return
	}

	if (compatibleFeaturesFlags & 0x0000000000000001) != 0 {
		Printf("\t(APFS_FEATURE_DEFRAG_PRERELEASE)\n")
	}
	if (compatibleFeaturesFlags & 0x0000000000000002) != 0 {
		Printf("\t(APFS_FEATURE_HARDLINK_MAP_RECORDS)\n")
	}
	if (compatibleFeaturesFlags & 0x0000000000000004) != 0 {
		Printf("\t(APFS_FEATURE_DEFRAG)\n")
	}
	if (compatibleFeaturesFlags & 0x0000000000000008) != 0 {
		Printf("\t(APFS_FEATURE_STRICTATIME)\n")
	}
	if (compatibleFeaturesFlags & 0x0000000000000010) != 0 {
		Printf("\t(APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE)\n")
	}
}

// PrintVolumeFlags prints the volume flags for debugging
// Corresponds to libfsapfs_debug_print_volume_flags
func PrintVolumeFlags(volumeFlags uint64) {
	if !IsVerbose() {
		return
	}

	if (volumeFlags & 0x0000000000000001) != 0 {
		Printf("\t(APFS_FS_UNENCRYPTED)\n")
	}
	if (volumeFlags & 0x0000000000000002) != 0 {
		Printf("\t(APFS_FS_EFFACEABLE)\n")
	}
	if (volumeFlags & 0x0000000000000004) != 0 {
		Printf("\t(APFS_FS_RESERVED_4)\n")
	}
	if (volumeFlags & 0x0000000000000008) != 0 {
		Printf("\t(APFS_FS_ONEKEY)\n")
	}
	if (volumeFlags & 0x0000000000000010) != 0 {
		Printf("\t(APFS_FS_SPILLEDOVER)\n")
	}
	if (volumeFlags & 0x0000000000000020) != 0 {
		Printf("\t(APFS_FS_RUN_SPILLOVER_CLEANER)\n")
	}
}

// PrintVolumeIncompatibleFeaturesFlags prints the volume incompatible feature flags
// Corresponds to libfsapfs_debug_print_volume_incompatible_features_flags
func PrintVolumeIncompatibleFeaturesFlags(incompatibleFeaturesFlags uint64) {
	if !IsVerbose() {
		return
	}

	if (incompatibleFeaturesFlags & 0x0000000000000001) != 0 {
		Printf("\t(APFS_INCOMPAT_CASE_INSENSITIVE)\n")
	}
	if (incompatibleFeaturesFlags & 0x0000000000000002) != 0 {
		Printf("\t(APFS_INCOMPAT_DATALESS_SNAPS)\n")
	}
	if (incompatibleFeaturesFlags & 0x0000000000000004) != 0 {
		Printf("\t(APFS_INCOMPAT_ENC_ROLLED)\n")
	}
	if (incompatibleFeaturesFlags & 0x0000000000000008) != 0 {
		Printf("\t(APFS_INCOMPAT_NORMALIZATION_INSENSITIVE)\n")
	}
	if (incompatibleFeaturesFlags & 0x0000000000000010) != 0 {
		Printf("\t(APFS_INCOMPAT_INCOMPLETE_RESTORE)\n")
	}
	if (incompatibleFeaturesFlags & 0x0000000000000020) != 0 {
		Printf("\t(APFS_INCOMPAT_SEALED_VOLUME)\n")
	}
}

// PrintVolumeReadOnlyCompatibleFeaturesFlags prints the volume read-only compatible feature flags
// Corresponds to libfsapfs_debug_print_volume_read_only_compatible_features_flags
func PrintVolumeReadOnlyCompatibleFeaturesFlags(readOnlyCompatibleFeaturesFlags uint64) {
	if !IsVerbose() {
		return
	}
	// Currently there are no volume read-only compatible feature flags defined
	_ = readOnlyCompatibleFeaturesFlags
}

// GetFileSystemDataTypeName returns the name of the file system data type
// Corresponds to libfsapfs_debug_print_file_system_data_type
func GetFileSystemDataTypeName(fileSystemDataType uint8) string {
	switch fileSystemDataType {
	case 0:
		return "(APFS_TYPE_ANY)"
	case 1:
		return "(APFS_TYPE_SNAP_METADATA)"
	case 2:
		return "(APFS_TYPE_EXTENT)"
	case 3:
		return "(APFS_TYPE_INODE)"
	case 4:
		return "(APFS_TYPE_XATTR)"
	case 5:
		return "(APFS_TYPE_SIBLING_LINK)"
	case 6:
		return "(APFS_TYPE_DSTREAM_ID)"
	case 7:
		return "(APFS_TYPE_CRYPTO_STATE)"
	case 8:
		return "(APFS_TYPE_FILE_EXTENT)"
	case 9:
		return "(APFS_TYPE_DIR_REC)"
	case 10:
		return "(APFS_TYPE_DIR_STATS)"
	case 11:
		return "(APFS_TYPE_SNAP_NAME)"
	case 12:
		return "(APFS_TYPE_SIBLING_MAP)"
	}
	return "Unknown"
}

// GetDirectoryRecordExtendedFieldTypeName returns the name of the directory record extended field type
// Corresponds to libfsapfs_debug_print_directory_record_extended_field_type
func GetDirectoryRecordExtendedFieldTypeName(extendedFieldType uint8) string {
	switch extendedFieldType {
	case 1:
		return "(DREC_EXT_TYPE_SIBLING_ID)"
	}
	return "Unknown"
}

// GetInodeExtendedFieldTypeName returns the name of the inode extended field type
// Corresponds to libfsapfs_debug_print_inode_extended_field_type
func GetInodeExtendedFieldTypeName(extendedFieldType uint8) string {
	switch extendedFieldType {
	case 1:
		return "(INO_EXT_TYPE_SNAP_XID)"
	case 2:
		return "(INO_EXT_TYPE_DELTA_TREE_OID)"
	case 3:
		return "(INO_EXT_TYPE_DOCUMENT_ID)"
	case 4:
		return "(INO_EXT_TYPE_NAME)"
	case 5:
		return "(INO_EXT_TYPE_PREV_FSIZE)"
	case 6:
		return "(INO_EXT_TYPE_RESERVED_6)"
	case 7:
		return "(INO_EXT_TYPE_FINDER_INFO)"
	case 8:
		return "(INO_EXT_TYPE_DSTREAM)"
	case 9:
		return "(INO_EXT_TYPE_RESERVED_9)"
	case 10:
		return "(INO_EXT_TYPE_DIR_STATS_KEY)"
	case 11:
		return "(INO_EXT_TYPE_FS_UUID)"
	case 12:
		return "(INO_EXT_TYPE_RESERVED_12)"
	case 13:
		return "(INO_EXT_TYPE_SPARSE_BYTES)"
	case 14:
		return "(INO_EXT_TYPE_RDEV)"
	case 15:
		return "(INO_EXT_TYPE_PURGEABLE_FLAGS)"
	case 16:
		return "(INO_EXT_TYPE_ORIG_SYNC_ROOT_ID)"
	}
	return "Unknown"
}

// PrintPOSIXTimeValue prints a POSIX time value for debugging
// Corresponds to libfsapfs_debug_print_posix_time_value
func PrintPOSIXTimeValue(functionName, valueName string, byteStream []byte, byteOrder binary.ByteOrder, valueType string) error {
	if !IsVerbose() {
		return nil
	}

	if len(byteStream) < 8 {
		return fmt.Errorf("invalid byte stream size: %d", len(byteStream))
	}

	var timestamp int64
	if byteOrder == binary.LittleEndian {
		timestamp = int64(binary.LittleEndian.Uint64(byteStream))
	} else {
		timestamp = int64(binary.BigEndian.Uint64(byteStream))
	}

	// Handle nanosecond timestamps (APFS uses nanoseconds since epoch)
	var t time.Time
	if valueType == "nanoseconds" {
		t = time.Unix(0, timestamp)
	} else {
		t = time.Unix(timestamp, 0)
	}

	Printf("%s: %s: %s UTC\n", functionName, valueName, t.UTC().Format("2006-01-02 15:04:05"))

	return nil
}

// PrintGUIDValue prints a GUID/UUID value for debugging
// Corresponds to libfsapfs_debug_print_guid_value
func PrintGUIDValue(functionName, valueName string, byteStream []byte, byteOrder binary.ByteOrder) error {
	if !IsVerbose() {
		return nil
	}

	if len(byteStream) < 16 {
		return fmt.Errorf("invalid byte stream size for GUID: %d", len(byteStream))
	}

	// Parse UUID from byte stream
	var guidBytes [16]byte
	copy(guidBytes[:], byteStream[:16])

	// Handle byte order for UUID parsing
	// UUIDs are stored in mixed-endian format in APFS
	if byteOrder == binary.LittleEndian {
		// Swap first three groups (time_low, time_mid, time_hi_and_version)
		guidBytes[0], guidBytes[3] = guidBytes[3], guidBytes[0]
		guidBytes[1], guidBytes[2] = guidBytes[2], guidBytes[1]
		guidBytes[4], guidBytes[5] = guidBytes[5], guidBytes[4]
		guidBytes[6], guidBytes[7] = guidBytes[7], guidBytes[6]
	}

	guid, err := uuid.FromBytes(guidBytes[:])
	if err != nil {
		return fmt.Errorf("unable to parse GUID: %w", err)
	}

	Printf("%s: %s: %s\n", functionName, valueName, guid.String())

	return nil
}

// PrintReadOffsets prints the read offsets for debugging I/O operations
// Corresponds to libfsapfs_debug_print_read_offsets
func PrintReadOffsets(fileIOHandle io.ReaderAt, offsets []struct{ Offset, Size int64 }) error {
	if !IsVerbose() {
		return nil
	}

	if fileIOHandle == nil {
		return fmt.Errorf("invalid file IO handle")
	}

	Printf("Offsets read:\n")

	for i, offset := range offsets {
		Printf("%08d ( 0x%08x ) - %08d ( 0x%08x ) size: %d\n",
			offset.Offset,
			offset.Offset,
			offset.Offset+offset.Size,
			offset.Offset+offset.Size,
			offset.Size)

		_ = i // avoid unused variable
	}

	Printf("\n")

	return nil
}

// PrintData prints data in hexadecimal format for debugging
// Corresponds to libcnotify_print_data
func PrintData(data []byte, groupData bool) {
	if !IsVerbose() {
		return
	}

	stream := GetStream()

	const bytesPerLine = 16
	for i := 0; i < len(data); i += bytesPerLine {
		end := i + bytesPerLine
		if end > len(data) {
			end = len(data)
		}

		Printf("\t%08x: ", i)

		for j := i; j < end; j++ {
			Printf("%02x ", data[j])
			if groupData && (j-i+1)%8 == 0 && j < end-1 {
				Printf(" ")
			}
		}

		remainder := bytesPerLine - (end - i)
		for j := 0; j < remainder; j++ {
			Printf("   ")
		}
		if groupData && remainder > 0 {
			Printf(" ")
		}

		Printf(" |")
		for j := i; j < end; j++ {
			if data[j] >= 32 && data[j] <= 126 {
				Printf("%c", data[j])
			} else {
				Printf(".")
			}
		}
		Printf("|\n")
	}

	_ = stream // Mark as used
}

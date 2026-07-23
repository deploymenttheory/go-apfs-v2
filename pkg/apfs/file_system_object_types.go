package apfs

// Filesystem object type constants
const (
	APFS_TYPE_ANY           = 0x0
	APFS_TYPE_SNAP_METADATA = 0x1
	APFS_TYPE_EXTENT        = 0x2
	APFS_TYPE_INODE         = 0x3
	APFS_TYPE_XATTR         = 0x4
	APFS_TYPE_SIBLING_LINK  = 0x5
	APFS_TYPE_DSTREAM_ID    = 0x6
	APFS_TYPE_CRYPTO_STATE  = 0x7
	APFS_TYPE_FILE_EXTENT   = 0x8
	APFS_TYPE_DIR_REC       = 0x9
	APFS_TYPE_DIR_STATS     = 0xA
	APFS_TYPE_SNAP_NAME     = 0xB
	APFS_TYPE_SIBLING_MAP   = 0xC
	APFS_TYPE_FILE_INFO     = 0xD
	APFS_TYPE_INVALID       = 0xF
)

// GetFSObjectTypeName returns the human-readable name for a filesystem object type
func GetFSObjectTypeName(objType uint8) string {
	switch objType {
	case 0x0:
		return "APFS_TYPE_ANY"
	case 0x1:
		return "APFS_TYPE_SNAP_METADATA"
	case 0x2:
		return "APFS_TYPE_EXTENT"
	case 0x3:
		return "APFS_TYPE_INODE"
	case 0x4:
		return "APFS_TYPE_XATTR"
	case 0x5:
		return "APFS_TYPE_SIBLING_LINK"
	case 0x6:
		return "APFS_TYPE_DSTREAM_ID"
	case 0x7:
		return "APFS_TYPE_CRYPTO_STATE"
	case 0x8:
		return "APFS_TYPE_FILE_EXTENT"
	case 0x9:
		return "APFS_TYPE_DIR_REC"
	case 0xA:
		return "APFS_TYPE_DIR_STATS"
	case 0xB:
		return "APFS_TYPE_SNAP_NAME"
	case 0xC:
		return "APFS_TYPE_SIBLING_MAP"
	case 0xD:
		return "APFS_TYPE_FILE_INFO"
	case 0xF:
		return "APFS_TYPE_INVALID"
	default:
		return "UNKNOWN"
	}
}

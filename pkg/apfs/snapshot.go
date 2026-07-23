// Snapshot functions
// Corresponds to libfsapfs_snapshot.c and libfsapfs_snapshot.h
package apfs

import (
	"fmt"
	"io"
	"unicode/utf16"
)

// Snapshot represents an APFS snapshot
// Corresponds to libfsapfs_internal_snapshot_t
type Snapshot struct {
	// The volume superblock
	VolumeSuperblock *VolumeSuperblock

	// The IO handle
	IOHandle *IOHandle

	// The file IO handle
	FileIOHandle io.ReaderAt

	// The snapshot metadata
	SnapshotMetadata *SnapshotMetadata
}

// NewSnapshot creates a new snapshot
// Corresponds to libfsapfs_snapshot_initialize
func NewSnapshot(
	ioHandle *IOHandle,
	fileIOHandle io.ReaderAt,
	snapshotMetadata *SnapshotMetadata,
) (*Snapshot, error) {
	if ioHandle == nil {
		return nil, fmt.Errorf("invalid IO handle")
	}
	if fileIOHandle == nil {
		return nil, fmt.Errorf("invalid file IO handle")
	}
	if snapshotMetadata == nil {
		return nil, fmt.Errorf("invalid snapshot metadata")
	}

	return &Snapshot{
		VolumeSuperblock: nil, // Will be set when opened
		IOHandle:         ioHandle,
		FileIOHandle:     fileIOHandle,
		SnapshotMetadata: snapshotMetadata,
	}, nil
}

// Free releases resources associated with the snapshot
// Corresponds to libfsapfs_snapshot_free
func (s *Snapshot) Free() error {
	if s == nil {
		return fmt.Errorf("invalid snapshot")
	}

	// Set fields to nil to help garbage collection
	s.VolumeSuperblock = nil
	s.SnapshotMetadata = nil
	s.FileIOHandle = nil
	s.IOHandle = nil

	return nil
}

// OpenRead opens a snapshot for reading
// Corresponds to libfsapfs_internal_snapshot_open_read
func (s *Snapshot) OpenRead(fileHandle io.ReaderAt, fileOffset int64) error {
	if s == nil {
		return fmt.Errorf("invalid snapshot")
	}
	if s.IOHandle == nil {
		return fmt.Errorf("invalid snapshot - missing IO handle")
	}
	if s.VolumeSuperblock != nil {
		return fmt.Errorf("invalid snapshot - volume superblock already set")
	}

	if DebugOutput {
		fmt.Println("Reading volume superblock")
	}

	// Create volume superblock
	volumeSuperblock := NewVolumeSuperblock()
	if volumeSuperblock == nil {
		return fmt.Errorf("unable to create volume superblock")
	}

	// Read volume superblock
	if err := volumeSuperblock.ReadFileIOHandle(fileHandle, fileOffset, true); err != nil {
		return fmt.Errorf("unable to read volume superblock at offset %d (0x%08x): %w",
			fileOffset, fileOffset, err)
	}

	s.VolumeSuperblock = volumeSuperblock

	return nil
}

// Close closes a snapshot
// Corresponds to libfsapfs_internal_snapshot_close
func (s *Snapshot) Close() error {
	if s == nil {
		return fmt.Errorf("invalid snapshot")
	}
	if s.IOHandle == nil {
		return fmt.Errorf("invalid snapshot - missing IO handle")
	}

	// Clear file IO handle reference
	s.FileIOHandle = nil

	// Free volume superblock if allocated
	if s.VolumeSuperblock != nil {
		s.VolumeSuperblock = nil
	}

	return nil
}

// GetUTF8NameSize retrieves the size of the UTF-8 encoded name
// The returned size includes the end of string character
// Corresponds to libfsapfs_snapshot_get_utf8_name_size
func (s *Snapshot) GetUTF8NameSize() (int, error) {
	if s == nil {
		return 0, fmt.Errorf("invalid snapshot")
	}

	if s.SnapshotMetadata == nil {
		return 0, fmt.Errorf("invalid snapshot - missing snapshot metadata")
	}

	return s.SnapshotMetadata.GetUTF8NameSize()
}

// GetUTF8Name retrieves the UTF-8 encoded name
// Corresponds to libfsapfs_snapshot_get_utf8_name
func (s *Snapshot) GetUTF8Name() (string, error) {
	if s == nil {
		return "", fmt.Errorf("invalid snapshot")
	}

	if s.SnapshotMetadata == nil {
		return "", fmt.Errorf("invalid snapshot - missing snapshot metadata")
	}

	return s.SnapshotMetadata.GetUTF8Name()
}

// GetUTF16NameSize retrieves the size of the UTF-16 encoded name
// The returned size includes the end of string character
// Corresponds to libfsapfs_snapshot_get_utf16_name_size
func (s *Snapshot) GetUTF16NameSize() (int, error) {
	if s == nil {
		return 0, fmt.Errorf("invalid snapshot")
	}

	if s.SnapshotMetadata == nil {
		return 0, fmt.Errorf("invalid snapshot - missing snapshot metadata")
	}

	return s.SnapshotMetadata.GetUTF16NameSize()
}

// GetUTF16Name retrieves the UTF-16 encoded name
// Corresponds to libfsapfs_snapshot_get_utf16_name
func (s *Snapshot) GetUTF16Name() ([]uint16, error) {
	if s == nil {
		return nil, fmt.Errorf("invalid snapshot")
	}

	if s.SnapshotMetadata == nil {
		return nil, fmt.Errorf("invalid snapshot - missing snapshot metadata")
	}

	return s.SnapshotMetadata.GetUTF16Name()
}

// GetUTF8NameSize retrieves the size of the UTF-8 encoded name from snapshot metadata
// The returned size includes the end of string character
// Corresponds to libfsapfs_snapshot_metadata_get_utf8_name_size
func (m *SnapshotMetadata) GetUTF8NameSize() (int, error) {
	if m == nil {
		return 0, fmt.Errorf("invalid snapshot metadata")
	}

	// Return the length of the name plus 1 for null terminator
	return len(m.Name) + 1, nil
}

// GetUTF8Name retrieves the UTF-8 encoded name from snapshot metadata
// Corresponds to libfsapfs_snapshot_metadata_get_utf8_name
func (m *SnapshotMetadata) GetUTF8Name() (string, error) {
	if m == nil {
		return "", fmt.Errorf("invalid snapshot metadata")
	}

	return m.Name, nil
}

// GetUTF16NameSize retrieves the size of the UTF-16 encoded name from snapshot metadata
// The returned size includes the end of string character
// Corresponds to libfsapfs_snapshot_metadata_get_utf16_name_size
func (m *SnapshotMetadata) GetUTF16NameSize() (int, error) {
	if m == nil {
		return 0, fmt.Errorf("invalid snapshot metadata")
	}

	// Convert UTF-8 string to UTF-16
	runes := []rune(m.Name)
	utf16Data := utf16.Encode(runes)

	// Return the length plus 1 for null terminator
	return len(utf16Data) + 1, nil
}

// GetUTF16Name retrieves the UTF-16 encoded name from snapshot metadata
// Corresponds to libfsapfs_snapshot_metadata_get_utf16_name
func (m *SnapshotMetadata) GetUTF16Name() ([]uint16, error) {
	if m == nil {
		return nil, fmt.Errorf("invalid snapshot metadata")
	}

	// Convert UTF-8 string to UTF-16
	runes := []rune(m.Name)
	utf16Data := utf16.Encode(runes)

	// Add null terminator
	result := make([]uint16, len(utf16Data)+1)
	copy(result, utf16Data)
	result[len(utf16Data)] = 0

	return result, nil
}

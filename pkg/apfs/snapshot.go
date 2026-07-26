// Snapshot functions
package apfs

import (
	"fmt"
	"io"
	"unicode/utf16"
)

// Snapshot represents an APFS snapshot
type Snapshot struct {
	// The volume superblock
	VolumeSuperblock *VolumeSuperblock

	// The IO handle
	IOHandle *IOHandle

	// The file IO handle
	Reader io.ReaderAt

	// The snapshot metadata
	SnapshotMetadata *SnapshotMetadata
}

// NewSnapshot creates a new snapshot
func NewSnapshot(
	ioHandle *IOHandle,
	reader io.ReaderAt,
	snapshotMetadata *SnapshotMetadata,
) (*Snapshot, error) {
	if ioHandle == nil {
		return nil, fmt.Errorf("invalid IO handle")
	}
	if reader == nil {
		return nil, fmt.Errorf("invalid reader")
	}
	if snapshotMetadata == nil {
		return nil, fmt.Errorf("invalid snapshot metadata")
	}

	return &Snapshot{
		VolumeSuperblock: nil, // Will be set when opened
		IOHandle:         ioHandle,
		Reader:           reader,
		SnapshotMetadata: snapshotMetadata,
	}, nil
}

// Free releases resources associated with the snapshot
func (s *Snapshot) Free() error {
	if s == nil {
		return fmt.Errorf("invalid snapshot")
	}

	// Set fields to nil to help garbage collection
	s.VolumeSuperblock = nil
	s.SnapshotMetadata = nil
	s.Reader = nil
	s.IOHandle = nil

	return nil
}

// OpenRead opens a snapshot for reading
func (s *Snapshot) OpenRead(reader io.ReaderAt, fileOffset int64) error {
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
	if err := volumeSuperblock.ReadFrom(reader, fileOffset, true); err != nil {
		return fmt.Errorf("unable to read volume superblock at offset %d (0x%08x): %w",
			fileOffset, fileOffset, err)
	}

	s.VolumeSuperblock = volumeSuperblock

	return nil
}

// Close closes a snapshot
func (s *Snapshot) Close() error {
	if s == nil {
		return fmt.Errorf("invalid snapshot")
	}
	if s.IOHandle == nil {
		return fmt.Errorf("invalid snapshot - missing IO handle")
	}

	// Clear file IO handle reference
	s.Reader = nil

	// Free volume superblock if allocated
	if s.VolumeSuperblock != nil {
		s.VolumeSuperblock = nil
	}

	return nil
}

// GetUTF8NameSize retrieves the size of the UTF-8 encoded name
// The returned size includes the end of string character
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
func (m *SnapshotMetadata) GetUTF8NameSize() (int, error) {
	if m == nil {
		return 0, fmt.Errorf("invalid snapshot metadata")
	}

	// Return the length of the name plus 1 for null terminator
	return len(m.Name) + 1, nil
}

// GetUTF8Name retrieves the UTF-8 encoded name from snapshot metadata
func (m *SnapshotMetadata) GetUTF8Name() (string, error) {
	if m == nil {
		return "", fmt.Errorf("invalid snapshot metadata")
	}

	return m.Name, nil
}

// GetUTF16NameSize retrieves the size of the UTF-16 encoded name from snapshot metadata
// The returned size includes the end of string character
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

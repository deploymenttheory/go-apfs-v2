package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Container reaper object type
const ContainerReaperObjectType = 0x80000011

// ContainerReaper represents an APFS container reaper
// The reaper is used for tracking blocks to be freed
// Corresponds to libfsapfs_container_reaper_t
type ContainerReaper struct {
	// Dummy field - structure is currently not fully implemented
	// The reaper structure is read but not actively used in basic operations
	dummy int
}

// NewContainerReaper creates a new container reaper
// Corresponds to libfsapfs_container_reaper_initialize
func NewContainerReaper() (*ContainerReaper, error) {
	return &ContainerReaper{
		dummy: 0,
	}, nil
}

// Free releases resources associated with the container reaper
func (cr *ContainerReaper) Free() error {
	if cr == nil {
		return fmt.Errorf("invalid container reaper")
	}

	// Nothing to free currently
	return nil
}

// ReadFileIOHandle reads the container reaper from a file
// Corresponds to libfsapfs_container_reaper_read_file_io_handle
func (cr *ContainerReaper) ReadFileIOHandle(
	fileHandle io.ReaderAt,
	fileOffset int64,
) error {
	if cr == nil {
		return fmt.Errorf("invalid container reaper")
	}

	// Container reaper structure is 40 bytes (object header)
	data := make([]byte, 40)
	n, err := fileHandle.ReadAt(data, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read container reaper data at offset %d: %w", fileOffset, err)
	}
	if n != 40 {
		return fmt.Errorf("unable to read complete container reaper data: expected 40 bytes, got %d", n)
	}

	return cr.ReadData(data)
}

// ReadData reads the container reaper from data
// Corresponds to libfsapfs_container_reaper_read_data
func (cr *ContainerReaper) ReadData(data []byte) error {
	if cr == nil {
		return fmt.Errorf("invalid container reaper")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < 40 {
		return fmt.Errorf("invalid data size: expected at least 40 bytes, got %d", len(data))
	}

	// Read object type (offset 24)
	objectType := binary.LittleEndian.Uint32(data[24:28])
	if objectType != ContainerReaperObjectType {
		return fmt.Errorf("invalid object type: 0x%08x (expected 0x%08x)", objectType, ContainerReaperObjectType)
	}

	// Read object subtype (offset 28)
	objectSubtype := binary.LittleEndian.Uint32(data[28:32])
	if objectSubtype != 0x00000000 {
		return fmt.Errorf("invalid object subtype: 0x%08x", objectSubtype)
	}

	// Container reaper structure is currently minimal
	// The actual implementation would parse reaper-specific data here
	// For now, we just validate the object type

	return nil
}

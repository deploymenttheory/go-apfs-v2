// Input/Output (IO) handle functions
// Corresponds to libfsapfs_io_handle.c and libfsapfs_io_handle.h
package apfs

import "fmt"

// Container and volume signatures
// Corresponds to fsapfs_container_signature and fsapfs_volume_signature
var (
	ContainerSignature = [4]byte{'N', 'X', 'S', 'B'}
	VolumeSignature    = [4]byte{'A', 'P', 'S', 'B'}
)

// IOHandle represents the Input/Output handle for APFS operations
// Corresponds to libfsapfs_io_handle_t
type IOHandle struct {
	// The bytes per sector
	BytesPerSector uint16

	// The block size
	BlockSize uint32

	// The container size
	ContainerSize uint64

	// Value to indicate if abort was signalled
	Abort bool

	// The profiler (only available when built with profiler tag)
	Profiler *Profiler
}

// NewIOHandle creates a new IO handle with default values
// Corresponds to libfsapfs_io_handle_initialize
func NewIOHandle() (*IOHandle, error) {
	ioHandle := &IOHandle{
		BytesPerSector: 512,  // Default sector size
		BlockSize:      4096, // Default APFS block size (4KB)
		ContainerSize:  0,
		Abort:          false,
	}

	// Initialize profiler (conditionally compiled)
	profiler, err := NewProfiler()
	if err != nil {
		return nil, fmt.Errorf("unable to initialize profiler: %w", err)
	}

	if err := profiler.Open("profiler.csv"); err != nil {
		return nil, fmt.Errorf("unable to open profiler: %w", err)
	}

	ioHandle.Profiler = profiler

	return ioHandle, nil
}

// Clear resets the IO handle to default values
// Corresponds to libfsapfs_io_handle_clear
func (io *IOHandle) Clear() error {
	if io == nil {
		return nil
	}

	io.BytesPerSector = 512
	io.BlockSize = 4096
	io.ContainerSize = 0
	io.Abort = false

	return nil
}

// Free releases resources associated with the IO handle
// Corresponds to libfsapfs_io_handle_free
func (io *IOHandle) Free() error {
	if io == nil {
		return nil
	}

	// Close and free profiler if it exists
	if io.Profiler != nil {
		if err := io.Profiler.Close(); err != nil {
			return fmt.Errorf("unable to close profiler: %w", err)
		}
		if err := io.Profiler.Free(); err != nil {
			return fmt.Errorf("unable to free profiler: %w", err)
		}
		io.Profiler = nil
	}

	return nil
}

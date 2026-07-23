//go:build profiler
// +build profiler

// Profiler functions for performance measurement
// Corresponds to libfsapfs_profiler.c and libfsapfs_profiler.h
package apfs

import (
	"fmt"
	"os"
	"time"
)

// Profiler represents a performance profiler that writes timing data to a CSV file
// Corresponds to libfsapfs_profiler_t
type Profiler struct {
	outputStream *os.File
}

// NewProfiler creates a new profiler
// Corresponds to libfsapfs_profiler_initialize
func NewProfiler() (*Profiler, error) {
	return &Profiler{
		outputStream: nil,
	}, nil
}

// Free releases resources associated with the profiler
// Corresponds to libfsapfs_profiler_free
func (p *Profiler) Free() error {
	if p == nil {
		return fmt.Errorf("invalid profiler")
	}

	// Close the output stream if it's open
	if p.outputStream != nil {
		if err := p.Close(); err != nil {
			return err
		}
	}

	return nil
}

// Open opens the profiler output file
// Corresponds to libfsapfs_profiler_open
func (p *Profiler) Open(filename string) error {
	if p == nil {
		return fmt.Errorf("invalid profiler")
	}

	if p.outputStream != nil {
		return fmt.Errorf("invalid profiler - output stream value already set")
	}

	// Open the file for writing
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("unable to open profiler: %w", err)
	}

	p.outputStream = file

	// Write CSV header
	if _, err := fmt.Fprintf(p.outputStream, "timestamp,name,offset,size,duration\n"); err != nil {
		// Close the file on error
		file.Close()
		p.outputStream = nil
		return fmt.Errorf("unable to write header: %w", err)
	}

	return nil
}

// Close closes the profiler output file
// Corresponds to libfsapfs_profiler_close
func (p *Profiler) Close() error {
	if p == nil {
		return fmt.Errorf("invalid profiler")
	}

	if p.outputStream == nil {
		return fmt.Errorf("invalid profiler - missing output stream")
	}

	if err := p.outputStream.Close(); err != nil {
		return fmt.Errorf("unable to close profiler: %w", err)
	}

	p.outputStream = nil

	return nil
}

// StartTiming captures the start timestamp for a profiling measurement
// Corresponds to libfsapfs_profiler_start_timing
// Returns the start timestamp in nanoseconds
func (p *Profiler) StartTiming() (int64, error) {
	if p == nil {
		return 0, fmt.Errorf("invalid profiler")
	}

	// Get current time in nanoseconds
	now := time.Now()
	timestamp := now.UnixNano()

	return timestamp, nil
}

// StopTiming captures the stop timestamp and writes the profiling data
// Corresponds to libfsapfs_profiler_stop_timing
//
// Parameters:
//   - startTimestamp: The start timestamp from StartTiming (in nanoseconds)
//   - name: The name/description of the operation being profiled
//   - offset: The file offset being accessed
//   - size: The size of the data being processed
func (p *Profiler) StopTiming(startTimestamp int64, name string, offset int64, size uint64) error {
	if p == nil {
		return fmt.Errorf("invalid profiler")
	}

	if p.outputStream == nil {
		return fmt.Errorf("invalid profiler - missing output stream")
	}

	// Get current time
	now := time.Now()
	stopTimestamp := now.UnixNano()

	// Calculate duration
	duration := stopTimestamp - startTimestamp

	// Write the profiling data to the CSV file
	if _, err := fmt.Fprintf(p.outputStream, "%d,%s,%d,%d,%d\n",
		startTimestamp, name, offset, size, duration); err != nil {
		return fmt.Errorf("unable to write sample: %w", err)
	}

	return nil
}

// Package disk provides utilities for handling disk images (DMG)
package disk

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// OpenWithOffset opens a file and returns an io.ReaderAt for the APFS container
// If the file is a DMG, it returns a DMGReader with decompression support
// If it's a raw APFS container, it returns the file at offset 0
func OpenWithOffset(filename string) (reader io.ReaderAt, offset int64, closer io.Closer, err error) {
	// Check if it's a DMG by extension first
	if strings.HasSuffix(strings.ToLower(filename), ".dmg") {
		// Try to open as DMG with full decompression support
		dmgReader, err := OpenDMG(filename)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("unable to open DMG: %w", err)
		}
		return dmgReader, 0, dmgReader, nil
	}

	// Not a DMG, assume raw APFS container at offset 0
	file, err := os.Open(filename)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("unable to open file: %w", err)
	}

	return file, 0, file, nil
}

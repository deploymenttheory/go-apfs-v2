// Package disk provides utilities for handling disk images (DMG)
package disk

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// containerSignatureOffset is where the NXSB magic lives inside block 0 of an
// APFS container (after the 32-byte object header).
const containerSignatureOffset = 32

// OpenWithOffset opens a disk image and returns an io.ReaderAt for the APFS
// container plus the byte offset at which the container starts. The image
// format is detected from content, never from the filename:
//
//  1. UDIF "koly" trailer in the last 512 bytes -> DMG with on-the-fly
//     decompression (the returned reader is already partition-relative)
//  2. "NXSB" magic at offset 32 -> bare APFS container at offset 0
//  3. "EFI PART" GPT at LBA 1 -> raw image; offset of the Apple_APFS partition
//  4. otherwise -> assume a bare container at offset 0 (the superblock
//     checksum will reject non-APFS data with a clear error)
func OpenWithOffset(filename string) (reader io.ReaderAt, offset int64, closer io.Closer, err error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("unable to open file: %w", err)
	}

	// 1. DMG: UDIF images end with a 512-byte "koly" footer
	if stat, err := file.Stat(); err == nil && stat.Size() >= dmgFooterSize {
		sig := make([]byte, 4)
		if _, err := file.ReadAt(sig, stat.Size()-dmgFooterSize); err == nil && string(sig) == dmgSignature {
			file.Close()
			dmgReader, err := OpenDMG(filename)
			if err != nil {
				return nil, 0, nil, fmt.Errorf("unable to open DMG: %w", err)
			}
			return dmgReader, 0, dmgReader, nil
		}
	}

	// 2. Bare APFS container
	magic := make([]byte, 4)
	if _, err := file.ReadAt(magic, containerSignatureOffset); err == nil && string(magic) == "NXSB" {
		return file, 0, file, nil
	}

	// 3. GPT-partitioned raw image
	if partOffset, err := findAPFSPartitionInGPT(file); err == nil {
		return file, partOffset, file, nil
	}

	// 4. Fall back to a bare container at offset 0
	return file, 0, file, nil
}

// findAPFSPartitionInGPT reads a GPT at LBA 1 of the image and returns the
// byte offset of the first Apple_APFS (or HFS+) partition.
func findAPFSPartitionInGPT(r io.ReaderAt) (int64, error) {
	headerData := make([]byte, gptSectorSize)
	if _, err := r.ReadAt(headerData, gptSectorSize); err != nil {
		return 0, fmt.Errorf("unable to read GPT header: %w", err)
	}

	var header GPTHeader
	if err := binary.Read(bytes.NewReader(headerData), binary.LittleEndian, &header); err != nil {
		return 0, fmt.Errorf("unable to parse GPT header: %w", err)
	}

	if err := header.Verify(); err != nil {
		return 0, err
	}

	entriesData := make([]byte, int64(header.EntriesCount)*int64(header.EntriesSize))
	if _, err := r.ReadAt(entriesData, int64(header.EntriesStart)*gptSectorSize); err != nil {
		return 0, fmt.Errorf("unable to read GPT partition entries: %w", err)
	}

	partitions := make([]GPTPartition, header.EntriesCount)
	if err := binary.Read(bytes.NewReader(entriesData), binary.LittleEndian, &partitions); err != nil {
		return 0, fmt.Errorf("unable to parse GPT partition entries: %w", err)
	}

	for _, partition := range partitions {
		if partition.IsEmpty() {
			continue
		}
		typeGUID := partition.Type.String()
		if typeGUID == appleAPFSGUID || typeGUID == appleHFSGUID {
			return int64(partition.StartingLBA) * gptSectorSize, nil
		}
	}

	return 0, fmt.Errorf("no APFS partition found in GPT")
}

package apfs

import (
	"encoding/binary"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// CRC32 polynomial used for checksum calculation
const CRC32Polynomial = 0x82f63b78

// CRC32Table stores precomputed CRC-32 values for lookup
var CRC32Table [256]uint32

// CRC32TableComputed indicates whether the CRC-32 table has been initialized
var CRC32TableComputed = false

// InitializeCRC32Table initializes the internal CRC-32 table
// The table speeds up the CRC-32 calculation
func InitializeCRC32Table() {
	if CRC32TableComputed {
		return
	}

	for tableIndex := 0; tableIndex < 256; tableIndex++ {
		checksum := uint32(tableIndex)

		for bitIterator := 0; bitIterator < 8; bitIterator++ {
			if checksum&1 != 0 {
				checksum = CRC32Polynomial ^ (checksum >> 1)
			} else {
				checksum = checksum >> 1
			}
		}
		CRC32Table[tableIndex] = checksum
	}
	CRC32TableComputed = true
}

// CalculateWeakCRC32 calculates the weak CRC-32 checksum of a buffer of data
func CalculateWeakCRC32(buffer []byte, initialValue uint32) (uint32, error) {
	if buffer == nil {
		return 0, fmt.Errorf("invalid buffer")
	}

	if int64(len(buffer)) > common.Int32Max {
		return 0, fmt.Errorf("invalid size value exceeds maximum")
	}

	if !CRC32TableComputed {
		InitializeCRC32Table()
	}

	safeChecksum := initialValue

	for _, b := range buffer {
		tableIndex := (safeChecksum ^ uint32(b)) & 0x000000ff
		safeChecksum = CRC32Table[tableIndex] ^ (safeChecksum >> 8)
	}

	return safeChecksum, nil
}

// CalculateFletcher64 calculates the Fletcher-64 checksum of a buffer of data
func CalculateFletcher64(buffer []byte, initialValue uint64) (uint64, error) {
	if buffer == nil {
		return 0, fmt.Errorf("invalid buffer")
	}

	if int64(len(buffer)) > common.Int32Max {
		return 0, fmt.Errorf("invalid size value exceeds maximum")
	}

	if len(buffer)%4 != 0 {
		return 0, fmt.Errorf("invalid size value out of bounds: size must be multiple of 4")
	}

	lower32bit := initialValue & common.Uint32Mask
	upper32bit := (initialValue >> 32) & common.Uint32Mask

	for bufferOffset := 0; bufferOffset < len(buffer); bufferOffset += 4 {
		value32bit := binary.LittleEndian.Uint32(buffer[bufferOffset : bufferOffset+4])

		lower32bit += uint64(value32bit)
		upper32bit += lower32bit
	}

	lower32bit %= common.Uint32Mask
	upper32bit %= common.Uint32Mask

	value32bit := uint64(common.Uint32Mask - ((lower32bit + upper32bit) % common.Uint32Mask))
	upper32bit = uint64(common.Uint32Mask - ((lower32bit + value32bit) % common.Uint32Mask))

	return (upper32bit << 32) | value32bit, nil
}

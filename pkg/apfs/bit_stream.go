package apfs

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// Bit stream storage types
const (
	BitStreamStorageTypeUnknown         = 0x00
	BitStreamStorageTypeByteFrontToBack = 0x01
	BitStreamStorageTypeByteBackToFront = 0x02
)

// BitStream represents a bit stream for reading individual bits from a byte stream
type BitStream struct {
	// The byte stream
	ByteStream []byte

	// The byte stream offset
	ByteStreamOffset int

	// The storage type
	StorageType uint8

	// The bit buffer
	BitBuffer uint32

	// The number of bits remaining in the bit buffer
	BitBufferSize uint8
}

// NewBitStream creates a new bit stream
func NewBitStream(
	byteStream []byte,
	byteStreamOffset int,
	storageType uint8,
) (*BitStream, error) {
	if byteStream == nil {
		return nil, fmt.Errorf("invalid byte stream")
	}

	if byteStreamOffset > common.Int32Max {
		return nil, fmt.Errorf("invalid byte stream offset value exceeds maximum")
	}

	if len(byteStream) > common.Int32Max {
		return nil, fmt.Errorf("invalid byte stream size value exceeds maximum")
	}

	if storageType != BitStreamStorageTypeByteBackToFront && storageType != BitStreamStorageTypeByteFrontToBack {
		return nil, fmt.Errorf("unsupported storage type")
	}

	return &BitStream{
		ByteStream:       byteStream,
		ByteStreamOffset: byteStreamOffset,
		StorageType:      storageType,
		BitBuffer:        0,
		BitBufferSize:    0,
	}, nil
}

// Value retrieves a value from the bit stream
func (bs *BitStream) Value(numberOfBits uint8) (uint32, error) {
	if numberOfBits > common.Uint32BitWidth {
		return 0, fmt.Errorf("invalid number of bits value exceeds maximum")
	}

	var safeValue32bit uint32 = 0
	remainingNumberOfBits := numberOfBits

	for remainingNumberOfBits > 0 {
		// Fill the bit buffer if needed
		for remainingNumberOfBits > bs.BitBufferSize && bs.BitBufferSize <= common.BitBufferRefillThreshold {
			if bs.ByteStreamOffset >= len(bs.ByteStream) {
				return 0, fmt.Errorf("invalid byte stream offset value out of bounds")
			}

			if bs.StorageType == BitStreamStorageTypeByteBackToFront {
				bs.BitBuffer |= uint32(bs.ByteStream[bs.ByteStreamOffset]) << bs.BitBufferSize
			} else if bs.StorageType == BitStreamStorageTypeByteFrontToBack {
				bs.BitBuffer <<= common.BitsPerByte
				bs.BitBuffer |= uint32(bs.ByteStream[bs.ByteStreamOffset])
			}

			bs.BitBufferSize += common.BitsPerByte
			bs.ByteStreamOffset++
		}

		// Determine how many bits to read
		var readNumberOfBits uint8
		if remainingNumberOfBits < bs.BitBufferSize {
			readNumberOfBits = remainingNumberOfBits
		} else {
			readNumberOfBits = bs.BitBufferSize
		}

		readValue32bit := bs.BitBuffer

		// Shift safe value if needed
		if remainingNumberOfBits < numberOfBits {
			safeValue32bit <<= remainingNumberOfBits
		}

		// Extract bits based on storage type
		if bs.StorageType == BitStreamStorageTypeByteBackToFront {
			if readNumberOfBits < common.Uint32BitWidth {
				readValue32bit &= ^(common.Uint32Mask << readNumberOfBits)
				bs.BitBuffer >>= readNumberOfBits
			}
			bs.BitBufferSize -= readNumberOfBits
		} else if bs.StorageType == BitStreamStorageTypeByteFrontToBack {
			bs.BitBufferSize -= readNumberOfBits
			readValue32bit >>= bs.BitBufferSize

			if bs.BitBufferSize > 0 {
				bs.BitBuffer &= common.Uint32Mask >> (common.Uint32BitWidth - bs.BitBufferSize)
			}
		}

		if bs.BitBufferSize == 0 {
			bs.BitBuffer = 0
		}

		safeValue32bit |= readValue32bit
		remainingNumberOfBits -= readNumberOfBits
	}

	return safeValue32bit, nil
}

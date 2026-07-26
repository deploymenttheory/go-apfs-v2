// Deflate (zlib) (un)compression functions
package apfs

import (
	"encoding/binary"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// Deflate block types
// Corresponds to LIBFSAPFS_DEFLATE_BLOCK_TYPES
const (
	DeflateBlockTypeUncompressed   = 0x00
	DeflateBlockTypeHuffmanFixed   = 0x01
	DeflateBlockTypeHuffmanDynamic = 0x02
	DeflateBlockTypeReserved       = 0x03
)

// Deflate code sizes sequence
var deflateCodeSizesSequence = []uint8{
	16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2,
	14, 1, 15,
}

// Deflate literal codes base values
var deflateLiteralCodesBase = []uint16{
	3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
	35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
}

// Deflate literal codes number of extra bits
var deflateLiteralCodesNumberOfExtraBits = []uint16{
	0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
	3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
}

// Deflate distance codes base values
var deflateDistanceCodesBase = []uint16{
	1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
	257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193,
	12289, 16385, 24577,
}

// Deflate distance codes number of extra bits
var deflateDistanceCodesNumberOfExtraBits = []uint16{
	0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
	7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
}

// BuildDynamicHuffmanTrees initializes the dynamic Huffman trees
func BuildDynamicHuffmanTrees(bitStream *BitStream, literalsTree *HuffmanTree, distancesTree *HuffmanTree) error {
	codeSizeArray := make([]uint8, 316)

	// Read number of code sizes (14 bits total)
	numberOfCodeSizes, err := bitStream.GetValue(14)
	if err != nil {
		return fmt.Errorf("unable to retrieve value from bit stream: %w", err)
	}

	numberOfLiteralCodes := numberOfCodeSizes & 0x0000001f
	numberOfCodeSizes >>= 5
	numberOfDistanceCodes := numberOfCodeSizes & 0x0000001f
	numberOfCodeSizes >>= 5

	numberOfLiteralCodes += 257

	if numberOfLiteralCodes > 286 {
		return fmt.Errorf("invalid number of literal codes value out of bounds: %d", numberOfLiteralCodes)
	}

	numberOfDistanceCodes++

	if numberOfDistanceCodes > 30 {
		return fmt.Errorf("invalid number of distance codes value out of bounds: %d", numberOfDistanceCodes)
	}

	numberOfCodeSizes += 4

	// Read code sizes for the code size tree
	for codeSizeIndex := uint32(0); codeSizeIndex < numberOfCodeSizes; codeSizeIndex++ {
		codeSize, err := bitStream.GetValue(3)
		if err != nil {
			return fmt.Errorf("unable to retrieve value from bit stream: %w", err)
		}

		codeSizeSequence := deflateCodeSizesSequence[codeSizeIndex]
		codeSizeArray[codeSizeSequence] = uint8(codeSize)
	}

	// Fill remaining code sizes with 0
	for codeSizeIndex := numberOfCodeSizes; codeSizeIndex < 19; codeSizeIndex++ {
		codeSizeSequence := deflateCodeSizesSequence[codeSizeIndex]
		codeSizeArray[codeSizeSequence] = 0
	}

	// Build codes tree
	codesTree, err := NewHuffmanTree(19, 15)
	if err != nil {
		return fmt.Errorf("unable to build codes tree: %w", err)
	}
	defer codesTree.Free()

	success, err := codesTree.Build(codeSizeArray, 19)
	if err != nil {
		return fmt.Errorf("unable to build codes tree: %w", err)
	}
	if !success {
		return fmt.Errorf("codes tree is empty")
	}

	// Read the literal and distance code sizes
	totalCodeSizes := numberOfLiteralCodes + numberOfDistanceCodes
	codeSizeIndex := uint32(0)

	for codeSizeIndex < totalCodeSizes {
		symbol, err := codesTree.GetSymbolFromBitStream(bitStream)
		if err != nil {
			return fmt.Errorf("unable to retrieve literal value from bit stream: %w", err)
		}

		if symbol < 16 {
			codeSizeArray[codeSizeIndex] = uint8(symbol)
			codeSizeIndex++
			continue
		}

		var codeSize uint32 = 0
		var timesToRepeat uint32

		if symbol == 16 {
			if codeSizeIndex == 0 {
				return fmt.Errorf("invalid code size index value out of bounds")
			}

			codeSize = uint32(codeSizeArray[codeSizeIndex-1])

			value, err := bitStream.GetValue(2)
			if err != nil {
				return fmt.Errorf("unable to retrieve value from bit stream: %w", err)
			}
			timesToRepeat = value + 3

		} else if symbol == 17 {
			value, err := bitStream.GetValue(3)
			if err != nil {
				return fmt.Errorf("unable to retrieve value from bit stream: %w", err)
			}
			timesToRepeat = value + 3

		} else if symbol == 18 {
			value, err := bitStream.GetValue(7)
			if err != nil {
				return fmt.Errorf("unable to retrieve value from bit stream: %w", err)
			}
			timesToRepeat = value + 11

		} else {
			return fmt.Errorf("invalid code value value out of bounds: %d", symbol)
		}

		if (codeSizeIndex + timesToRepeat) > totalCodeSizes {
			return fmt.Errorf("invalid times to repeat value out of bounds")
		}

		for timesToRepeat > 0 {
			codeSizeArray[codeSizeIndex] = uint8(codeSize)
			codeSizeIndex++
			timesToRepeat--
		}
	}

	// Check for end-of-block code
	if codeSizeArray[256] == 0 {
		return fmt.Errorf("end-of-block code value missing in literal codes array")
	}

	// Build literals tree
	success, err = literalsTree.Build(codeSizeArray, int(numberOfLiteralCodes))
	if err != nil {
		return fmt.Errorf("unable to build literals tree: %w", err)
	}
	if !success {
		return fmt.Errorf("literals tree is empty")
	}

	// Build distances tree
	success, err = distancesTree.Build(codeSizeArray[numberOfLiteralCodes:], int(numberOfDistanceCodes))
	if err != nil {
		return fmt.Errorf("unable to build distances tree: %w", err)
	}
	if !success {
		return fmt.Errorf("distances tree is empty")
	}

	return nil
}

// BuildFixedHuffmanTrees initializes the fixed Huffman trees
func BuildFixedHuffmanTrees(literalsTree *HuffmanTree, distancesTree *HuffmanTree) error {
	codeSizeArray := make([]uint8, 318)

	// Build the fixed Huffman code size array
	for symbol := 0; symbol < 318; symbol++ {
		if symbol < 144 {
			codeSizeArray[symbol] = 8
		} else if symbol < 256 {
			codeSizeArray[symbol] = 9
		} else if symbol < 280 {
			codeSizeArray[symbol] = 7
		} else if symbol < 288 {
			codeSizeArray[symbol] = 8
		} else {
			codeSizeArray[symbol] = 5
		}
	}

	// Build literals tree
	success, err := literalsTree.Build(codeSizeArray, 288)
	if err != nil {
		return fmt.Errorf("unable to build literals tree: %w", err)
	}
	if !success {
		return fmt.Errorf("literals tree is empty")
	}

	// Build distances tree
	success, err = distancesTree.Build(codeSizeArray[288:], 30)
	if err != nil {
		return fmt.Errorf("unable to build distances tree: %w", err)
	}
	if !success {
		return fmt.Errorf("distances tree is empty")
	}

	return nil
}

// DecodeHuffman decodes a Huffman compressed block
func DecodeHuffman(bitStream *BitStream, literalsTree *HuffmanTree, distancesTree *HuffmanTree, uncompressedData []byte, uncompressedDataSize int, uncompressedDataOffset *int) error {
	if uncompressedData == nil {
		return fmt.Errorf("invalid uncompressed data")
	}

	if uncompressedDataOffset == nil {
		return fmt.Errorf("invalid uncompressed data offset")
	}

	dataOffset := *uncompressedDataOffset

	for {
		symbol, err := literalsTree.GetSymbolFromBitStream(bitStream)
		if err != nil {
			return fmt.Errorf("unable to retrieve literal value from bit stream: %w", err)
		}

		// Literal value
		if symbol < 256 {
			if dataOffset >= uncompressedDataSize {
				return fmt.Errorf("invalid uncompressed data value too small")
			}
			uncompressedData[dataOffset] = uint8(symbol)
			dataOffset++

		} else if symbol > 256 && symbol < 286 {
			// Length/distance pair
			symbol -= 257

			numberOfExtraBits := deflateLiteralCodesNumberOfExtraBits[symbol]

			extraBits, err := bitStream.GetValue(uint8(numberOfExtraBits))
			if err != nil {
				return fmt.Errorf("unable to retrieve literal extra value from bit stream: %w", err)
			}

			compressionSize := deflateLiteralCodesBase[symbol] + uint16(extraBits)

			// Get distance symbol
			distanceSymbol, err := distancesTree.GetSymbolFromBitStream(bitStream)
			if err != nil {
				return fmt.Errorf("unable to retrieve distance value from bit stream: %w", err)
			}

			numberOfExtraBits = deflateDistanceCodesNumberOfExtraBits[distanceSymbol]

			extraBits, err = bitStream.GetValue(uint8(numberOfExtraBits))
			if err != nil {
				return fmt.Errorf("unable to retrieve distance extra value from bit stream: %w", err)
			}

			compressionOffset := deflateDistanceCodesBase[distanceSymbol] + uint16(extraBits)

			if int(compressionOffset) > dataOffset {
				return fmt.Errorf("invalid compression offset value out of bounds: %d > %d", compressionOffset, dataOffset)
			}

			if (dataOffset + int(compressionSize)) > uncompressedDataSize {
				return fmt.Errorf("invalid uncompressed data value too small")
			}

			// Copy data from lookback buffer
			for compressionSize > 0 {
				uncompressedData[dataOffset] = uncompressedData[dataOffset-int(compressionOffset)]
				dataOffset++
				compressionSize--
			}

		} else if symbol == 256 {
			// End of block
			break

		} else {
			return fmt.Errorf("invalid code value: %d", symbol)
		}
	}

	*uncompressedDataOffset = dataOffset

	return nil
}

// CalculateAdler32 calculates the little-endian Adler-32 of a buffer
// It uses the initial value to calculate a new Adler-32
func CalculateAdler32(data []byte, dataSize int, initialValue uint32) (uint32, error) {
	if data == nil {
		return 0, fmt.Errorf("invalid data")
	}

	lowerWord := uint32(initialValue & common.Uint16Mask)
	upperWord := uint32((initialValue >> 16) & common.Uint16Mask)
	dataOffset := 0

	// Process in chunks of 5552 bytes (0x15b0)
	// The modulo calculation is needed per 5552 bytes
	// 5552 / 16 = 347
	for dataSize >= 0x15b0 {
		for blockIndex := 0; blockIndex < 347; blockIndex++ {
			// Process 16 bytes at a time
			for i := 0; i < 16; i++ {
				lowerWord += uint32(data[dataOffset])
				dataOffset++
				upperWord += lowerWord
			}
		}

		// Optimized equivalent of: lowerWord %= 0xfff1
		value32bit := lowerWord >> 16
		lowerWord &= 0x0000ffff
		lowerWord += (value32bit << 4) - value32bit

		if lowerWord > 65521 {
			value32bit = lowerWord >> 16
			lowerWord &= 0x0000ffff
			lowerWord += (value32bit << 4) - value32bit
		}
		if lowerWord >= 65521 {
			lowerWord -= 65521
		}

		// Optimized equivalent of: upperWord %= 0xfff1
		value32bit = upperWord >> 16
		upperWord &= 0x0000ffff
		upperWord += (value32bit << 4) - value32bit

		if upperWord > 65521 {
			value32bit = upperWord >> 16
			upperWord &= 0x0000ffff
			upperWord += (value32bit << 4) - value32bit
		}
		if upperWord >= 65521 {
			upperWord -= 65521
		}

		dataSize -= 0x15b0
	}

	// Process remaining data
	if dataSize > 0 {
		for dataSize > 16 {
			// Process 16 bytes at a time
			for i := 0; i < 16; i++ {
				lowerWord += uint32(data[dataOffset])
				dataOffset++
				upperWord += lowerWord
			}
			dataSize -= 16
		}

		// Process remaining bytes
		for dataSize > 0 {
			lowerWord += uint32(data[dataOffset])
			dataOffset++
			upperWord += lowerWord
			dataSize--
		}

		// Optimized equivalent of: lowerWord %= 0xfff1
		value32bit := lowerWord >> 16
		lowerWord &= 0x0000ffff
		lowerWord += (value32bit << 4) - value32bit

		if lowerWord > 65521 {
			value32bit = lowerWord >> 16
			lowerWord &= 0x0000ffff
			lowerWord += (value32bit << 4) - value32bit
		}
		if lowerWord >= 65521 {
			lowerWord -= 65521
		}

		// Optimized equivalent of: upperWord %= 0xfff1
		value32bit = upperWord >> 16
		upperWord &= 0x0000ffff
		upperWord += (value32bit << 4) - value32bit

		if upperWord > 65521 {
			value32bit = upperWord >> 16
			upperWord &= 0x0000ffff
			upperWord += (value32bit << 4) - value32bit
		}
		if upperWord >= 65521 {
			upperWord -= 65521
		}
	}

	checksumValue := (upperWord << 16) | lowerWord

	return checksumValue, nil
}

// ReadDataHeader reads the compressed data header
func ReadDataHeader(compressedData []byte, compressedDataSize int, compressedDataOffset *int) error {
	if compressedData == nil {
		return fmt.Errorf("invalid compressed data")
	}

	if compressedDataOffset == nil {
		return fmt.Errorf("invalid compressed data offset")
	}

	safeOffset := *compressedDataOffset

	if compressedDataSize < 2 || safeOffset > (compressedDataSize-2) {
		return fmt.Errorf("invalid compressed data value too small")
	}

	compressionData := compressedData[safeOffset]
	safeOffset++
	flags := compressedData[safeOffset]
	safeOffset++

	compressionMethod := compressionData & 0x0f
	compressionInformation := compressionData >> 4

	// Validate check bits (RFC 1950)
	// The two header bytes (CMF and FLG) must form a value that is a multiple of 31
	// This is a simple check to detect header corruption
	checkValue := (uint16(compressionData) * 256) + uint16(flags)
	if checkValue%31 != 0 {
		return fmt.Errorf("invalid zlib header check bits (CMF=%d, FLG=%d, check=%d)",
			compressionData, flags, checkValue%31)
	}

	// Check for preset dictionary flag
	if (flags & 0x20) != 0 {
		if compressedDataSize < 6 || safeOffset > (compressedDataSize-6) {
			return fmt.Errorf("invalid compressed data value too small")
		}

		// Skip preset dictionary identifier (4 bytes)
		// presetDictionaryIdentifier := binary.BigEndian.Uint32(compressedData[safeOffset:safeOffset+4])
		safeOffset += 4
	}

	if compressionMethod != 8 {
		return fmt.Errorf("unsupported compression method: %d", compressionMethod)
	}

	compressionWindowBits := compressionInformation + 8
	compressionWindowSize := uint32(1) << compressionWindowBits

	if compressionWindowSize > 32768 {
		return fmt.Errorf("unsupported compression window size: %d", compressionWindowSize)
	}

	*compressedDataOffset = safeOffset

	return nil
}

// ReadBlockHeader reads the header of a block of compressed data
func ReadBlockHeader(bitStream *BitStream, blockType *uint8, lastBlockFlag *uint8) error {
	if blockType == nil {
		return fmt.Errorf("invalid block type")
	}

	if lastBlockFlag == nil {
		return fmt.Errorf("invalid last block flag")
	}

	value32bit, err := bitStream.GetValue(3)
	if err != nil {
		return fmt.Errorf("unable to retrieve value from bit stream: %w", err)
	}

	*lastBlockFlag = uint8(value32bit & 0x00000001)
	value32bit >>= 1
	*blockType = uint8(value32bit)

	return nil
}

// ReadBlock reads a block of compressed data
func ReadBlock(bitStream *BitStream, blockType uint8, fixedHuffmanLiteralsTree *HuffmanTree, fixedHuffmanDistancesTree *HuffmanTree, uncompressedData []byte, uncompressedDataSize int, uncompressedDataOffset *int) error {
	if bitStream == nil {
		return fmt.Errorf("invalid bit stream")
	}

	if uncompressedData == nil {
		return fmt.Errorf("invalid uncompressed data")
	}

	if uncompressedDataOffset == nil {
		return fmt.Errorf("invalid uncompressed data offset")
	}

	safeUncompressedDataOffset := *uncompressedDataOffset

	switch blockType {
	case DeflateBlockTypeUncompressed:
		// Ignore the bits in the buffer up to the next byte
		skipBits := bitStream.BitBufferSize & 0x07

		if skipBits > 0 {
			_, err := bitStream.GetValue(skipBits)
			if err != nil {
				return fmt.Errorf("unable to retrieve value from bit stream: %w", err)
			}
		}

		// Read block size (32 bits)
		blockSize, err := bitStream.GetValue(32)
		if err != nil {
			return fmt.Errorf("unable to retrieve value from bit stream: %w", err)
		}

		blockSizeCopy := (blockSize >> 16) ^ 0x0000ffff
		blockSize &= 0x0000ffff

		if blockSize != blockSizeCopy {
			return fmt.Errorf("mismatch in block size (%d != %d)", blockSize, blockSizeCopy)
		}

		if blockSize == 0 {
			break
		}

		if int(blockSize) > (len(bitStream.ByteStream) - bitStream.ByteStreamOffset) {
			return fmt.Errorf("invalid compressed data value too small")
		}

		if int(blockSize) > (uncompressedDataSize - safeUncompressedDataOffset) {
			return fmt.Errorf("invalid uncompressed data value too small")
		}

		// Copy uncompressed data
		copy(uncompressedData[safeUncompressedDataOffset:], bitStream.ByteStream[bitStream.ByteStreamOffset:bitStream.ByteStreamOffset+int(blockSize)])

		bitStream.ByteStreamOffset += int(blockSize)
		safeUncompressedDataOffset += int(blockSize)

		// Flush the bit stream buffer
		bitStream.BitBuffer = 0
		bitStream.BitBufferSize = 0

	case DeflateBlockTypeHuffmanFixed:
		err := DecodeHuffman(bitStream, fixedHuffmanLiteralsTree, fixedHuffmanDistancesTree, uncompressedData, uncompressedDataSize, &safeUncompressedDataOffset)
		if err != nil {
			return fmt.Errorf("unable to decode fixed Huffman encoded bit stream: %w", err)
		}

	case DeflateBlockTypeHuffmanDynamic:
		dynamicHuffmanLiteralsTree, err := NewHuffmanTree(288, 15)
		if err != nil {
			return fmt.Errorf("unable to build dynamic literals Huffman tree: %w", err)
		}
		defer dynamicHuffmanLiteralsTree.Free()

		dynamicHuffmanDistancesTree, err := NewHuffmanTree(30, 15)
		if err != nil {
			return fmt.Errorf("unable to build dynamic distances Huffman tree: %w", err)
		}
		defer dynamicHuffmanDistancesTree.Free()

		err = BuildDynamicHuffmanTrees(bitStream, dynamicHuffmanLiteralsTree, dynamicHuffmanDistancesTree)
		if err != nil {
			return fmt.Errorf("unable to build dynamic Huffman trees: %w", err)
		}

		err = DecodeHuffman(bitStream, dynamicHuffmanLiteralsTree, dynamicHuffmanDistancesTree, uncompressedData, uncompressedDataSize, &safeUncompressedDataOffset)
		if err != nil {
			return fmt.Errorf("unable to decode dynamic Huffman encoded bit stream: %w", err)
		}

	case DeflateBlockTypeReserved:
		fallthrough
	default:
		return fmt.Errorf("unsupported block type: %d", blockType)
	}

	*uncompressedDataOffset = safeUncompressedDataOffset

	return nil
}

// DeflateDecompress decompresses data using deflate compression
func DeflateDecompress(compressedData []byte, compressedDataSize int, uncompressedData []byte, uncompressedDataSize *int) error {
	if compressedData == nil {
		return fmt.Errorf("invalid compressed data")
	}

	if uncompressedData == nil {
		return fmt.Errorf("invalid uncompressed data")
	}

	if uncompressedDataSize == nil {
		return fmt.Errorf("invalid uncompressed data size")
	}

	safeUncompressedDataSize := *uncompressedDataSize
	compressedDataOffset := 0

	if compressedDataOffset >= compressedDataSize {
		return fmt.Errorf("invalid compressed data value too small")
	}

	bitStream, err := NewBitStream(compressedData, compressedDataOffset, BitStreamStorageTypeByteBackToFront)
	if err != nil {
		return fmt.Errorf("unable to create bit stream: %w", err)
	}

	var fixedHuffmanLiteralsTree *HuffmanTree
	var fixedHuffmanDistancesTree *HuffmanTree

	uncompressedDataOffset := 0

	for bitStream.ByteStreamOffset < len(bitStream.ByteStream) {
		var blockType uint8
		var lastBlockFlag uint8

		err := ReadBlockHeader(bitStream, &blockType, &lastBlockFlag)
		if err != nil {
			return fmt.Errorf("unable to read compressed data block header: %w", err)
		}

		if blockType == DeflateBlockTypeHuffmanFixed {
			if fixedHuffmanLiteralsTree == nil && fixedHuffmanDistancesTree == nil {
				fixedHuffmanLiteralsTree, err = NewHuffmanTree(288, 15)
				if err != nil {
					return fmt.Errorf("unable to build fixed literals Huffman tree: %w", err)
				}

				fixedHuffmanDistancesTree, err = NewHuffmanTree(30, 15)
				if err != nil {
					if fixedHuffmanLiteralsTree != nil {
						fixedHuffmanLiteralsTree.Free()
					}
					return fmt.Errorf("unable to build fixed distances Huffman tree: %w", err)
				}

				err = BuildFixedHuffmanTrees(fixedHuffmanLiteralsTree, fixedHuffmanDistancesTree)
				if err != nil {
					if fixedHuffmanLiteralsTree != nil {
						fixedHuffmanLiteralsTree.Free()
					}
					if fixedHuffmanDistancesTree != nil {
						fixedHuffmanDistancesTree.Free()
					}
					return fmt.Errorf("unable to build fixed Huffman trees: %w", err)
				}
			}
		}

		err = ReadBlock(bitStream, blockType, fixedHuffmanLiteralsTree, fixedHuffmanDistancesTree, uncompressedData, safeUncompressedDataSize, &uncompressedDataOffset)
		if err != nil {
			if fixedHuffmanDistancesTree != nil {
				fixedHuffmanDistancesTree.Free()
			}
			if fixedHuffmanLiteralsTree != nil {
				fixedHuffmanLiteralsTree.Free()
			}
			return fmt.Errorf("unable to read block of compressed data: %w", err)
		}

		if lastBlockFlag != 0 {
			break
		}
	}

	if fixedHuffmanDistancesTree != nil {
		fixedHuffmanDistancesTree.Free()
	}
	if fixedHuffmanLiteralsTree != nil {
		fixedHuffmanLiteralsTree.Free()
	}

	*uncompressedDataSize = uncompressedDataOffset

	return nil
}

// DeflateDecompressZlib decompresses data using zlib compression
func DeflateDecompressZlib(compressedData []byte, compressedDataSize int, uncompressedData []byte, uncompressedDataSize *int) error {
	if compressedData == nil {
		return fmt.Errorf("invalid compressed data")
	}

	if uncompressedData == nil {
		return fmt.Errorf("invalid uncompressed data")
	}

	if uncompressedDataSize == nil {
		return fmt.Errorf("invalid uncompressed data size")
	}

	safeUncompressedDataSize := *uncompressedDataSize
	compressedDataOffset := 0

	// Read data header
	err := ReadDataHeader(compressedData, compressedDataSize, &compressedDataOffset)
	if err != nil {
		return fmt.Errorf("unable to read data header: %w", err)
	}

	if compressedDataOffset >= compressedDataSize {
		return fmt.Errorf("invalid compressed data value too small")
	}

	bitStream, err := NewBitStream(compressedData, compressedDataOffset, BitStreamStorageTypeByteBackToFront)
	if err != nil {
		return fmt.Errorf("unable to create bit stream: %w", err)
	}

	var fixedHuffmanLiteralsTree *HuffmanTree
	var fixedHuffmanDistancesTree *HuffmanTree

	uncompressedDataOffset := 0

	for bitStream.ByteStreamOffset < len(bitStream.ByteStream) {
		var blockType uint8
		var lastBlockFlag uint8

		err := ReadBlockHeader(bitStream, &blockType, &lastBlockFlag)
		if err != nil {
			return fmt.Errorf("unable to read compressed data block header: %w", err)
		}

		if blockType == DeflateBlockTypeHuffmanFixed {
			if fixedHuffmanLiteralsTree == nil && fixedHuffmanDistancesTree == nil {
				fixedHuffmanLiteralsTree, err = NewHuffmanTree(288, 15)
				if err != nil {
					return fmt.Errorf("unable to build fixed literals Huffman tree: %w", err)
				}

				fixedHuffmanDistancesTree, err = NewHuffmanTree(30, 15)
				if err != nil {
					if fixedHuffmanLiteralsTree != nil {
						fixedHuffmanLiteralsTree.Free()
					}
					return fmt.Errorf("unable to build fixed distances Huffman tree: %w", err)
				}

				err = BuildFixedHuffmanTrees(fixedHuffmanLiteralsTree, fixedHuffmanDistancesTree)
				if err != nil {
					if fixedHuffmanLiteralsTree != nil {
						fixedHuffmanLiteralsTree.Free()
					}
					if fixedHuffmanDistancesTree != nil {
						fixedHuffmanDistancesTree.Free()
					}
					return fmt.Errorf("unable to build fixed Huffman trees: %w", err)
				}
			}
		}

		err = ReadBlock(bitStream, blockType, fixedHuffmanLiteralsTree, fixedHuffmanDistancesTree, uncompressedData, safeUncompressedDataSize, &uncompressedDataOffset)
		if err != nil {
			if fixedHuffmanDistancesTree != nil {
				fixedHuffmanDistancesTree.Free()
			}
			if fixedHuffmanLiteralsTree != nil {
				fixedHuffmanLiteralsTree.Free()
			}
			return fmt.Errorf("unable to read block of compressed data: %w", err)
		}

		if lastBlockFlag != 0 {
			break
		}
	}

	// Verify checksum if available
	if (len(bitStream.ByteStream) - bitStream.ByteStreamOffset) >= 4 {
		// Rewind bit buffer
		for bitStream.BitBufferSize >= 8 {
			bitStream.ByteStreamOffset--
			bitStream.BitBufferSize -= 8
		}

		storedChecksum := binary.BigEndian.Uint32(bitStream.ByteStream[bitStream.ByteStreamOffset : bitStream.ByteStreamOffset+4])

		calculatedChecksum, err := CalculateAdler32(uncompressedData, uncompressedDataOffset, 1)
		if err != nil {
			if fixedHuffmanDistancesTree != nil {
				fixedHuffmanDistancesTree.Free()
			}
			if fixedHuffmanLiteralsTree != nil {
				fixedHuffmanLiteralsTree.Free()
			}
			return fmt.Errorf("unable to calculate checksum: %w", err)
		}

		if storedChecksum != calculatedChecksum {
			if fixedHuffmanDistancesTree != nil {
				fixedHuffmanDistancesTree.Free()
			}
			if fixedHuffmanLiteralsTree != nil {
				fixedHuffmanLiteralsTree.Free()
			}
			return fmt.Errorf("checksum does not match (stored: 0x%08x, calculated: 0x%08x)", storedChecksum, calculatedChecksum)
		}
	}

	if fixedHuffmanDistancesTree != nil {
		fixedHuffmanDistancesTree.Free()
	}
	if fixedHuffmanLiteralsTree != nil {
		fixedHuffmanLiteralsTree.Free()
	}

	*uncompressedDataSize = uncompressedDataOffset

	return nil
}

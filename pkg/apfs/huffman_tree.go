// Huffman tree functions
package apfs

import (
	"fmt"
)

// HuffmanTree represents a Huffman tree for decompression
type HuffmanTree struct {
	// The maximum number of bits allowed for a Huffman code
	MaximumCodeSize uint8

	// The symbols array
	Symbols []uint16

	// The code size counts array
	CodeSizeCounts []int
}

// NewHuffmanTree creates a new Huffman tree
func NewHuffmanTree(numberOfSymbols int, maximumCodeSize uint8) (*HuffmanTree, error) {
	if numberOfSymbols < 0 || numberOfSymbols > 1024 {
		return nil, fmt.Errorf("invalid number of symbols value out of bounds: %d", numberOfSymbols)
	}

	if maximumCodeSize > 32 {
		return nil, fmt.Errorf("invalid maximum code size value out of bounds: %d", maximumCodeSize)
	}

	ht := &HuffmanTree{
		MaximumCodeSize: maximumCodeSize,
		Symbols:         make([]uint16, numberOfSymbols),
		CodeSizeCounts:  make([]int, maximumCodeSize+1),
	}

	return ht, nil
}

// Close releases resources associated with the Huffman tree
func (ht *HuffmanTree) Close() error {
	if ht == nil {
		return fmt.Errorf("invalid Huffman tree")
	}

	// Go's garbage collector will handle memory cleanup
	ht.Symbols = nil
	ht.CodeSizeCounts = nil

	return nil
}

// Build builds the Huffman tree from code sizes
// Returns true on success, false if the tree is empty
func (ht *HuffmanTree) Build(codeSizesArray []uint8, numberOfCodeSizes int) (bool, error) {
	if ht == nil {
		return false, fmt.Errorf("invalid Huffman tree")
	}

	if codeSizesArray == nil {
		return false, fmt.Errorf("invalid code sizes array")
	}

	if numberOfCodeSizes < 0 || numberOfCodeSizes > 32767 {
		return false, fmt.Errorf("invalid number of code sizes value out of bounds: %d", numberOfCodeSizes)
	}

	// Determine the code size frequencies
	// Clear code size counts
	for i := range ht.CodeSizeCounts {
		ht.CodeSizeCounts[i] = 0
	}

	for symbol := 0; symbol < numberOfCodeSizes; symbol++ {
		codeSize := codeSizesArray[symbol]

		if codeSize > ht.MaximumCodeSize {
			return false, fmt.Errorf("invalid symbol: %d code size: %d value out of bounds", symbol, codeSize)
		}

		ht.CodeSizeCounts[codeSize]++
	}

	// The tree has no codes
	if ht.CodeSizeCounts[0] == numberOfCodeSizes {
		return false, nil
	}

	// Check if the set of code sizes is incomplete or over-subscribed
	leftValue := 1

	for bitIndex := uint8(1); bitIndex <= ht.MaximumCodeSize; bitIndex++ {
		leftValue <<= 1
		leftValue -= ht.CodeSizeCounts[bitIndex]

		if leftValue < 0 {
			return false, fmt.Errorf("code sizes are over-subscribed")
		}
	}

	// Check for incomplete code sizes
	// Note: This was a TODO in the C code, now implemented
	if leftValue > 0 {
		return false, fmt.Errorf("code sizes are incomplete (leftover value: %d)", leftValue)
	}

	// Calculate the offsets to sort the symbols per code size
	symbolOffsets := make([]int, ht.MaximumCodeSize+1)
	symbolOffsets[0] = 0
	symbolOffsets[1] = 0

	for bitIndex := uint8(1); bitIndex < ht.MaximumCodeSize; bitIndex++ {
		symbolOffsets[bitIndex+1] = symbolOffsets[bitIndex] + ht.CodeSizeCounts[bitIndex]
	}

	// Fill the symbols sorted by code size
	for symbol := 0; symbol < numberOfCodeSizes; symbol++ {
		codeSize := codeSizesArray[symbol]

		if codeSize == 0 {
			continue
		}

		codeOffset := symbolOffsets[codeSize]

		if codeOffset < 0 || codeOffset > numberOfCodeSizes {
			return false, fmt.Errorf("invalid symbol: %d code offset: %d value out of bounds", symbol, codeOffset)
		}

		symbolOffsets[codeSize]++
		ht.Symbols[codeOffset] = uint16(symbol)
	}

	return true, nil
}

// SymbolFromBitStream retrieves a symbol based on the Huffman code read from the bit-stream
func (ht *HuffmanTree) SymbolFromBitStream(bitStream *BitStream) (uint16, error) {
	if ht == nil {
		return 0, fmt.Errorf("invalid Huffman tree")
	}

	if bitStream == nil {
		return 0, fmt.Errorf("invalid bit stream")
	}

	var safeSymbol uint16
	firstHuffmanCode := 0
	firstIndex := 0
	huffmanCode := 0
	result := false

	// Note: Optimization opportunity - could read maximum_code_size bits at once into a local buffer
	// This would reduce the number of GetValue() calls from O(n) to O(1) per symbol lookup
	// However, current implementation prioritizes correctness and code clarity
	// Performance profiling should be done before optimizing

	for bitIndex := uint8(1); bitIndex <= ht.MaximumCodeSize; bitIndex++ {
		value32bit, err := bitStream.Value(1)
		if err != nil {
			return 0, fmt.Errorf("unable to retrieve value from bit stream: %w", err)
		}

		huffmanCode <<= 1
		huffmanCode |= int(value32bit)

		codeSizeCount := ht.CodeSizeCounts[bitIndex]

		if (huffmanCode - codeSizeCount) < firstHuffmanCode {
			index := firstIndex + (huffmanCode - firstHuffmanCode)
			if index < 0 || index >= len(ht.Symbols) {
				return 0, fmt.Errorf("invalid symbol index: %d", index)
			}
			safeSymbol = ht.Symbols[index]
			result = true
			break
		}

		firstHuffmanCode += codeSizeCount
		firstHuffmanCode <<= 1
		firstIndex += codeSizeCount
	}

	if !result {
		return 0, fmt.Errorf("invalid Huffman code: 0x%08x", huffmanCode)
	}

	return safeSymbol, nil
}

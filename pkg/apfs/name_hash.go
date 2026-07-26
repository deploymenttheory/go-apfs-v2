package apfs

import (
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
	"golang.org/x/text/unicode/norm"
)

// CRC32 table for name hash calculation
var crc32Table [256]uint32
var crc32TableInitialized bool

// initializeCRC32Table initializes the CRC-32 table
func initializeCRC32Table() {
	if crc32TableInitialized {
		return
	}

	// APFS uses the polynomial 0x82f63b78 for name hash CRC32
	// This matches the C library CalculateNameHash.c:165
	const polynomial uint32 = 0x82f63b78

	for tableIndex := uint32(0); tableIndex < 256; tableIndex++ {
		checksum := tableIndex

		for bitIterator := 0; bitIterator < 8; bitIterator++ {
			if checksum&1 != 0 {
				checksum = polynomial ^ (checksum >> 1)
			} else {
				checksum = checksum >> 1
			}
		}

		crc32Table[tableIndex] = checksum
	}

	crc32TableInitialized = true
}

// CalculateNameHash calculates the APFS name hash from a UTF-8 string
//
// Note: This implementation uses Go's unicode.ToLower() and norm.NFD for case folding
// and normalization. The C library has special case mappings for certain Unicode
// characters (Greek letters, ligatures, etc.) that may not be handled identically
// by Go's standard library. For most use cases, the Go implementation should produce
// compatible results. If exact hash matching is required for edge cases, additional
// special case mapping tables from the C implementation may need to be added.
func CalculateNameHash(utf8String []byte, useCaseFolding bool) uint32 {
	// Initialize CRC32 table if not already done
	initializeCRC32Table()

	var calculatedChecksum uint32 = common.Uint32Mask
	utf8Index := 0

	// Process each character in the UTF-8 string
	for utf8Index < len(utf8String) {
		// Decode UTF-8 character
		unicodeChar, size := utf8.DecodeRune(utf8String[utf8Index:])
		if unicodeChar == utf8.RuneError || unicodeChar == 0 {
			break
		}
		utf8Index += size

		// Apply case folding if requested
		if useCaseFolding {
			unicodeChar = unicode.ToLower(unicodeChar)
		}

		// Apply NFD (Canonical Decomposition) normalization
		normalized := norm.NFD.String(string(unicodeChar))

		// Process each rune in the normalized string
		for _, nfdChar := range normalized {
			// Convert to little-endian uint32 and process with CRC32
			// Process 4 bytes (as per the C implementation)
			unicodeValue := uint32(nfdChar)

			// Process byte 0
			byteValue := uint8(unicodeValue & 0xFF)
			checksumTableIndex := (calculatedChecksum ^ uint32(byteValue)) & 0xFF
			calculatedChecksum = crc32Table[checksumTableIndex] ^ (calculatedChecksum >> 8)
			unicodeValue >>= 8

			// Process byte 1
			byteValue = uint8(unicodeValue & 0xFF)
			checksumTableIndex = (calculatedChecksum ^ uint32(byteValue)) & 0xFF
			calculatedChecksum = crc32Table[checksumTableIndex] ^ (calculatedChecksum >> 8)
			unicodeValue >>= 8

			// Process byte 2
			byteValue = uint8(unicodeValue & 0xFF)
			checksumTableIndex = (calculatedChecksum ^ uint32(byteValue)) & 0xFF
			calculatedChecksum = crc32Table[checksumTableIndex] ^ (calculatedChecksum >> 8)
			unicodeValue >>= 8

			// Process byte 3
			byteValue = uint8(unicodeValue & 0xFF)
			checksumTableIndex = (calculatedChecksum ^ uint32(byteValue)) & 0xFF
			calculatedChecksum = crc32Table[checksumTableIndex] ^ (calculatedChecksum >> 8)
		}
	}

	// Mask to 22 bits (0x003fffff)
	return calculatedChecksum & 0x003fffff
}

// CalculateNameHashFromUTF16 calculates the APFS name hash from a UTF-16 string
//
// Note: This implementation uses Go's unicode.ToLower() and norm.NFD for case folding
// and normalization. See CalculateNameHash for details about special case handling.
func CalculateNameHashFromUTF16(utf16String []uint16, useCaseFolding bool) uint32 {
	// Initialize CRC32 table if not already done
	initializeCRC32Table()

	var calculatedChecksum uint32 = common.Uint32Mask

	// Decode UTF-16 to runes
	runes := utf16.Decode(utf16String)

	// Process each rune
	for _, unicodeChar := range runes {
		// Stop at null terminator
		if unicodeChar == 0 {
			break
		}

		// Apply case folding if requested
		if useCaseFolding {
			unicodeChar = unicode.ToLower(unicodeChar)
		}

		// Apply NFD (Canonical Decomposition) normalization
		normalized := norm.NFD.String(string(unicodeChar))

		// Process each rune in the normalized string
		for _, nfdChar := range normalized {
			// Convert to little-endian uint32 and process with CRC32
			unicodeValue := uint32(nfdChar)

			// Process byte 0
			byteValue := uint8(unicodeValue & 0xFF)
			checksumTableIndex := (calculatedChecksum ^ uint32(byteValue)) & 0xFF
			calculatedChecksum = crc32Table[checksumTableIndex] ^ (calculatedChecksum >> 8)
			unicodeValue >>= 8

			// Process byte 1
			byteValue = uint8(unicodeValue & 0xFF)
			checksumTableIndex = (calculatedChecksum ^ uint32(byteValue)) & 0xFF
			calculatedChecksum = crc32Table[checksumTableIndex] ^ (calculatedChecksum >> 8)
			unicodeValue >>= 8

			// Process byte 2
			byteValue = uint8(unicodeValue & 0xFF)
			checksumTableIndex = (calculatedChecksum ^ uint32(byteValue)) & 0xFF
			calculatedChecksum = crc32Table[checksumTableIndex] ^ (calculatedChecksum >> 8)
			unicodeValue >>= 8

			// Process byte 3
			byteValue = uint8(unicodeValue & 0xFF)
			checksumTableIndex = (calculatedChecksum ^ uint32(byteValue)) & 0xFF
			calculatedChecksum = crc32Table[checksumTableIndex] ^ (calculatedChecksum >> 8)
		}
	}

	// Mask to 22 bits (0x003fffff)
	return calculatedChecksum & 0x003fffff
}

// UTF16ToString converts a UTF-16 slice to a UTF-8 string
func UTF16ToString(utf16Data []uint16) string {
	runes := utf16.Decode(utf16Data)
	return string(runes)
}

// StringToUTF16 converts a UTF-8 string to a UTF-16 slice
func StringToUTF16(str string) []uint16 {
	runes := []rune(str)
	return utf16.Encode(runes)
}

// CompareNamesWithUTF8 compares two names using UTF-8 encoding with optional case folding
// Returns 0 if equal, <0 if name1 < name2, >0 if name1 > name2
func CompareNamesWithUTF8(name1 []byte, name2 []byte, useCaseFolding bool) int {
	// Apply normalization and case folding as needed
	str1 := string(name1)
	str2 := string(name2)

	if useCaseFolding {
		// Apply case folding (convert to lowercase for comparison)
		str1Runes := []rune(str1)
		str2Runes := []rune(str2)

		for i := range str1Runes {
			str1Runes[i] = unicode.ToLower(str1Runes[i])
		}
		for i := range str2Runes {
			str2Runes[i] = unicode.ToLower(str2Runes[i])
		}

		str1 = string(str1Runes)
		str2 = string(str2Runes)
	}

	// Apply NFD normalization
	str1 = norm.NFD.String(str1)
	str2 = norm.NFD.String(str2)

	// Compare
	if str1 < str2 {
		return -1
	} else if str1 > str2 {
		return 1
	}
	return 0
}

// CompareNamesWithUTF16 compares two names using UTF-16 encoding with optional case folding
// Returns 0 if equal, <0 if name1 < name2, >0 if name1 > name2
func CompareNamesWithUTF16(name1 []uint16, name2 []uint16, useCaseFolding bool) int {
	// Convert UTF-16 to string
	str1 := UTF16ToString(name1)
	str2 := UTF16ToString(name2)

	if useCaseFolding {
		// Apply case folding (convert to lowercase for comparison)
		str1Runes := []rune(str1)
		str2Runes := []rune(str2)

		for i := range str1Runes {
			str1Runes[i] = unicode.ToLower(str1Runes[i])
		}
		for i := range str2Runes {
			str2Runes[i] = unicode.ToLower(str2Runes[i])
		}

		str1 = string(str1Runes)
		str2 = string(str2Runes)
	}

	// Apply NFD normalization
	str1 = norm.NFD.String(str1)
	str2 = norm.NFD.String(str2)

	// Compare
	if str1 < str2 {
		return -1
	} else if str1 > str2 {
		return 1
	}
	return 0
}

// Note: Helper functions for file system keys (CreateFileSystemKey, ExtractIdentifierFromKey, etc.)
// are defined in btree_key_value.go

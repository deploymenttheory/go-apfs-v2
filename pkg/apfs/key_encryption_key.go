// The key encryption key (KEK) functions
package apfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// WrappedKEKInitializationVector is the expected IV for wrapped KEK
var WrappedKEKInitializationVector = [8]byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}

// KeyEncryptionKey represents an APFS key encryption key (KEK)
type KeyEncryptionKey struct {
	// The identifier (UUID)
	Identifier [16]byte

	// The HMAC
	HMAC [32]byte

	// The number of iterations for PBKDF2
	NumberOfIterations uint64

	// The salt for PBKDF2
	Salt [16]byte

	// The encryption method
	EncryptionMethod uint32

	// The wrapped key material.  A record wraps 16, 32 or 64 bytes of key
	// data, so the wrapped form is 24, 40 or 72 bytes: a 64-byte value is
	// the AES-XTS-256 volume key.
	WrappedKEK []byte
}

// NewKeyEncryptionKey creates a new key encryption key
func NewKeyEncryptionKey() (*KeyEncryptionKey, error) {
	return &KeyEncryptionKey{
		Identifier:         [16]byte{},
		HMAC:               [32]byte{},
		NumberOfIterations: 0,
		Salt:               [16]byte{},
		EncryptionMethod:   0,
		WrappedKEK:         nil,
	}, nil
}

// readTagLengthValue reads a TLV (tag-length-value) encoded field
// Returns tag, value data, and new offset
func readTagLengthValue(data []byte, offset int) (tag uint8, valueData []byte, newOffset int, err error) {
	if offset >= len(data)-1 {
		return 0, nil, offset, fmt.Errorf("insufficient data for TLV header at offset %d", offset)
	}

	tag = data[offset]
	offset++

	byteValue := data[offset]
	offset++

	var valueDataSize uint16

	// Parse length encoding
	if (byteValue & 0x80) == 0 {
		// Short form: length is the byte value
		valueDataSize = uint16(byteValue)
	} else if byteValue == 0x81 {
		// Long form with 1 byte length
		if offset >= len(data) {
			return 0, nil, offset, fmt.Errorf("insufficient data for 1-byte length at offset %d", offset)
		}
		valueDataSize = uint16(data[offset])
		offset++
	} else if byteValue == 0x82 {
		// Long form with 2 byte length (little-endian)
		if offset+1 >= len(data) {
			return 0, nil, offset, fmt.Errorf("insufficient data for 2-byte length at offset %d", offset)
		}
		valueDataSize = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	} else {
		return 0, nil, offset, fmt.Errorf("unsupported extended value data size: 0x%02x", byteValue)
	}

	// Extract value data
	if offset+int(valueDataSize) > len(data) {
		return 0, nil, offset, fmt.Errorf("invalid value data size %d at offset %d (exceeds data bounds)", valueDataSize, offset)
	}

	valueData = data[offset : offset+int(valueDataSize)]
	newOffset = offset + int(valueDataSize)

	return tag, valueData, newOffset, nil
}

// ReadData reads the key encryption key from binary data
func (kek *KeyEncryptionKey) ReadData(data []byte) error {
	if kek == nil {
		return fmt.Errorf("invalid key encryption key")
	}

	if len(data) < 2 {
		return fmt.Errorf("invalid data size")
	}

	// Read outer object
	outerTag, outerValue, offset, err := readTagLengthValue(data, 0)
	if err != nil {
		return fmt.Errorf("unable to read outer object: %w", err)
	}

	if outerTag != 0x30 {
		return fmt.Errorf("unsupported object value tag: 0x%02x (expected 0x30)", outerTag)
	}

	// Parse attributes within outer object
	var wrappedKEKObjectData []byte

	attributeOffset := offset - len(outerValue)
	endOffset := offset

	for attributeOffset < endOffset {
		tag, valueData, newOffset, err := readTagLengthValue(data, attributeOffset)
		if err != nil {
			return fmt.Errorf("unable to read attribute: %w", err)
		}

		// Check for terminator
		if tag == 0 && len(valueData) == 0 {
			break
		}

		switch tag {
		case 0x81:
			// HMAC (32 bytes)
			if len(valueData) != 32 {
				return fmt.Errorf("unsupported HMAC attribute value data size: %d (expected 32)", len(valueData))
			}
			copy(kek.HMAC[:], valueData)

		case 0x82:
			// Unknown (8 bytes) - skip

		case 0xa3:
			// Wrapped KEK packed object - store for later parsing
			// We need to go back 2 bytes to include the tag and length
			wrappedKEKObjectStart := attributeOffset
			wrappedKEKObjectEnd := newOffset
			wrappedKEKObjectData = data[wrappedKEKObjectStart:wrappedKEKObjectEnd]
		}

		attributeOffset = newOffset
	}

	if wrappedKEKObjectData == nil {
		return fmt.Errorf("missing wrapped KEK packed object")
	}

	// Parse wrapped KEK object
	wrappedTag, wrappedValue, wrappedOffset, err := readTagLengthValue(wrappedKEKObjectData, 0)
	if err != nil {
		return fmt.Errorf("unable to read wrapped KEK object: %w", err)
	}

	if wrappedTag != 0xa3 {
		return fmt.Errorf("unsupported wrapped KEK object value tag: 0x%02x (expected 0xa3)", wrappedTag)
	}

	// Parse wrapped KEK attributes
	wrappedAttributeOffset := wrappedOffset - len(wrappedValue)
	wrappedEndOffset := wrappedOffset

	for wrappedAttributeOffset < wrappedEndOffset {
		tag, valueData, newOffset, err := readTagLengthValue(wrappedKEKObjectData, wrappedAttributeOffset)
		if err != nil {
			return fmt.Errorf("unable to read wrapped KEK attribute: %w", err)
		}

		// Check for terminator
		if tag == 0 && len(valueData) == 0 {
			break
		}

		switch tag {
		case 0x81:
			// Identifier (16 bytes, UUID)
			if len(valueData) != 16 {
				return fmt.Errorf("unsupported identifier attribute value data size: %d (expected 16)", len(valueData))
			}
			copy(kek.Identifier[:], valueData)

		case 0x82:
			// KEK metadata (8 bytes)
			if len(valueData) != 8 {
				return fmt.Errorf("unsupported KEK metadata attribute value data size: %d (expected 8)", len(valueData))
			}
			kek.EncryptionMethod = binary.LittleEndian.Uint32(valueData[0:4])

		case 0x83:
			// Wrapped key: 16, 32 or 64 bytes plus the 8-byte IV.
			if len(valueData) != 24 && len(valueData) != 40 && len(valueData) != 72 {
				return fmt.Errorf("unsupported wrapped KEK attribute value data size: %d (expected 24, 40 or 72)", len(valueData))
			}
			kek.WrappedKEK = append([]byte(nil), valueData...)

		case 0x84:
			// Number of iterations (1-8 bytes, big-endian)
			if len(valueData) == 0 || len(valueData) > 8 {
				return fmt.Errorf("unsupported number of iterations attribute value data size: %d", len(valueData))
			}
			kek.NumberOfIterations = 0
			for i := 0; i < len(valueData); i++ {
				kek.NumberOfIterations <<= 8
				kek.NumberOfIterations |= uint64(valueData[i])
			}

		case 0x85:
			// Salt (16 bytes)
			if len(valueData) != 16 {
				return fmt.Errorf("unsupported salt attribute value data size: %d (expected 16)", len(valueData))
			}
			copy(kek.Salt[:], valueData)
		}

		wrappedAttributeOffset = newOffset
	}

	return nil
}

// UnlockWithKey unlocks the key encryption key using a key
// Returns the unlocked key, or nil if unlocking failed
func (kek *KeyEncryptionKey) UnlockWithKey(key []byte) ([]byte, error) {
	if kek == nil {
		return nil, fmt.Errorf("invalid key encryption key")
	}

	if key == nil || len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: expected 32 bytes, got %d", len(key))
	}

	// The wrapped length says how long the unwrapped key is; the method only
	// says how the key doing the wrapping was selected.
	if kek.EncryptionMethod != 0 && kek.EncryptionMethod != 2 && kek.EncryptionMethod != 16 {
		return nil, fmt.Errorf("unsupported encryption method: %d", kek.EncryptionMethod)
	}
	if len(kek.WrappedKEK) != 24 && len(kek.WrappedKEK) != 40 && len(kek.WrappedKEK) != 72 {
		return nil, fmt.Errorf("unsupported wrapped key size: %d", len(kek.WrappedKEK))
	}
	usedKeySize := len(kek.WrappedKEK) - 8
	if kek.EncryptionMethod == 2 && usedKeySize != 16 {
		return nil, fmt.Errorf("unsupported wrapped key size for method 2: %d", usedKeySize)
	}

	// Unwrap with the key doing the wrapping (RFC 3394)
	unwrappedKEK, err := AESKeyUnwrap(key, len(key)*8, kek.WrappedKEK)
	if err != nil {
		return nil, fmt.Errorf("unable to unwrap wrapped KEK with key: %w", err)
	}

	// Verify initialization vector
	if !bytes.Equal(unwrappedKEK[0:8], WrappedKEKInitializationVector[:]) {
		return nil, fmt.Errorf("invalid initialization vector (unlock failed)")
	}

	// Copy unwrapped key data
	unlockedKey := make([]byte, usedKeySize)
	copy(unlockedKey, unwrappedKEK[8:8+usedKeySize])

	// For encryption method 2 the wrapped record holds half of the key and
	// the other half is a hash of the first half and the record UUID.
	if kek.EncryptionMethod == 2 {
		extended := make([]byte, 32)
		copy(extended, unlockedKey[:16])
		copy(extended[16:], kek.Identifier[:])
		hash := sha256.Sum256(extended)
		copy(extended[16:], hash[0:16])
		unlockedKey = extended
	}

	// Clear sensitive data
	for i := range unwrappedKEK {
		unwrappedKEK[i] = 0
	}

	return unlockedKey, nil
}

// UnlockWithPassword unlocks the key encryption key using a password
// Returns the unlocked key, or nil if unlocking failed
func (kek *KeyEncryptionKey) UnlockWithPassword(password []byte) ([]byte, error) {
	if kek == nil {
		return nil, fmt.Errorf("invalid key encryption key")
	}

	// The method selects the wrapping cipher and the password-key size; the
	// wrapped length says how long the unwrapped key is.
	var passwordKeySize int
	if kek.EncryptionMethod == 0 || kek.EncryptionMethod == 16 {
		passwordKeySize = 32
	} else if kek.EncryptionMethod == 2 {
		passwordKeySize = 16
	} else {
		return nil, fmt.Errorf("unsupported encryption method: %d", kek.EncryptionMethod)
	}
	if len(kek.WrappedKEK) != 24 && len(kek.WrappedKEK) != 40 && len(kek.WrappedKEK) != 72 {
		return nil, fmt.Errorf("unsupported wrapped key size: %d", len(kek.WrappedKEK))
	}
	unwrappedKeySize := len(kek.WrappedKEK) - 8

	// Derive password key using PBKDF2
	passwordKey, err := PBKDF2(password, kek.Salt[:], uint32(kek.NumberOfIterations), passwordKeySize)
	if err != nil {
		return nil, fmt.Errorf("unable to derive password key: %w", err)
	}

	// Unwrap KEK with password key using AES Key Wrap (RFC 3394)
	unwrappedKEK, err := AESKeyUnwrap(passwordKey, passwordKeySize*8, kek.WrappedKEK)
	if err != nil {
		// Clear password key
		for i := range passwordKey {
			passwordKey[i] = 0
		}
		return nil, fmt.Errorf("unable to unwrap wrapped KEK with password: %w", err)
	}

	// Clear password key
	for i := range passwordKey {
		passwordKey[i] = 0
	}

	// Verify initialization vector
	if !bytes.Equal(unwrappedKEK[0:8], WrappedKEKInitializationVector[:]) {
		// Clear sensitive data
		for i := range unwrappedKEK {
			unwrappedKEK[i] = 0
		}
		return nil, fmt.Errorf("invalid initialization vector (unlock failed - wrong password?)")
	}

	// Allocate unlocked key buffer (method 2 keeps its 32-byte padded form)
	keySize := 32
	if unwrappedKeySize > keySize {
		keySize = unwrappedKeySize
	}
	unlockedKey := make([]byte, keySize)
	copy(unlockedKey[0:unwrappedKeySize], unwrappedKEK[8:8+unwrappedKeySize])

	// Clear sensitive data
	for i := range unwrappedKEK {
		unwrappedKEK[i] = 0
	}

	return unlockedKey, nil
}

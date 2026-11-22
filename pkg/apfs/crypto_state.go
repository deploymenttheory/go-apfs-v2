// Per-file keys (PFK): crypto state records and the per-file key resolver.
//
// Volumes that set APFS_INCOMPAT_PFK (0x40) encrypt each file with its own
// key. The per-file key is not derived from a counter: it is a random key,
// wrapped (RFC 3394) and stored in the volume's file system B-tree as a
// crypto state record — a D record keyed by (fileID, cryptoID). The file's
// extents carry the cryptoID that names which D record holds their key.
//
// The unwrap key for the wrapped per-file key is the volume master key
// (the VEK) on software-encrypted volumes; on hardware-encrypted volumes
// the wrapping key lives in the Secure Enclave and cannot be recovered —
// this file deliberately refuses that case by requiring the master key.
package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Volume incompatible feature bit for per-file keys. Named "made up" in
// apfsprogs; it is what Apple's driver calls the PFK/rolling feature.
const VolumeIncompatiblePerFileKeys uint64 = 0x0000000000000040

// Well-known crypto identifiers (j_crypto_id values).
const (
	CryptoIDSWUnencrypted  uint64 = 0
	CryptoIDSWRaw          uint64 = 1
	CryptoIDUnencrypted    uint64 = 2
	CryptoIDSparseBundle   uint64 = 3
	CryptoIDSoftwareCrypto uint64 = 4
	CryptoIDInvalid        uint64 = 0xFFFFFFFFFFFFFFFF
)

// j_crypto_key: the file system B-tree key of a crypto state record.
// Word 0 is the standard (type<<60 | fileID) identifier; word 1 is the
// crypto identifier the extents refer to.
type CryptoStateKey struct {
	Type     uint8
	FileID   uint64
	CryptoID uint64
}

// j_crypto_val: refcount followed by the wrapped crypto state
// (apfs_wrapped_crypto_state). The field layout matches
// apfs_wrapped_crypto_state in apfsprogs' include/apfs/raw.h.
type CryptoStateValue struct {
	Refcount        uint32
	MajorVersion    uint16
	MinorVersion    uint16
	CPFlags         uint32
	PersistentClass uint32
	KeyOSVersion    uint32
	KeyRevision     uint16
	KeyLen          uint16
	PersistentKey   []byte
}

// ParseCryptoStateKey parses a D record key from its raw bytes.
func ParseCryptoStateKey(data []byte) (*CryptoStateKey, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("invalid crypto state key: size %d, want at least 24", len(data))
	}
	identifier := binary.LittleEndian.Uint64(data[0:8])
	return &CryptoStateKey{
		Type:     uint8(identifier >> 60),
		FileID:   identifier & 0x0FFFFFFFFFFFFFFF,
		CryptoID: binary.LittleEndian.Uint64(data[8:16]),
	}, nil
}

// ParseCryptoStateValue parses a D record value (j_crypto_val) from raw
// bytes. The value starts with the four-byte reference count; the wrapped
// key follows the fixed 20-byte header of apfs_wrapped_crypto_state.
func ParseCryptoStateValue(key, value []byte) (*CryptoStateValue, error) {
	if value == nil {
		return nil, fmt.Errorf("invalid crypto state value")
	}
	if len(value) < 24 {
		return nil, fmt.Errorf("invalid crypto state value: size %d, want at least 24", len(value))
	}

	c := &CryptoStateValue{}
	c.Refcount = binary.LittleEndian.Uint32(value[0:4])
	c.MajorVersion = binary.LittleEndian.Uint16(value[4:6])
	c.MinorVersion = binary.LittleEndian.Uint16(value[6:8])
	c.CPFlags = binary.LittleEndian.Uint32(value[8:12])
	c.PersistentClass = binary.LittleEndian.Uint32(value[12:16])
	c.KeyOSVersion = binary.LittleEndian.Uint32(value[16:20])
	c.KeyRevision = binary.LittleEndian.Uint16(value[20:22])
	c.KeyLen = binary.LittleEndian.Uint16(value[22:24])

	if int(c.KeyLen) > len(value)-24 {
		return nil, fmt.Errorf("crypto state key length %d exceeds value size %d", c.KeyLen, len(value)-24)
	}
	if c.KeyLen == 0 || c.KeyLen%8 != 0 {
		return nil, fmt.Errorf("crypto state key length %d is not a positive multiple of 8", c.KeyLen)
	}
	// A wrapped XTS key is one or two AES key sizes; reject absurd values
	// early rather than feeding the unwrap function garbage.
	if c.KeyLen > 256 {
		return nil, fmt.Errorf("crypto state key length %d out of bounds", c.KeyLen)
	}

	c.PersistentKey = make([]byte, c.KeyLen)
	copy(c.PersistentKey, value[24:24+c.KeyLen])

	return c, nil
}

// UnwrapPerFileKey unwraps the per-file key from the crypto state record
// using the volume master key (VEK). The result is the AES-XTS key for the
// file: 32 or 64 bytes (AES-128-XTS / AES-256-XTS) depending on the key
// length stored in the record.
func (c *CryptoStateValue) UnwrapPerFileKey(masterKey []byte) ([]byte, error) {
	if masterKey == nil {
		return nil, fmt.Errorf("cannot unwrap per-file key without the volume master key")
	}

	// The wrap key for a per-file key on a software-encrypted PFK volume
	// is the unwrapped volume key (the KEK/VEK pair are both 32-byte
	// AES keys; which of them Apple's driver used is recorded in the
	// keybag flags). The caller passes the one it wants to try; the IV
	// check below rejects a wrong guess.
	wrapKey := masterKey
	keyBitSize := len(wrapKey) * 8
	if keyBitSize > 256 {
		return nil, fmt.Errorf("unsupported master key size %d", len(wrapKey))
	}
	if keyBitSize == 192 {
		// A 24-byte key is not a valid XTS key and is not produced by any
		// known APFS writer; refuse rather than guess.
		return nil, fmt.Errorf("unexpected master key size %d", len(wrapKey))
	}

	unwrapped, err := AESKeyUnwrap(wrapKey, keyBitSize, c.PersistentKey)
	if err != nil {
		return nil, fmt.Errorf("unable to unwrap per-file key: %w", err)
	}

	// RFC 3394 puts the integrity vector in the first eight bytes of the
	// unwrap output; a mismatch means the wrap key was wrong. The key
	// itself is everything after it.
	if !bytes.Equal(unwrapped[0:8], WrappedKEKInitializationVector[:]) {
		for i := range unwrapped {
			unwrapped[i] = 0
		}
		return nil, fmt.Errorf("invalid per-file key initialization vector (wrong volume key?)")
	}

	perFileKey := make([]byte, len(unwrapped)-8)
	copy(perFileKey, unwrapped[8:])

	switch len(perFileKey) {
	case 32, 64:
		return perFileKey, nil
	default:
		return nil, fmt.Errorf("unexpected per-file key size %d", len(perFileKey))
	}
}

// PerFileContextFor returns a resolver bound to one file: it maps the
// crypto identifiers of that file's extents (and extent-backed extended
// attributes) to the encryption contexts that decrypt them. Volumes
// assign it to FileEntry.PerFileContext when handing out entries.
func (v *Volume) PerFileContextFor(reader io.ReaderAt, fileID uint64) func(uint64) (*EncryptionContext, error) {
	return func(cryptoID uint64) (*EncryptionContext, error) {
		return v.PerFileKey(reader, fileID, cryptoID)
	}
}

// cryptoStateCacheKey keys the per-file context cache. Per-file keys are
// per (file, cryptoID): a file keeps its old key while its extents roll to
// a new one, so both parts are needed.
type cryptoStateCacheKey struct {
	fileID   uint64
	cryptoID uint64
}

// CryptoStateFor finds the crypto state record of one file extent. The
// file system B-tree keys D records by fileID alone; every record of one
// file is adjacent in the leaf, so the leaf is scanned for the record
// whose crypto identifier matches.
func (v *Volume) CryptoStateFor(reader io.ReaderAt, fileID, cryptoID uint64) (*CryptoStateValue, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid volume")
	}
	if v.FileSystemBTree == nil {
		return nil, fmt.Errorf("volume has no file system btree")
	}

	// All records for the file identifier, then keep only D records:
	// extent and xattr keys share the (type<<60 | fileID) word-0 form,
	// so the type nibble must be checked before treating a key as a
	// crypto state key.
	entries, err := v.FileSystemBTree.AllRecordsForOID(reader, fileID)
	if err != nil {
		return nil, fmt.Errorf("unable to look up crypto state for file %d: %w", fileID, err)
	}

	var fallback *CryptoStateValue
	for _, entry := range entries {
		key, err := ParseCryptoStateKey(entry.KeyData)
		if err != nil {
			continue
		}
		if key.FileID != fileID || key.Type != FileSystemRecordTypeCryptoState {
			continue
		}
		value, err := ParseCryptoStateValue(entry.KeyData, entry.ValueData)
		if err != nil {
			continue
		}
		if key.CryptoID == cryptoID {
			return value, nil
		}
		fallback = value
	}

	if fallback != nil {
		// The exact crypto id is missing (mid-roll extents); use the
		// newest revision we can find rather than refusing to read.
		return fallback, nil
	}

	return nil, fmt.Errorf("no crypto state record for file %d crypto id %d", fileID, cryptoID)
}

// PerFileKey returns the encryption context that decrypts the extent of
// fileID with the given crypto identifier, or a nil context when that
// extent is stored in the clear (the unencrypted crypto identifiers).
// On volumes without the PFK feature it returns the whole-volume context
// for any encrypted identifier, so callers can use it unconditionally.
func (v *Volume) PerFileKey(reader io.ReaderAt, fileID, cryptoID uint64) (*EncryptionContext, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid volume")
	}

	switch cryptoID {
	case CryptoIDSWUnencrypted, CryptoIDUnencrypted, CryptoIDSparseBundle:
		// These identifiers name unencrypted data even on a volume
		// that is otherwise encrypted; decrypting them would garble
		// the clear. A nil context means "read without decrypting".
		return nil, nil
	case CryptoIDInvalid:
		return nil, fmt.Errorf("extent of file %d has the invalid crypto identifier", fileID)
	}

	if !v.pfkEnabled || cryptoID == CryptoIDSWRaw || cryptoID == CryptoIDSoftwareCrypto {
		if v.EncryptionContext == nil {
			return nil, fmt.Errorf("volume is locked")
		}
		return v.EncryptionContext, nil
	}

	if v.EncryptionContext == nil || v.masterKey == nil {
		return nil, fmt.Errorf("per-file keys require an unlocked volume")
	}

	v.cryptoMu.Lock()
	defer v.cryptoMu.Unlock()
	if v.cryptoCache == nil {
		v.cryptoCache = make(map[cryptoStateCacheKey]*EncryptionContext)
	}
	cacheKey := cryptoStateCacheKey{fileID: fileID, cryptoID: cryptoID}
	if ctx, ok := v.cryptoCache[cacheKey]; ok {
		return ctx, nil
	}

	record, err := v.CryptoStateFor(reader, fileID, cryptoID)
	if err != nil {
		return nil, err
	}
	perFileKey, err := record.UnwrapPerFileKey(v.masterKey)
	if err != nil {
		return nil, err
	}
	context, err := NewEncryptionContextForKey(perFileKey)
	if err != nil {
		return nil, err
	}
	v.cryptoCache[cacheKey] = context
	return context, nil
}

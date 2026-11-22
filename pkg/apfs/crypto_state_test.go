package apfs

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"testing"
)

// RFC 3394 section 4.3: wrap 128 bits of key data with a 256-bit KEK.
// This is the vector that also exercises the AES-256 unwrap path used
// to recover per-file keys, so it doubles as the known-answer test for
// the production unwrap.
func TestAESKeyWrapRFC3394KnownAnswer(t *testing.T) {
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	plain := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	want := []byte{
		0x64, 0xe8, 0xc3, 0xf9, 0xce, 0x0f, 0x5b, 0xa2,
		0x63, 0xe9, 0x77, 0x79, 0x05, 0x81, 0x8a, 0x2a,
		0x93, 0xc8, 0x19, 0x1e, 0x7d, 0x6e, 0x8a, 0xe7,
	}

	wrapped, err := AESKeyWrap(kek, 256, plain)
	if err != nil {
		t.Fatalf("AESKeyWrap: %v", err)
	}
	if !bytes.Equal(wrapped, want) {
		t.Fatalf("AESKeyWrap mismatch:\n got %x\nwant %x", wrapped, want)
	}

	// The same vector run backwards through the production unwrap must
	// restore both the integrity vector and the key data.
	unwrapped, err := AESKeyUnwrap(kek, 256, wrapped)
	if err != nil {
		t.Fatalf("AESKeyUnwrap: %v", err)
	}
	if !bytes.Equal(unwrapped[8:], plain) {
		t.Fatalf("unwrap did not restore key:\n got %x\nwant %x", unwrapped[8:], plain)
	}
	if !bytes.Equal(unwrapped[0:8], WrappedKEKInitializationVector[:]) {
		t.Fatalf("unwrap did not recover the RFC 3394 integrity vector")
	}
}

// RFC 3394 section 4.1: wrap 128 bits of key data with a 128-bit KEK.
// AES-128 is the size a software-encrypted volume's wrapped key most
// often uses, so it gets its own known-answer test.
func TestAESKeyWrapRFC3394KnownAnswer128(t *testing.T) {
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	plain := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	want := []byte{
		0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47,
		0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a, 0x7b, 0x82,
		0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
	}

	wrapped, err := AESKeyWrap(kek, 128, plain)
	if err != nil {
		t.Fatalf("AESKeyWrap: %v", err)
	}
	if !bytes.Equal(wrapped, want) {
		t.Fatalf("AESKeyWrap mismatch:\n got %x\nwant %x", wrapped, want)
	}

	unwrapped, err := AESKeyUnwrap(kek, 128, wrapped)
	if err != nil {
		t.Fatalf("AESKeyUnwrap: %v", err)
	}
	if !bytes.Equal(unwrapped[8:], plain) {
		t.Fatalf("unwrap did not restore key:\n got %x\nwant %x", unwrapped[8:], plain)
	}
}

// buildCryptoStateRecord assembles a synthetic (key, value) pair for a
// crypto state record whose wrapped per-file key is key, wrapped with kek.
func buildCryptoStateRecord(t *testing.T, fileID, cryptoID uint64, kek, key []byte) (keyBytes, valueBytes []byte) {
	t.Helper()

	wrapped, err := AESKeyWrap(kek, len(kek)*8, key)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	keyBytes = make([]byte, 24)
	binary.LittleEndian.PutUint64(keyBytes[0:8], (uint64(FileSystemRecordTypeCryptoState)<<60)|fileID)
	binary.LittleEndian.PutUint64(keyBytes[8:16], cryptoID)

	valueBytes = make([]byte, 24+len(wrapped))
	binary.LittleEndian.PutUint32(valueBytes[0:4], 1)  // refcount
	binary.LittleEndian.PutUint16(valueBytes[4:6], 2)  // major
	binary.LittleEndian.PutUint16(valueBytes[6:8], 0)  // minor
	binary.LittleEndian.PutUint32(valueBytes[8:12], 0) // cpflags
	binary.LittleEndian.PutUint32(valueBytes[12:16], 2)
	// persistent class 2 (complete until first unlock)
	binary.LittleEndian.PutUint32(valueBytes[16:20], 2800) // key os version
	binary.LittleEndian.PutUint16(valueBytes[20:22], 1)    // key revision
	binary.LittleEndian.PutUint16(valueBytes[22:24], uint16(len(wrapped)))
	copy(valueBytes[24:], wrapped)
	return keyBytes, valueBytes
}

func TestParseCryptoStateRecord(t *testing.T) {
	kek := bytes.Repeat([]byte{0x2a}, 32)
	perFileKey := bytes.Repeat([]byte{0x77}, 64) // an AES-256-XTS key

	keyBytes, valueBytes := buildCryptoStateRecord(t, 0x1234, 9, kek, perFileKey)

	key, err := ParseCryptoStateKey(keyBytes)
	if err != nil {
		t.Fatalf("ParseCryptoStateKey: %v", err)
	}
	if key.Type != FileSystemRecordTypeCryptoState || key.FileID != 0x1234 || key.CryptoID != 9 {
		t.Fatalf("key fields wrong: %+v", key)
	}

	value, err := ParseCryptoStateValue(keyBytes, valueBytes)
	if err != nil {
		t.Fatalf("ParseCryptoStateValue: %v", err)
	}
	if value.KeyLen != uint16(len(perFileKey)+8) || len(value.PersistentKey) != len(perFileKey)+8 {
		t.Fatalf("wrapped key length wrong: %d", value.KeyLen)
	}
	if value.PersistentClass != 2 || value.Refcount != 1 {
		t.Fatalf("value fields wrong: %+v", value)
	}

	got, err := value.UnwrapPerFileKey(kek)
	if err != nil {
		t.Fatalf("UnwrapPerFileKey: %v", err)
	}
	if !bytes.Equal(got, perFileKey) {
		t.Fatalf("per-file key mismatch:\n got %x\nwant %x", got, perFileKey)
	}
}

func TestUnwrapPerFileKeyRejectsWrongKey(t *testing.T) {
	kek := bytes.Repeat([]byte{0x2a}, 32)
	perFileKey := bytes.Repeat([]byte{0x77}, 64)

	keyBytes, valueBytes := buildCryptoStateRecord(t, 0x1234, 9, kek, perFileKey)
	value, err := ParseCryptoStateValue(keyBytes, valueBytes)
	if err != nil {
		t.Fatalf("ParseCryptoStateValue: %v", err)
	}

	if _, err := value.UnwrapPerFileKey(bytes.Repeat([]byte{0x2b}, 32)); err == nil {
		t.Fatalf("wrong wrap key must not unwrap")
	}
	if _, err := value.UnwrapPerFileKey(nil); err == nil {
		t.Fatalf("missing wrap key must be refused")
	}
}

func TestParseCryptoStateValueRejectsGarbage(t *testing.T) {
	keyBytes := make([]byte, 24)
	binary.LittleEndian.PutUint64(keyBytes[0:8], (uint64(FileSystemRecordTypeCryptoState)<<60)|5)
	binary.LittleEndian.PutUint64(keyBytes[8:16], 1)

	// Value that claims a key longer than itself.
	valueBytes := make([]byte, 24)
	binary.LittleEndian.PutUint16(valueBytes[22:24], 200)
	if _, err := ParseCryptoStateValue(keyBytes, valueBytes); err == nil {
		t.Fatalf("oversized key length must be refused")
	}

	// Value with a zero key length.
	valueBytes = make([]byte, 24)
	if _, err := ParseCryptoStateValue(keyBytes, valueBytes); err == nil {
		t.Fatalf("zero key length must be refused")
	}

	// Short value.
	if _, err := ParseCryptoStateValue(keyBytes, valueBytes[:8]); err == nil {
		t.Fatalf("short value must be refused")
	}
}

// PerFileKey must map the well-known crypto identifiers without ever
// consulting a D record: unencrypted ids read in the clear (nil
// context), raw/sw-crypto ids use the whole-volume context, and the
// invalid id is an error.
func TestPerFileKeyWellKnownIdentifiers(t *testing.T) {
	volume := &Volume{
		pfkEnabled:        true,
		EncryptionContext: &EncryptionContext{Method: uint32(EncryptionMethodAES128XTS)},
		masterKey:         bytes.Repeat([]byte{0x11}, 32),
	}

	for _, id := range []uint64{CryptoIDSWUnencrypted, CryptoIDUnencrypted, CryptoIDSparseBundle} {
		ctx, err := volume.PerFileKey(nil, 7, id)
		if err != nil || ctx != nil {
			t.Fatalf("unencrypted id %d: ctx=%v err=%v, want nil,nil", id, ctx, err)
		}
	}
	for _, id := range []uint64{CryptoIDSWRaw, CryptoIDSoftwareCrypto} {
		ctx, err := volume.PerFileKey(nil, 7, id)
		if err != nil || ctx != volume.EncryptionContext {
			t.Fatalf("volume-key id %d: ctx=%v err=%v", id, ctx, err)
		}
	}
	if _, err := volume.PerFileKey(nil, 7, CryptoIDInvalid); err == nil {
		t.Fatalf("invalid id must be refused")
	}

	// On a locked volume the volume-key identifiers must refuse.
	locked := &Volume{pfkEnabled: true}
	if _, err := locked.PerFileKey(nil, 7, CryptoIDSoftwareCrypto); err == nil {
		t.Fatalf("locked volume must refuse the software-crypto id")
	}
}

// encryptXTSForTest mirrors EncryptionContext.cryptXTS's decryption,
// sector by sector: T = E(tweakKey, LE64(sector)), then per 16-byte
// block C = E(dataKey, P ^ T) ^ T with T multiplied by alpha.
func encryptXTSForTest(t *testing.T, key, plaintext []byte, sector uint64, sectorSize int) []byte {
	t.Helper()

	half := len(key) / 2
	dataCipher, err := aes.NewCipher(key[:half])
	if err != nil {
		t.Fatalf("data cipher: %v", err)
	}
	tweakCipher, err := aes.NewCipher(key[half:])
	if err != nil {
		t.Fatalf("tweak cipher: %v", err)
	}

	ciphertext := make([]byte, len(plaintext))
	sectorNumber := sector
	for offset := 0; offset+sectorSize <= len(plaintext); offset += sectorSize {
		tweak := make([]byte, 16)
		binary.LittleEndian.PutUint64(tweak[0:8], sectorNumber)
		tweakCipher.Encrypt(tweak, tweak)
		for blockOffset := offset; blockOffset < offset+sectorSize; blockOffset += 16 {
			block := make([]byte, 16)
			for i := range block {
				block[i] = plaintext[blockOffset+i] ^ tweak[i]
			}
			dataCipher.Encrypt(block, block)
			for i := range block {
				ciphertext[blockOffset+i] = block[i] ^ tweak[i]
			}
			multiplyTweakByAlpha(tweak)
		}
		sectorNumber++
	}
	return ciphertext
}

// A per-file-key extent read through FileSystemDataHandle must decrypt
// with the key the resolver returns, not with the volume key the handle
// carries; without the resolver the same bytes must come out garbled.
func TestReadDataBlockUsesPerFileKey(t *testing.T) {
	volumeKey := bytes.Repeat([]byte{0x23}, 32)
	perFileKey := bytes.Repeat([]byte{0x77}, 32)

	volumeContext, err := NewEncryptionContextForKey(volumeKey)
	if err != nil {
		t.Fatalf("volume context: %v", err)
	}
	perFileContext, err := NewEncryptionContextForKey(perFileKey)
	if err != nil {
		t.Fatalf("per-file context: %v", err)
	}

	plaintext := make([]byte, 4096)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	// One extent: physical block 0, crypto id 5. ReadDataBlock adjusts
	// the identifier by the block's position (0) and DataBlock.Read
	// turns it into the tweak sector (5 * 4096 / 512 = 40).
	ciphertext := encryptXTSForTest(t, perFileKey, plaintext, 40, 512)
	reader := bytes.NewReader(ciphertext)

	handle := &FileSystemDataHandle{
		IOHandle:          &IOHandle{BlockSize: 4096, BytesPerSector: 512},
		EncryptionContext: volumeContext,
		FileExtents: []*FileExtent{
			{PhysicalBlockNumber: 0, EncryptionIdentifier: 5, DataSize: 4096},
		},
		PerFileContext: func(cryptoID uint64) (*EncryptionContext, error) {
			if cryptoID != 5 {
				t.Errorf("resolver asked for crypto id %d, want 5", cryptoID)
			}
			return perFileContext, nil
		},
	}

	block, err := handle.ReadDataBlock(reader, 0, 0, 4096, 0)
	if err != nil {
		t.Fatalf("ReadDataBlock: %v", err)
	}
	if !bytes.Equal(block.Data, plaintext) {
		t.Fatalf("per-file key not used: block does not match plaintext")
	}

	// Without the resolver the handle falls back to the volume key and
	// the same ciphertext must not decrypt to the plaintext.
	handle.PerFileContext = nil
	block, err = handle.ReadDataBlock(reader, 0, 0, 4096, 0)
	if err != nil {
		t.Fatalf("ReadDataBlock without resolver: %v", err)
	}
	if bytes.Equal(block.Data, plaintext) {
		t.Fatalf("volume key must not decrypt a per-file-key block")
	}
}

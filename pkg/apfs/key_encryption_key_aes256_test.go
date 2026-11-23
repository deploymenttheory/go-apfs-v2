package apfs

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func derField(tag byte, value []byte) []byte {
	out := []byte{tag}
	switch {
	case len(value) < 0x80:
		out = append(out, byte(len(value)))
	case len(value) < 0x100:
		out = append(out, 0x81, byte(len(value)))
	default:
		out = append(out, 0x82, byte(len(value)>>8), byte(len(value)))
	}
	return append(out, value...)
}

// A 64-byte volume key is wrapped into 72 bytes; it must survive parsing and
// unwrapping instead of being refused as an oversized 40-byte record.
func TestKeyEncryptionKeyAES256Wrap(t *testing.T) {
	var kek [32]byte
	var vek256 [64]byte
	if _, err := rand.Read(kek[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(vek256[:]); err != nil {
		t.Fatal(err)
	}

	wrapped, err := AESKeyWrap(kek[:], 256, vek256[:])
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if len(wrapped) != 72 {
		t.Fatalf("wrapped length = %d, want 72", len(wrapped))
	}

	kekRecord := &KeyEncryptionKey{EncryptionMethod: 0, WrappedKEK: wrapped}
	got, err := kekRecord.UnlockWithKey(kek[:])
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if !bytes.Equal(got, vek256[:]) {
		t.Fatal("unwrapped key does not match the 64-byte volume key")
	}

	// The DER reader must accept the 72-byte wrapped form.
	info := make([]byte, 8)
	binary.LittleEndian.PutUint32(info, 0)
	payload := derField(0x80, []byte{0})
	payload = append(payload, derField(0x81, make([]byte, 16))...)
	payload = append(payload, derField(0x82, info)...)
	payload = append(payload, derField(0x83, wrapped)...)
	record := derField(0x80, []byte{0})
	record = append(record, derField(0x81, make([]byte, 32))...)
	record = append(record, derField(0x82, make([]byte, 8))...)
	record = append(record, derField(0xa3, payload)...)
	der := derField(0x30, record)

	parsed := &KeyEncryptionKey{}
	if err := parsed.ReadData(der); err != nil {
		t.Fatalf("ReadData: %v", err)
	}
	if len(parsed.WrappedKEK) != 72 {
		t.Fatalf("parsed wrapped length = %d, want 72", len(parsed.WrappedKEK))
	}
	got, err = parsed.UnlockWithKey(kek[:])
	if err != nil {
		t.Fatalf("unlock parsed: %v", err)
	}
	if !bytes.Equal(got, vek256[:]) {
		t.Fatal("parsed record did not unwrap to the 64-byte volume key")
	}
}

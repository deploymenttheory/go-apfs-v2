package disk

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"
)

// gptImage builds a two-sector image holding a protective sector and a GPT
// header whose partition-entry count is entries, with no entries behind it.
func gptImage(t *testing.T, entries uint32) []byte {
	t.Helper()
	h := GPTHeader{
		Revision:       0x00010000,
		HeaderSize:     gptSectorSize - 420,
		HeaderStartLBA: 1,
		EntriesStart:   2,
		EntriesCount:   entries,
		EntriesSize:    128,
	}
	copy(h.Signature[:], gptSignature)
	var buf bytes.Buffer
	buf.Write(make([]byte, gptSectorSize))
	if err := binary.Write(&buf, binary.LittleEndian, &h); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestGPTEntriesAllocationUnbounded measures what a raw image's GPT header can
// make the opener allocate. The header's entry count is trusted: a 1 KiB image
// claiming 1<<20 entries makes findAPFSPartitionInGPT allocate the full
// 128 MiB table before it discovers the entries are not there. The count is a
// uint32, so a header claiming 0xFFFFFFFF entries asks for about 512 GiB. The
// DMG path bounds this; the raw-image path does not.
func TestGPTEntriesAllocationUnbounded(t *testing.T) {
	const entries = 1 << 20
	img := gptImage(t, entries)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := findAPFSPartitionInGPT(bytes.NewReader(img))
	runtime.ReadMemStats(&after)

	if err == nil {
		t.Fatal("expected an error for a GPT whose entries are missing")
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	want := uint64(entries) * 128
	if allocated < want {
		t.Fatalf("allocated %d bytes for a %d-byte image; the entry count now appears to be bounded", allocated, len(img))
	}
	t.Logf("LIMIT gpt entries allocation = %d MiB allocated for a %d-byte image claiming %d entries (err: %v)",
		allocated>>20, len(img), entries, err)
}

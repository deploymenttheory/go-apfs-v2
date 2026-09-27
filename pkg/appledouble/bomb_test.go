package appledouble

import (
	"encoding/binary"
	"testing"
)

// TestDecodeResourceEntryAliasingBounded pins F4 (entry-table variant): many
// resource entries each pointing at the same region must not multiply the
// bytes copied out.
func TestDecodeResourceEntryAliasingBounded(t *testing.T) {
	const n = 3
	const dataLen = 100
	total := 26 + 12*n + dataLen
	b := make([]byte, total)
	binary.BigEndian.PutUint32(b[0:], magic)
	binary.BigEndian.PutUint32(b[4:], version)
	binary.BigEndian.PutUint16(b[24:], n)
	dataOff := 26 + 12*n
	for i := 0; i < n; i++ {
		e := b[26+12*i:]
		binary.BigEndian.PutUint32(e[0:], entryResource)
		binary.BigEndian.PutUint32(e[4:], uint32(dataOff))
		binary.BigEndian.PutUint32(e[8:], uint32(dataLen))
	}
	// n*dataLen = 300 > total (162): the aliased copies exceed the file.
	if _, err := Decode(b); err == nil {
		t.Fatal("aliased resource entries were accepted; cumulative copy is unbounded")
	}
}

// TestDecodeAttrAliasingBounded pins F4 (attribute-value variant): many
// attribute entries each pointing at the same near-whole-file region must be
// rejected rather than each retained.
func TestDecodeAttrAliasingBounded(t *testing.T) {
	const numAttrs = 3
	const valLen = 100
	finderOff := 38
	attrOff := finderOff + 32 // header sits right after the 32-byte FinderInfo
	hdrLen := 36
	entriesOff := attrOff + hdrLen
	total := entriesOff + numAttrs*12
	b := make([]byte, total)
	binary.BigEndian.PutUint32(b[0:], magic)
	binary.BigEndian.PutUint32(b[4:], version)
	binary.BigEndian.PutUint16(b[24:], 1) // one entry: the Finder region
	e := b[26:]
	binary.BigEndian.PutUint32(e[0:], entryFinder)
	binary.BigEndian.PutUint32(e[4:], uint32(finderOff))
	binary.BigEndian.PutUint32(e[8:], uint32(total-finderOff))
	copy(b[attrOff:], attrMagic)
	binary.BigEndian.PutUint32(b[attrOff+8:], uint32(total)) // totalSize <= len(b)
	binary.BigEndian.PutUint16(b[attrOff+34:], numAttrs)
	for i := 0; i < numAttrs; i++ {
		ae := b[entriesOff+12*i:]
		binary.BigEndian.PutUint32(ae[0:], 0)      // valOff: all alias offset 0
		binary.BigEndian.PutUint32(ae[4:], valLen) // valLen
		ae[10] = 1                                 // nameLen
		ae[11] = 'a'
	}
	// numAttrs*valLen = 300 > total (~178): rejected instead of retained.
	if _, err := Decode(b); err == nil {
		t.Fatal("aliased attribute values were accepted; retained memory is unbounded")
	}
}

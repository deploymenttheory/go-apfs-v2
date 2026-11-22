package apfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func fextKey(privateID, logicalAddr uint64) []byte {
	key := make([]byte, FileExtentTreeKeySize)
	binary.LittleEndian.PutUint64(key[0:8], privateID)
	binary.LittleEndian.PutUint64(key[8:16], logicalAddr)
	return key
}

func fextValue(length, physicalBlock uint64) []byte {
	value := make([]byte, FileExtentTreeValueSize)
	binary.LittleEndian.PutUint64(value[0:8], length)
	binary.LittleEndian.PutUint64(value[8:16], physicalBlock)
	return value
}

func fextBranch(privateID, logicalAddr, childBlock uint64) *BTreeEntry {
	child := make([]byte, 8)
	binary.LittleEndian.PutUint64(child, childBlock)
	return &BTreeEntry{KeyData: fextKey(privateID, logicalAddr), ValueData: child}
}

func fextEntry(privateID, logicalAddr, length, physicalBlock uint64) *BTreeEntry {
	return &BTreeEntry{KeyData: fextKey(privateID, logicalAddr), ValueData: fextValue(length, physicalBlock)}
}

func fextNode(level uint16, entries ...*BTreeEntry) *BTreeNode {
	flags := uint16(BTreeNodeFlagRoot)
	if level == 0 {
		flags |= BTreeNodeFlagLeaf
	}
	return &BTreeNode{
		NodeHeader:     &BTreeNodeHeader{Flags: flags, Level: level},
		Entries:        entries,
		FixedKeySize:   FileExtentTreeKeySize,
		FixedValueSize: FileExtentTreeValueSize,
	}
}

func fextTestTree(t *testing.T) *FileExtentTree {
	t.Helper()

	const rootBlock = 700
	const firstLeafBlock = 701
	const secondLeafBlock = 702

	handle := &IOHandle{BlockSize: 4096, BytesPerSector: 512}
	handle.putCachedNode(rootBlock, fextNode(1,
		fextBranch(7, 0, firstLeafBlock),
		fextBranch(7, 12288, secondLeafBlock),
	))
	handle.putCachedNode(firstLeafBlock, fextNode(0,
		fextEntry(7, 0, 4096, 100),
		// The length field carries extent flags in its high bits; only the
		// low 60 bits are the data length.
		fextEntry(7, 4096, 0xf000000000002000, 101),
	))
	handle.putCachedNode(secondLeafBlock, fextNode(0,
		fextEntry(7, 12288, 4096, 102),
		fextEntry(9, 0, 4096, 200),
	))

	tree, err := NewFileExtentTree(handle, nil, rootBlock, 1)
	if err != nil {
		t.Fatalf("NewFileExtentTree: %v", err)
	}
	return tree
}

func TestFileExtentTreeExtentsSpanLeaves(t *testing.T) {
	tree := fextTestTree(t)

	extents, err := tree.ExtentsForPrivateID(bytes.NewReader(nil), 7)
	if err != nil {
		t.Fatalf("ExtentsForPrivateID: %v", err)
	}

	want := []struct {
		logical uint64
		size    uint64
		block   uint64
	}{
		{0, 4096, 100},
		{4096, 8192, 101},
		{12288, 4096, 102},
	}
	if len(extents) != len(want) {
		t.Fatalf("got %d extents, want %d", len(extents), len(want))
	}
	for i, expected := range want {
		got := extents[i]
		if got.LogicalOffset != expected.logical || got.DataSize != expected.size || got.PhysicalBlockNumber != expected.block {
			t.Errorf("extent %d = {logical %d, size %d, block %d}, want {logical %d, size %d, block %d}",
				i, got.LogicalOffset, got.DataSize, got.PhysicalBlockNumber,
				expected.logical, expected.size, expected.block)
		}
		if got.EncryptionIdentifier != 0 {
			t.Errorf("extent %d encryption id = %d, want 0", i, got.EncryptionIdentifier)
		}
	}

	// A different private id in the same leaves is not mixed in.
	other, err := tree.ExtentsForPrivateID(bytes.NewReader(nil), 9)
	if err != nil {
		t.Fatalf("ExtentsForPrivateID(9): %v", err)
	}
	if len(other) != 1 || other[0].PhysicalBlockNumber != 200 {
		t.Fatalf("private id 9 extents = %+v", other)
	}

	// Unknown and below-minimum ids are empty, not errors.
	for _, id := range []uint64{5, 8, 10} {
		got, err := tree.ExtentsForPrivateID(bytes.NewReader(nil), id)
		if err != nil {
			t.Fatalf("ExtentsForPrivateID(%d): %v", id, err)
		}
		if len(got) != 0 {
			t.Errorf("ExtentsForPrivateID(%d) = %+v, want none", id, got)
		}
	}
}

func TestFileExtentTreeRootLeaf(t *testing.T) {
	handle := &IOHandle{BlockSize: 4096, BytesPerSector: 512}
	handle.putCachedNode(800, fextNode(0,
		fextEntry(3, 0, 4096, 42),
		fextEntry(4, 0, 4096, 43),
	))

	tree, err := NewFileExtentTree(handle, nil, 800, 1)
	if err != nil {
		t.Fatalf("NewFileExtentTree: %v", err)
	}
	extents, err := tree.ExtentsForPrivateID(bytes.NewReader(nil), 3)
	if err != nil {
		t.Fatalf("ExtentsForPrivateID: %v", err)
	}
	if len(extents) != 1 || extents[0].PhysicalBlockNumber != 42 {
		t.Fatalf("root leaf extents = %+v", extents)
	}
}

func TestFileExtentTreeRejectsMalformedBranch(t *testing.T) {
	handle := &IOHandle{BlockSize: 4096, BytesPerSector: 512}
	handle.putCachedNode(900, &BTreeNode{
		NodeHeader: &BTreeNodeHeader{Flags: BTreeNodeFlagRoot, Level: 1},
		Entries: []*BTreeEntry{{
			KeyData:   fextKey(7, 0),
			ValueData: []byte{1, 2, 3, 4},
		}},
		FixedKeySize:   FileExtentTreeKeySize,
		FixedValueSize: FileExtentTreeValueSize,
	})

	tree, err := NewFileExtentTree(handle, nil, 900, 1)
	if err != nil {
		t.Fatalf("NewFileExtentTree: %v", err)
	}
	if _, err := tree.ExtentsForPrivateID(bytes.NewReader(nil), 7); err == nil {
		t.Fatal("malformed branch entry accepted")
	}
}

func TestFileExtentTreeRejectsShortKey(t *testing.T) {
	handle := &IOHandle{BlockSize: 4096, BytesPerSector: 512}
	handle.putCachedNode(901, fextNode(0, &BTreeEntry{
		KeyData:   []byte{1, 2, 3, 4},
		ValueData: fextValue(4096, 1),
	}))

	tree, err := NewFileExtentTree(handle, nil, 901, 1)
	if err != nil {
		t.Fatalf("NewFileExtentTree: %v", err)
	}
	if _, err := tree.ExtentsForPrivateID(bytes.NewReader(nil), 7); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestFileExtentTreeRootInfoValidation(t *testing.T) {
	for _, info := range []*BTreeInfo{
		{NodeSize: 8192, KeySize: 16, ValueSize: 16},
		{NodeSize: 4096, KeySize: 8, ValueSize: 16},
		{NodeSize: 4096, KeySize: 16, ValueSize: 8},
	} {
		handle := &IOHandle{BlockSize: 4096, BytesPerSector: 512}
		root := fextNode(0)
		root.Info = info
		handle.putCachedNode(902, root)
		tree, err := NewFileExtentTree(handle, nil, 902, 1)
		if err != nil {
			t.Fatalf("NewFileExtentTree: %v", err)
		}
		if _, err := tree.RootNode(bytes.NewReader(nil)); err == nil {
			t.Fatalf("invalid btree info accepted: %+v", info)
		}
	}
}

func TestNewFileExtentTreeValidation(t *testing.T) {
	if _, err := NewFileExtentTree(nil, nil, 1, 1); err == nil {
		t.Fatal("nil IO handle accepted")
	}
	handle := &IOHandle{BlockSize: 4096, BytesPerSector: 512}
	if _, err := NewFileExtentTree(handle, nil, 0, 1); err == nil {
		t.Fatal("zero root block accepted")
	}
}

// fextErrReader always fails so the read error path is exercised.
type fextErrReader struct{}

func (fextErrReader) ReadAt([]byte, int64) (int, error) {
	return 0, errors.New("read failed")
}

func TestFileExtentTreeReadFailure(t *testing.T) {
	handle := &IOHandle{BlockSize: 4096, BytesPerSector: 512}
	tree, err := NewFileExtentTree(handle, nil, 12345, 1)
	if err != nil {
		t.Fatalf("NewFileExtentTree: %v", err)
	}
	if _, err := tree.ExtentsForPrivateID(fextErrReader{}, 7); err == nil {
		t.Fatal("read failure accepted")
	}
}

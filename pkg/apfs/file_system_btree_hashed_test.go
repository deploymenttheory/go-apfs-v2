package apfs

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// hashedFSBranch builds a hashed B-tree branch entry. The value is
// btn_index_node_val_t: a child OID relative to the tree's root OID, followed
// by the child hash (32 bytes for the SHA-256 hash used on sealed volumes).
func hashedFSBranch(id, relativeChildOID uint64) *BTreeEntry {
	value := make([]byte, 8+32)
	binary.LittleEndian.PutUint64(value[0:8], relativeChildOID)
	return &BTreeEntry{
		KeyData:   boundaryFSKey(id, FileSystemRecordTypeInode),
		ValueData: value,
	}
}

func TestHashedBTreeChildOIDIsRelativeToRoot(t *testing.T) {
	r := bytes.NewReader(nil)
	const rootOID = 100
	const relativeChildOID = 5

	root := boundaryFSNode(1, hashedFSBranch(10, relativeChildOID))
	root.NodeHeader.Flags |= BTreeNodeFlagRoot | BTreeNodeFlagHashed

	nodes := map[uint64]*BTreeNode{
		rootOID: root,
		// boundaryFSTree maps virtual OID N to the node cached for N.
		rootOID + relativeChildOID: boundaryFSNode(0,
			&BTreeEntry{KeyData: boundaryFSKey(10, FileSystemRecordTypeInode), ValueData: []byte{7}},
		),
	}

	got, err := boundaryFSTree(nodes).AllRecordsForOID(r, 10)
	if err != nil {
		t.Fatalf("AllRecordsForOID: %v", err)
	}
	if len(got) != 1 || len(got[0].ValueData) != 1 || got[0].ValueData[0] != 7 {
		t.Fatalf("hashed relative child records = %+v", got)
	}

	// The same tree without the hashed flag treats 5 as an absolute OID, which
	// does not exist, proving the test exercises the relative-OID path.
	nodes[rootOID].NodeHeader.Flags &^= BTreeNodeFlagHashed
	if _, err := boundaryFSTree(nodes).AllRecordsForOID(r, 10); err == nil {
		t.Fatal("absolute OID lookup unexpectedly succeeded")
	}
}

func TestHashedBTreeEntryByIdentifier(t *testing.T) {
	r := bytes.NewReader(nil)
	const rootOID = 100
	const relativeChildOID = 5

	root := boundaryFSNode(1, hashedFSBranch(40, relativeChildOID), hashedFSBranch(60, relativeChildOID))
	root.NodeHeader.Flags |= BTreeNodeFlagRoot | BTreeNodeFlagHashed

	nodes := map[uint64]*BTreeNode{
		rootOID: root,
		rootOID + relativeChildOID: boundaryFSNode(0,
			&BTreeEntry{KeyData: boundaryFSKey(40, FileSystemRecordTypeInode), ValueData: []byte{1}},
		),
	}

	node, entry, err := boundaryFSTree(nodes).EntryByIdentifier(r, 40, FileSystemRecordTypeInode, 1)
	if err != nil {
		t.Fatalf("EntryByIdentifier: %v", err)
	}
	if node == nil || entry == nil || len(entry.ValueData) != 1 || entry.ValueData[0] != 1 {
		t.Fatalf("hashed EntryByIdentifier = %v, %+v", node, entry)
	}
}

func TestBTreeNodeHeaderIsHashed(t *testing.T) {
	if !(&BTreeNodeHeader{Flags: BTreeNodeFlagHashed}).IsHashed() {
		t.Fatal("hashed flag not recognised")
	}
	if (&BTreeNodeHeader{Flags: BTreeNodeFlagLeaf}).IsHashed() {
		t.Fatal("leaf flag treated as hashed")
	}
}

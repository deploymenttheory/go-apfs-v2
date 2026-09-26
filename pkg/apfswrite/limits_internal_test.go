// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import "testing"

// omapRootCapacity returns how many mappings the single object-map root-leaf
// can hold: it is bounded both by the table of contents reserved for it and by
// the space left for fixed-size keys and values.
func omapRootCapacity(b *builder) int {
	toc := b.tocAreaBytes(objectTypeOmap)
	byTOC := toc / sizeofKvoff
	body := int(b.blocksize) - sizeofBtreeNodePhys - toc - sizeofBtreeInfo
	bySpace := body / (sizeofOmapKey + sizeofOmapVal)
	return min(byTOC, bySpace)
}

// TestLimitOmapCapacity measures the volume object map's capacity. It holds one
// mapping for the file-system tree root and one per leaf, so it is not the
// binding limit while it can map every leaf the file-system tree may have.
func TestLimitOmapCapacity(t *testing.T) {
	b := &builder{blocksize: 4096}
	capacity := omapRootCapacity(b)
	need := 1 + maxFSTreeLeaves
	if capacity < need {
		t.Fatalf("omap root holds %d mappings, fewer than the %d a full file-system tree needs", capacity, need)
	}
	t.Logf("LIMIT omap root-leaf mappings = %d (a full %d-leaf file-system tree needs %d)", capacity, maxFSTreeLeaves, need)
}

// TestLimitExtentrefCapacity measures the extentref tree's capacity: one record
// per non-empty file, up to maxExtentrefLeaves leaves. It shows the file-system
// tree limit is reached first, so the extentref limit cannot be hit today.
func TestLimitExtentrefCapacity(t *testing.T) {
	perLeaf := extentrefRecordsPerLeaf(4096)
	capacity := perLeaf * maxExtentrefLeaves
	// TestLimitFSTreeFileCount measures the file-system tree refusing at 851
	// small files; anything the extentref tree can hold beyond that is moot.
	const fsTreeLimit = 850
	if capacity <= fsTreeLimit {
		t.Fatalf("extentref tree holds %d extents, not more than the file-system tree's %d files", capacity, fsTreeLimit)
	}
	t.Logf("LIMIT extentref records = %d per leaf x %d leaves = %d non-empty files (unreachable: fs-tree stops at %d)",
		perLeaf, maxExtentrefLeaves, capacity, fsTreeLimit)
}

// Package decmpfs decodes Apple's transparent file compression.
//
// decmpfs is a property of the file, not of the file system: a
// com.apple.decmpfs extended attribute holds a 16-byte header naming the
// compression type and the uncompressed size, and the compressed bytes live
// either immediately after that header ("inline") or in the file's resource
// fork, chunked into 64 KiB blocks. HFS+ introduced it and APFS carries it
// unchanged, so both readers need the same decoder and neither should own it.
//
// The caller supplies a Source — the byte range the compressed data lives in —
// and this package handles the header, the block table and the codecs. What it
// deliberately does not know is how to find either of those things, since that
// is where the two file systems differ.
package decmpfs

import (
	"bytes"
	"fmt"
)

// BlockSize is the uncompressed size of one decmpfs chunk. Every block except
// the last decompresses to exactly this much.
//
// It is unrelated to any file system's block size.
const BlockSize = 65536

// Internal compression method codes. These are this package's own vocabulary,
// not the decmpfs type numbers stored on disk; MethodFor translates. Several
// on-disk types share one method, because whether the data sits inline or in a
// resource fork is decided by where it is read from rather than by how it is
// decoded.
const (
	MethodNone    = 0
	MethodDeflate = 1
	MethodLZFSE   = 2
	MethodLZVN    = 3

	// MethodUnknown5 is retained only because it is reachable through a
	// deprecated alias in pkg/apfs. Nothing maps to it: see MethodFor.
	MethodUnknown5 = 5
)

// Source is the compressed byte range a decmpfs stream lives in: an APFS data
// stream, or an HFS+ resource fork, or the attribute value itself when the data
// is stored inline.
type Source interface {
	ReadAt(p []byte, off int64) (int, error)

	// Size is the length of the compressed range in bytes.
	Size() uint64
}

// MethodFor maps a raw com.apple.decmpfs type to the internal method code.
//
// The types come in attribute/resource-fork pairs, the odd member of each pair
// storing the data inline in the com.apple.decmpfs attribute and the even
// member storing it in the com.apple.ResourceFork attribute, chunked. The
// numbering is Apple's, from copyfile.c:
//
//	 1       uncompressed, stored inline
//	 3 /  4  zlib
//	 5       de-duplication within the generation store
//	 6       unused
//	 7 /  8  LZVN
//	 9 / 10  uncompressed
//	11 / 12  LZFSE
//	13 / 14  LZBITMAP
//
// The attribute-versus-resource-fork distinction is handled by where the data
// is read from, not by the method code, so each supported pair maps to one
// method.
func MethodFor(decmpfsType uint32) (int, error) {
	switch decmpfsType {
	case 3, 4:
		return MethodDeflate, nil
	case 7, 8:
		return MethodLZVN, nil
	case 11, 12:
		return MethodLZFSE, nil

	case 5:
		// Not a compression type at all: it marks de-duplication within the
		// generation store, and the content is not described by this attribute.
		// This was previously decoded as sparse and answered with zeros, which
		// silently returned the wrong contents for a file that has real data
		// somewhere else. Refusing is the only safe answer.
		return 0, fmt.Errorf("decmpfs type 5 (de-duplication within the generation store) does not describe file content and is not supported")
	case 1:
		return 0, fmt.Errorf("decmpfs uncompressed inline storage (type 1) is not supported yet")
	case 9, 10:
		return 0, fmt.Errorf("decmpfs uncompressed storage (type %d) is not supported yet", decmpfsType)
	case 13, 14:
		return 0, fmt.Errorf("decmpfs LZBITMAP compression (type %d) is not supported yet", decmpfsType)
	default:
		return 0, fmt.Errorf("unsupported decmpfs compression type: %d", decmpfsType)
	}
}

// CheckInline verifies that attrValue is a whole com.apple.decmpfs attribute
// with its header still attached, as inline decoding requires.
//
// The block-offset loader identifies inline storage by finding the header magic
// at offset zero. Handing it the payload with the header stripped hides that
// magic and sends the stream down the resource-fork branch, which misparses the
// first bytes of the compressed data as a block-offset table and produces
// plausible nonsense. Checking here makes that mistake fail loudly instead.
func CheckInline(attrValue []byte) error {
	if len(attrValue) <= HeaderSize {
		return fmt.Errorf("inline decmpfs attribute is %d bytes: too short to hold a %d-byte header and any data",
			len(attrValue), HeaderSize)
	}
	if !bytes.Equal(attrValue[:4], HeaderSignature[:]) {
		return fmt.Errorf("inline decmpfs data must carry its %q header: the block-offset loader identifies inline storage by that magic at offset zero",
			string(HeaderSignature[:]))
	}
	return nil
}

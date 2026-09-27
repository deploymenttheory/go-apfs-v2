// Package appledouble encodes and decodes the AppleDouble "._" sidecar
// files that carry a file's Finder info, resource fork and extended
// attributes where the file system cannot: in a cpio payload, on a
// non-Apple volume, in a zip made by Finder.
//
// The layout is the one macOS's kernel writes (xnu bsd/vfs/vfs_xattr.c)
// and pkgbuild copies into a payload, decoded from pkgbuild's output
// (testdata/cli/component-links.probe.json):
//
//	0    magic        00 05 16 07
//	4    version      00 02 00 00
//	8    filler       "Mac OS X        " (16 bytes)
//	24   numEntries   u16 = 2
//	26   entry        id 9 (Finder info), offset 50, length = attrEnd - 50
//	38   entry        id 2 (resource fork), offset attrEnd, length
//	50   Finder info  32 bytes
//	82   pad          2 bytes
//	84   ATTR header  "ATTR", debug_tag, total_size, data_start,
//	                  data_length, reserved[3], flags u16, num_attrs u16
//	120  attr entries {offset u32, length u32, flags u16, namelen u8,
//	                  name NUL} each padded to a 4-byte boundary, sorted
//	                  by name
//	data_start        values, in entry order
//	attrEnd           resource fork bytes
//
// All integers are big-endian. total_size is attrEnd: the Finder-info
// entry covers everything up to the resource fork. com.apple.FinderInfo
// and com.apple.ResourceFork live in their own slots, never in the
// attribute list.
package appledouble

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"path"
	"sort"
	"strings"
)

// Attr is one extended attribute.
type Attr struct {
	Name  string
	Value []byte
}

// File is the content of a sidecar.
type File struct {
	FinderInfo   [32]byte
	ResourceFork []byte
	// Attrs are the extended attributes other than Finder info and the
	// resource fork; Encode sorts them by name.
	Attrs []Attr
}

// Names of the attributes that have their own slots.
const (
	FinderInfoName   = "com.apple.FinderInfo"
	ResourceForkName = "com.apple.ResourceFork"
)

// Layout constants.
const (
	magic          = 0x00051607
	version        = 0x00020000
	filler         = "Mac OS X        "
	entryFinder    = 9
	entryResource  = 2
	finderOffset   = 50
	attrHeaderOff  = 84
	attrEntriesOff = 120
	attrMagic      = "ATTR"
	// MaxHeader bounds the header and attribute entry table, not the values.
	// Apple's copyfile uses ATTR_MAX_HDR_SIZE = 65536 + 18. Entry records are
	// four-byte aligned, so the largest encodable data_start is 65552.
	MaxHeader = 65536 + 18
)

var (
	// ErrNotAppleDouble reports bytes that do not start like a sidecar.
	ErrNotAppleDouble = errors.New("appledouble: not an AppleDouble file")
	// ErrTooLarge reports an attribute set the format cannot hold.
	ErrTooLarge = errors.New("appledouble: header, data offsets or lengths exceed format or address-space limits")
)

// IsSidecarName reports whether a payload or file name is an AppleDouble
// sidecar: its base name starts with "._".
func IsSidecarName(name string) bool {
	return strings.HasPrefix(path.Base(name), "._")
}

// SidecarName returns the sidecar name for a path: "./a/b" → "./a/._b".
func SidecarName(p string) string {
	dir, base := path.Split(p)
	return dir + "._" + base
}

// OwnerName returns the path a sidecar belongs to, and false if the
// name is not a sidecar's.
func OwnerName(p string) (string, bool) {
	dir, base := path.Split(p)
	if !strings.HasPrefix(base, "._") {
		return "", false
	}
	return dir + base[2:], true
}

// FromXattrs builds a File from a set of extended attributes, lifting
// Finder info and the resource fork into their slots.
func FromXattrs(attrs map[string][]byte) *File {
	f := &File{}
	for name, value := range attrs {
		switch name {
		case FinderInfoName:
			copy(f.FinderInfo[:], value)
		case ResourceForkName:
			f.ResourceFork = append([]byte(nil), value...)
		default:
			f.Attrs = append(f.Attrs, Attr{Name: name, Value: append([]byte(nil), value...)})
		}
	}
	f.sortAttrs()
	return f
}

// Xattrs returns the file's content as extended attributes, with Finder
// info and the resource fork under their names when present.
func (f *File) Xattrs() map[string][]byte {
	out := make(map[string][]byte, len(f.Attrs)+2)
	for _, a := range f.Attrs {
		out[a.Name] = a.Value
	}
	if f.FinderInfo != [32]byte{} {
		out[FinderInfoName] = append([]byte(nil), f.FinderInfo[:]...)
	}
	if len(f.ResourceFork) > 0 {
		out[ResourceForkName] = append([]byte(nil), f.ResourceFork...)
	}
	return out
}

// Empty reports whether the file carries nothing.
func (f *File) Empty() bool {
	return f.FinderInfo == [32]byte{} && len(f.ResourceFork) == 0 && len(f.Attrs) == 0
}

func (f *File) sortAttrs() {
	sort.SliceStable(f.Attrs, func(i, j int) bool { return f.Attrs[i].Name < f.Attrs[j].Name })
}

func entrySize(name string) int {
	return (11 + len(name) + 1 + 3) &^ 3
}

// Encode writes the sidecar bytes.
func (f *File) Encode() ([]byte, error) {
	f.sortAttrs()
	entries := 0
	var valueBytes uint64
	for _, a := range f.Attrs {
		if a.Name == "" || len(a.Name) > 127 || strings.IndexByte(a.Name, 0) >= 0 {
			return nil, fmt.Errorf("appledouble: invalid attribute name %q", a.Name)
		}
		if entrySize(a.Name) > MaxHeader-attrEntriesOff-entries {
			return nil, ErrTooLarge
		}
		entries += entrySize(a.Name)
		valueBytes += uint64(len(a.Value))
		if valueBytes > math.MaxUint32 {
			return nil, ErrTooLarge
		}
	}
	dataStart := attrEntriesOff + entries
	bufferSize, err := encodedSize(uint64(dataStart), valueBytes, uint64(len(f.ResourceFork)))
	if err != nil {
		return nil, err
	}
	values := int(valueBytes)
	attrEnd := dataStart + values

	var b bytes.Buffer
	b.Grow(bufferSize)
	_ = binary.Write(&b, binary.BigEndian, uint32(magic))
	_ = binary.Write(&b, binary.BigEndian, uint32(version))
	b.WriteString(filler)
	_ = binary.Write(&b, binary.BigEndian, uint16(2))
	_ = binary.Write(&b, binary.BigEndian, uint32(entryFinder))
	_ = binary.Write(&b, binary.BigEndian, uint32(finderOffset))
	_ = binary.Write(&b, binary.BigEndian, uint32(attrEnd-finderOffset))
	_ = binary.Write(&b, binary.BigEndian, uint32(entryResource))
	_ = binary.Write(&b, binary.BigEndian, uint32(attrEnd))
	_ = binary.Write(&b, binary.BigEndian, uint32(len(f.ResourceFork)))
	b.Write(f.FinderInfo[:])
	b.Write([]byte{0, 0})
	b.WriteString(attrMagic)
	_ = binary.Write(&b, binary.BigEndian, uint32(0)) // debug_tag
	_ = binary.Write(&b, binary.BigEndian, uint32(attrEnd))
	_ = binary.Write(&b, binary.BigEndian, uint32(dataStart))
	_ = binary.Write(&b, binary.BigEndian, uint32(values))
	b.Write(make([]byte, 12)) // reserved
	_ = binary.Write(&b, binary.BigEndian, uint16(0))
	_ = binary.Write(&b, binary.BigEndian, uint16(len(f.Attrs)))
	off := dataStart
	for _, a := range f.Attrs {
		valueOffset := off
		// copyfile leaves the zero-initialized offset for an empty value.
		// Presence is represented by the named entry, not by a data pointer.
		if len(a.Value) == 0 {
			valueOffset = 0
		}
		_ = binary.Write(&b, binary.BigEndian, uint32(valueOffset))
		_ = binary.Write(&b, binary.BigEndian, uint32(len(a.Value)))
		_ = binary.Write(&b, binary.BigEndian, uint16(0))
		b.WriteByte(byte(len(a.Name) + 1))
		b.WriteString(a.Name)
		b.WriteByte(0)
		for b.Len()%4 != 0 {
			b.WriteByte(0)
		}
		off += len(a.Value)
	}
	for _, a := range f.Attrs {
		b.Write(a.Value)
	}
	b.Write(f.ResourceFork)
	return b.Bytes(), nil
}

// Validate wire widths and address space before converting sizes or allocating.
// Values may extend beyond the header buffer; the fork has its own uint32 length.
func encodedSize(header, values, fork uint64) (int, error) {
	if header > MaxHeader || values > math.MaxUint32-header || fork > math.MaxUint32 {
		return 0, ErrTooLarge
	}
	total := header + values + fork
	if total > uint64(math.MaxInt) {
		return 0, ErrTooLarge
	}
	return int(total), nil
}

// Sniff reports whether b starts with the AppleDouble magic and version.
func Sniff(b []byte) bool {
	return len(b) >= 8 && binary.BigEndian.Uint32(b) == magic && binary.BigEndian.Uint32(b[4:]) == version
}

// Decode parses a sidecar. It tolerates files without an attribute
// section, with no attributes, and with either alignment before the
// ATTR header.
func Decode(b []byte) (*File, error) {
	if !Sniff(b) || len(b) < 26 {
		return nil, ErrNotAppleDouble
	}
	n := int(binary.BigEndian.Uint16(b[24:]))
	if len(b) < 26+12*n {
		return nil, fmt.Errorf("appledouble: truncated entry table")
	}
	f := &File{}
	// A real sidecar stores each region (resource fork, attribute values)
	// once and contiguously, so the bytes copied out can never exceed the
	// file. Without this budget a table of many entries, or many attributes,
	// each pointing at the same near-whole-file region would have every copy
	// retained: O(entries x len(b)) memory from a small input.
	copyBudget := len(b)
	spend := func(nbytes int) error {
		copyBudget -= nbytes
		if copyBudget < 0 {
			return fmt.Errorf("appledouble: copied data exceeds the file size")
		}
		return nil
	}
	var finderOff, finderLen int
	for i := 0; i < n; i++ {
		e := b[26+12*i:]
		id := binary.BigEndian.Uint32(e)
		off := int(binary.BigEndian.Uint32(e[4:]))
		length := int(binary.BigEndian.Uint32(e[8:]))
		if off < 0 || length < 0 || off > len(b) || length > len(b)-off {
			return nil, fmt.Errorf("appledouble: entry %d (offset %d, length %d) outside the file", id, off, length)
		}
		switch id {
		case entryFinder:
			finderOff, finderLen = off, length
		case entryResource:
			if err := spend(length); err != nil {
				return nil, err
			}
			f.ResourceFork = append([]byte(nil), b[off:off+length]...)
		}
	}
	if finderLen == 0 {
		return f, nil
	}
	copy(f.FinderInfo[:], b[finderOff:finderOff+min(finderLen, 32)])
	// The attribute header follows the Finder info, aligned to 4 bytes
	// or not, depending on the writer.
	hdr := -1
	for _, cand := range []int{finderOff + 32 + 2, finderOff + 32} {
		if cand+36 <= len(b) && string(b[cand:cand+4]) == attrMagic {
			hdr = cand
			break
		}
	}
	if hdr < 0 {
		return f, nil
	}
	h := b[hdr:]
	totalSize := int(binary.BigEndian.Uint32(h[8:]))
	numAttrs := int(binary.BigEndian.Uint16(h[34:]))
	if totalSize < 0 || totalSize > len(b) {
		return nil, fmt.Errorf("appledouble: attribute section (%d bytes) outside the file", totalSize)
	}
	off := hdr + 36
	for i := 0; i < numAttrs; i++ {
		if off+11 > len(b) {
			return nil, fmt.Errorf("appledouble: truncated attribute entry %d", i)
		}
		e := b[off:]
		valOff := int(binary.BigEndian.Uint32(e))
		valLen := int(binary.BigEndian.Uint32(e[4:]))
		nameLen := int(e[10])
		if nameLen == 0 || off+11+nameLen > len(b) {
			return nil, fmt.Errorf("appledouble: bad name length in attribute entry %d", i)
		}
		name := string(bytes.TrimRight(e[11:11+nameLen], "\x00"))
		if valOff < 0 || valLen < 0 || valOff > len(b) || valLen > len(b)-valOff {
			return nil, fmt.Errorf("appledouble: attribute %s value outside the file", name)
		}
		if err := spend(valLen); err != nil {
			return nil, err
		}
		f.Attrs = append(f.Attrs, Attr{Name: name, Value: append([]byte(nil), b[valOff:valOff+valLen]...)})
		// Advance by the length the record declared, not by the trimmed
		// name. The two agree for anything this package or the kernel
		// writes, since both store the name with a single NUL, but the
		// format allows a longer padded name and the kernel steps over
		// whatever nameLen says. Measuring from the trimmed name instead
		// lands the cursor inside the next record and misreads it.
		off += (11 + nameLen + 3) &^ 3
	}
	return f, nil
}

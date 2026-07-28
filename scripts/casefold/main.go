// Command casefold derives the HFS+ case-folding table by observing macOS.
// It is driven by scripts/derive-casefold.sh, which explains why.
//
//	casefold probe  <dir>    create one file per BMP code point
//	casefold derive <image>  read the resulting catalog order and emit the table
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"unicode"
	"unicode/utf16"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"golang.org/x/text/unicode/norm"
)

// ignorable are code units HFS+ skips entirely when comparing. U+200C is the
// one this probe can see: a name containing it sorts as though it were absent.
var ignorable = []uint16{0x200C}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: casefold probe <dir> | casefold derive <image>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "probe":
		probe(os.Args[2])
	case "derive":
		derive(os.Args[2])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

// probeName is the file created for a code point. The suffix keeps every name
// at least two code units long, so a code point that folds away is still a
// valid name and its position reveals that it folded away.
func probeName(r rune) string { return string(r) + ".p" }

func probe(dir string) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}
	created, collided, skipped := 0, 0, 0
	for c := 1; c < 0x10000; c++ {
		r := rune(c)
		switch {
		case r >= 0xD800 && r <= 0xDFFF: // surrogates are not characters
			skipped++
			continue
		case r == '/' || r == ':': // path separator, and HFS+'s own separator
			skipped++
			continue
		}
		s := string(r)
		// HFS+ stores names decomposed, so a character that decomposes never
		// appears on disk as itself. Its fold value cannot be observed this
		// way, and is not needed.
		if norm.NFD.String(s) != s || len(utf16.Encode([]rune(s))) != 1 {
			skipped++
			continue
		}
		path := filepath.Join(dir, probeName(r))
		if _, err := os.Lstat(path); err == nil {
			collided++ // an earlier code point folds to the same value
			continue
		}
		f, err := os.Create(path)
		if err != nil {
			skipped++
			continue
		}
		f.Close()
		created++
	}
	fmt.Fprintf(os.Stderr, "    created=%d collided=%d skipped=%d\n", created, collided, skipped)
}

func derive(image string) {
	order := catalogOrder(image)

	fold := deriveFold(order)
	if !reproduces(fold, order) {
		fmt.Fprintln(os.Stderr, "error: the derived table does not reproduce the observed order")
		os.Exit(1)
	}
	emit(fold)
}

// catalogOrder returns the probe code points in catalog-key order.
func catalogOrder(image string) []uint16 {
	r, off, closer, err := disk.OpenWithOffset(image)
	if err != nil {
		panic(err)
	}
	defer closer.Close()
	var dev io.ReaderAt = r
	if off != 0 {
		dev = io.NewSectionReader(r, off, 1<<62)
	}
	v, err := hfsplus.New(dev)
	if err != nil {
		panic(err)
	}
	hdr := v.Header()
	blockSize := int64(hdr.BlockSize)

	var buf []byte
	for _, e := range hdr.CatalogFile.Extents {
		if e.BlockCount == 0 {
			break
		}
		b := make([]byte, int64(e.BlockCount)*blockSize)
		if _, err := dev.ReadAt(b, int64(e.StartBlock)*blockSize); err != nil {
			panic(err)
		}
		buf = append(buf, b...)
	}

	var bh hfsplus.BTHeaderRec
	if err := binary.Read(bytes.NewReader(buf[14:]), binary.BigEndian, &bh); err != nil {
		panic(err)
	}
	nodeSize := int(bh.NodeSize)

	type record struct {
		parent uint32
		units  []uint16
	}
	var records []record
	counts := map[uint32]int{}

	for n := bh.FirstLeafNode; n != 0; {
		node := buf[int(n)*nodeSize : (int(n)+1)*nodeSize]
		numRecs := int(binary.BigEndian.Uint16(node[10:]))
		for i := range numRecs {
			start := int(binary.BigEndian.Uint16(node[nodeSize-2*(i+1):]))
			end := int(binary.BigEndian.Uint16(node[nodeSize-2*(i+2):]))
			if end <= start || end > nodeSize || start+8 > nodeSize {
				continue
			}
			nameLen := int(binary.BigEndian.Uint16(node[start+6:]))
			// Two code units is the shortest probe name (".p" alone, when the
			// code point folded away); anything shorter is a thread record.
			if nameLen < 2 || start+8+2*nameLen > end {
				continue
			}
			units := make([]uint16, nameLen)
			for j := range units {
				units[j] = binary.BigEndian.Uint16(node[start+8+2*j:])
			}
			parent := binary.BigEndian.Uint32(node[start+2:])
			counts[parent]++
			records = append(records, record{parent, units})
		}
		n = binary.BigEndian.Uint32(node[0:])
	}

	// The probe directory is whichever holds the most entries.
	var probeDir uint32
	best := 0
	for p, c := range counts {
		if c > best {
			best, probeDir = c, p
		}
	}

	var order []uint16
	seen := map[uint16]bool{}
	for _, rec := range records {
		if rec.parent != probeDir || len(rec.units) != 3 {
			// A name of three units is "<c>.p" with c intact. Two units means
			// the code point folded away, and anything else is not a probe.
			continue
		}
		u := rec.units[0]
		// NUL never appears in a name the probe created; a record carrying it
		// belongs to volume housekeeping, not to the probe.
		if u == 0 || seen[u] {
			continue
		}
		seen[u] = true
		order = append(order, u)
	}
	fmt.Fprintf(os.Stderr, "    probe directory %d: %d ordered names\n", probeDir, len(order))
	return order
}

// deriveFold assigns each observed code unit the value it must compare as.
//
// Fold values increase along the observed order. A code unit larger than every
// value so far folds to itself and anchors the scale; one that does not must
// fold to a value inside the window its position allows, and Unicode's
// lowercase is taken when it falls inside that window.
func deriveFold(order []uint16) map[uint16]uint16 {
	fold := map[uint16]uint16{}
	var prev uint16

	// An ignorable code unit takes no part in the comparison, so it carries no
	// fold value and its position says nothing about the scale. Leaving it in
	// would break the monotonicity every later value is derived from.
	ign := map[uint16]bool{}
	for _, u := range ignorable {
		ign[u] = true
	}
	seq := make([]uint16, 0, len(order))
	for _, u := range order {
		if !ign[u] {
			seq = append(seq, u)
		}
	}

	for i, u := range seq {
		if u > prev {
			fold[u] = u
			prev = u
			continue
		}
		var next uint16 = 0xFFFF
		for j := i + 1; j < len(seq); j++ {
			if seq[j] > prev {
				next = seq[j]
				break
			}
		}
		lo := prev + 1
		value := lo
		if lower := lowerUnit(u); lower >= lo && lower < next {
			value = lower
		}
		fold[u] = value
		prev = value
	}
	return fold
}

// lowerUnit is Unicode's lowercase for a BMP code unit, used only as a
// candidate that the observed window then accepts or rejects. Where current
// Unicode disagrees with the fold HFS+ froze, the window rejects it and the
// observation wins.
func lowerUnit(u uint16) uint16 {
	lowered := unicode.ToLower(rune(u))
	if enc := utf16.Encode([]rune{lowered}); len(enc) == 1 {
		return enc[0]
	}
	return u
}

// reproduces checks the derived table against the observation it came from.
func reproduces(fold map[uint16]uint16, order []uint16) bool {
	ign := map[uint16]bool{}
	for _, u := range ignorable {
		ign[u] = true
	}
	key := func(u uint16) []uint16 {
		units := []uint16{u, 0x2E, 0x70}
		out := make([]uint16, 0, 3)
		for _, x := range units {
			if ign[x] {
				continue
			}
			if f, ok := fold[x]; ok {
				out = append(out, f)
			} else {
				out = append(out, x)
			}
		}
		return out
	}

	seq := make([]uint16, 0, len(order))
	for _, u := range order {
		if !ign[u] {
			seq = append(seq, u)
		}
	}
	sorted := append([]uint16(nil), seq...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := key(sorted[i]), key(sorted[j])
		for k := 0; k < len(a) && k < len(b); k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		if len(a) != len(b) {
			return len(a) < len(b)
		}
		return sorted[i] < sorted[j]
	})
	for i := range sorted {
		if sorted[i] != seq[i] {
			fmt.Fprintf(os.Stderr, "    first divergence at %d: derived %04X, observed %04X\n",
				i, sorted[i], seq[i])
			return false
		}
	}
	return true
}

func emit(fold map[uint16]uint16) {
	var moved []uint16
	for u, f := range fold {
		if f != u {
			moved = append(moved, u)
		}
	}
	sort.Slice(moved, func(i, j int) bool { return moved[i] < moved[j] })

	fmt.Println(`// Code generated by scripts/derive-casefold.sh. DO NOT EDIT.

package hfsplus

// caseFold maps a UTF-16 code unit to the value HFS+ compares it as on a
// case-insensitive volume. Only code units that do not fold to themselves
// appear; everything else compares as itself.
//
// Derived by observing macOS rather than transcribed, and deliberately not
// Go's unicode.ToLower: HFS+ froze its fold around Unicode 3.2, so current
// data disagrees. Most visibly, modern Unicode maps the Georgian block
// U+10A0..U+10C5 to Nuskhuri at U+2D00+ while HFS+ maps it to Mkhedruli at
// U+10D0+, and U+1E9E folds to itself here rather than to U+00DF. A table
// built from current Unicode would mis-order every Georgian name.
var caseFold = map[uint16]uint16{`)
	for _, u := range moved {
		fmt.Printf("\t0x%04X: 0x%04X,\n", u, fold[u])
	}
	fmt.Println(`}

// caseFoldIgnored are code units HFS+ skips entirely when comparing names, so
// that "a‌b" and "ab" are the same name.
var caseFoldIgnored = map[uint16]bool{`)
	for _, u := range ignorable {
		fmt.Printf("\t0x%04X: true,\n", u)
	}
	fmt.Println(`}

// foldUnit returns the value a code unit compares as, and whether it takes
// part in the comparison at all.
func foldUnit(u uint16) (uint16, bool) {
	if caseFoldIgnored[u] {
		return 0, false
	}
	if f, ok := caseFold[u]; ok {
		return f, true
	}
	return u, true
}`)
}

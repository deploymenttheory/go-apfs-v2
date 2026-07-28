// Command normalize derives the HFS+ name-normalization exclusion list by
// observing macOS. It is driven by scripts/derive-normalization.sh.
//
//	normalize probe  <dir>    create one file per decomposing BMP code point
//	normalize derive <image>  read the stored names back and emit the table
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"golang.org/x/text/unicode/norm"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: normalize probe <dir> | normalize derive <image>")
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

func decomposes(r rune) bool {
	s := string(r)
	return norm.NFD.String(s) != s
}

// probe writes one file per decomposing code point. The name carries the code
// point in hex after a dash, so the original survives even a decomposition that
// replaces one rune with a single different one and would otherwise be
// indistinguishable from no change at all.
func probe(dir string) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}
	created := 0
	for c := 1; c < 0x10000; c++ {
		r := rune(c)
		if r >= 0xD800 && r <= 0xDFFF || r == '/' || r == ':' {
			continue
		}
		if !decomposes(r) || len(utf16.Encode([]rune{r})) != 1 {
			continue
		}
		f, err := os.Create(filepath.Join(dir, fmt.Sprintf("%s-%04X", string(r), c)))
		if err != nil {
			continue
		}
		f.Close()
		created++
	}
	fmt.Fprintf(os.Stderr, "    created %d probe files\n", created)
}

func derive(image string) {
	names := storedNames(image)

	var intact []rune
	var matchedNFD, other int
	for orig, stored := range names {
		want := []rune(norm.NFD.String(string(orig)))
		switch {
		case len(stored) == 1 && stored[0] == orig:
			intact = append(intact, orig)
		case equalRunes(stored, want):
			matchedNFD++
		default:
			other++
			fmt.Fprintf(os.Stderr, "    U+%04X stored as %v, NFD gives %v\n", orig, stored, want)
		}
	}

	// Anything that is neither left alone nor plain NFD would mean the rule is
	// more than "NFD with exclusions", and the table below could not express
	// it. Refuse rather than emit something that quietly loses those cases.
	if other > 0 {
		fmt.Fprintf(os.Stderr, "error: %d code points are neither intact nor NFD\n", other)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "    %d intact, %d match NFD, %d other\n", len(intact), matchedNFD, other)

	sort.Slice(intact, func(i, j int) bool { return intact[i] < intact[j] })
	emit(intact, len(intact)+matchedNFD)
}

func equalRunes(a, b []rune) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// storedNames maps each probed code point to the runes the volume stored for it.
func storedNames(image string) map[rune][]rune {
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
	header := v.Header()
	blockSize := int64(header.BlockSize)

	var buf []byte
	for _, e := range header.CatalogFile.Extents {
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

	out := map[rune][]rune{}
	for n := bh.FirstLeafNode; n != 0; {
		node := buf[int(n)*nodeSize : (int(n)+1)*nodeSize]
		for i := range int(binary.BigEndian.Uint16(node[10:])) {
			start := int(binary.BigEndian.Uint16(node[nodeSize-2*(i+1):]))
			end := int(binary.BigEndian.Uint16(node[nodeSize-2*(i+2):]))
			if end <= start || end > nodeSize || start+8 > nodeSize {
				continue
			}
			nameLen := int(binary.BigEndian.Uint16(node[start+6:]))
			if nameLen < 2 || start+8+2*nameLen > end {
				continue
			}
			units := make([]uint16, nameLen)
			for j := range units {
				units[j] = binary.BigEndian.Uint16(node[start+8+2*j:])
			}
			name := string(utf16.Decode(units))

			dash := strings.LastIndex(name, "-")
			if dash < 0 || len(name)-dash != 5 {
				continue
			}
			code, err := strconv.ParseUint(name[dash+1:], 16, 32)
			if err != nil {
				continue
			}
			out[rune(code)] = []rune(name[:dash])
		}
		n = binary.BigEndian.Uint32(node[0:])
	}
	return out
}

func emit(intact []rune, total int) {
	type span struct{ lo, hi rune }
	var spans []span
	if len(intact) > 0 {
		cur := span{intact[0], intact[0]}
		for _, r := range intact[1:] {
			if r == cur.hi+1 {
				cur.hi = r
				continue
			}
			spans = append(spans, cur)
			cur = span{r, r}
		}
		spans = append(spans, cur)
	}

	fmt.Printf(`// Code generated by scripts/derive-normalization.sh. DO NOT EDIT.

package hfsplus

// noDecompose are the code points HFS+ leaves alone even though Unicode gives
// them a canonical decomposition. Everything else is decomposed per NFD.
//
// Derived by observing macOS rather than transcribed: %d of the %d decomposing
// BMP code points are stored intact, the rest match NFD exactly, and none
// differ in any other way. Two groups appear here. The documented ones are the
// CJK compatibility ideographs at U+F900+ and part of U+2000..U+2FFF, which
// HFS+ excludes deliberately so a round trip cannot lose them. The rest --
// Balinese at U+1B06+, and U+2ADC -- gained their decompositions after Apple
// froze this behaviour, the same reason U+1E9E folds to itself in
// casefold_table.go.
var noDecompose = [][2]rune{
`, len(intact), total)
	for _, s := range spans {
		fmt.Printf("\t{0x%04X, 0x%04X},\n", s.lo, s.hi)
	}
	fmt.Println("}")
}

package hostdata

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
	"unicode/utf16"
)

// filterReplacementStreams retains EAs and named data, including sparse named
// data, while discarding original main data, links and object identity. Sparse
// blocks belong to the preceding DATA or ALTERNATE_DATA stream (MS-BKUP 2.10).
// Never send a main-data sparse block to BackupWrite: the caller owns new bytes.
func filterReplacementStreams(input io.Reader, output io.Writer) error {
	reader := bufio.NewReaderSize(input, 64<<10)
	writer := bufio.NewWriterSize(output, 64<<10)
	budget := uint64(8 << 20)
	var sparse, named bool
	for count := 0; count < 65536; count++ {
		var header [20]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			if err == io.EOF {
				return writer.Flush()
			}
			return err
		}
		id := binary.LittleEndian.Uint32(header[:4])
		attributes := binary.LittleEndian.Uint32(header[4:8])
		size := binary.LittleEndian.Uint64(header[8:16])
		nameSize := binary.LittleEndian.Uint32(header[16:])
		if size > math.MaxInt64 || nameSize > 64<<10 || nameSize%2 != 0 || (id != 4 && nameSize != 0) {
			return fmt.Errorf("invalid backup stream size/name")
		}
		name := make([]byte, int(nameSize))
		if _, err := io.ReadFull(reader, name); err != nil {
			return err
		}
		keep := false
		var offset [8]byte
		switch id {
		case 1, 5, 7: // main data, hard-link records, object identity
			sparse, named = id == 1 && attributes&8 != 0, false
		case 2, 4: // extended attributes, alternate data
			sparse, named = id == 4 && attributes&8 != 0, id == 4
			if id == 4 {
				units := make([]uint16, len(name)/2)
				for i := range units {
					units[i] = binary.LittleEndian.Uint16(name[2*i:])
				}
				text := string(utf16.Decode(units))
				if !strings.HasPrefix(text, ":") || !strings.HasSuffix(text, ":$DATA") || strings.Count(text, ":") != 2 || strings.ContainsAny(text, "\\/\x00") {
					return fmt.Errorf("%w: alternate stream name", ErrUnsupportedReplacement)
				}
			}
			keep = true
		case 9: // sparse extent in the preceding file stream
			if !sparse || size < 8 {
				return fmt.Errorf("invalid sparse backup stream")
			}
			if _, err := io.ReadFull(reader, offset[:]); err != nil {
				return err
			}
			start := binary.LittleEndian.Uint64(offset[:])
			if start > math.MaxInt64 || size-8 > math.MaxInt64-start {
				return fmt.Errorf("invalid sparse backup extent")
			}
			if named && start+size-8 > 8<<20 {
				return fmt.Errorf("%w: sparse alternate stream exceeds limit", ErrUnsupportedReplacement)
			}
			keep = named
		default:
			return fmt.Errorf("%w: backup stream type %d", ErrUnsupportedReplacement, id)
		}
		if keep {
			if uint64(nameSize) > budget || size > budget-uint64(nameSize) {
				return fmt.Errorf("%w: extended attributes/streams exceed limit", ErrUnsupportedReplacement)
			}
			budget -= uint64(nameSize) + size
			if _, err := writer.Write(header[:]); err != nil {
				return err
			}
			if _, err := writer.Write(name); err != nil {
				return err
			}
			if id == 9 {
				if _, err := writer.Write(offset[:]); err != nil {
					return err
				}
			}
		}
		if id == 9 {
			size -= 8
		}
		var sink io.Writer = io.Discard
		if keep {
			sink = writer
		}
		if _, err := io.CopyN(sink, reader, int64(size)); err != nil {
			return err
		}
	}
	return fmt.Errorf("%w: backup stream count", ErrUnsupportedReplacement)
}

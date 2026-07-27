// UDIF/DMG writer (encoder): the inverse of dmg_reader.go. Produces a valid
// UDIF DMG from a set of source blocks, and can losslessly repack an existing
// DMG by reconstructing its raw image layout and re-encoding it.
//
// On-disk layout produced (all multi-byte fields BIG-ENDIAN):
//
//	[data fork: concatenated compressed chunks]
//	[XML plist: resource-fork -> blkx array of mish blocks]
//	[512-byte "koly" trailer]
//
// Every mish block uses DataOffset=0, so each chunk's CompressedOffset is an
// absolute position within the data fork (which itself starts at file offset
// 0, DataForkOffset=0). This matches how Apple's hdiutil lays out its images
// and how dmg_reader.go inverts the offsets.
package disk

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"
)

// Compression selects the chunk compressor used by the encoder.
type Compression int

const (
	// CompressionZlib compresses each non-zero chunk with zlib, falling back
	// to raw storage when compression does not shrink the chunk. This is the
	// default and is understood by both this package's reader and hdiutil.
	CompressionZlib Compression = iota
	// CompressionNone stores every non-zero chunk raw (uncompressed).
	CompressionNone
)

// EncodeOptions controls how EncodeUDIF/RepackDMG produce a DMG.
type EncodeOptions struct {
	// Compression is the chunk compressor (default CompressionZlib).
	Compression Compression
	// ChunkSectors is the number of 512-byte sectors per chunk
	// (default encodeDefaultChunkSectors). Larger chunks compress slightly
	// better; smaller chunks give finer random-access granularity.
	ChunkSectors uint64
	// NoChecksums disables CRC32 checksum emission (all checksum fields are
	// written as UDIF "none", type 0). By default CRC32 (type 2) checksums
	// are emitted for each block, the data fork, and the master checksum.
	NoChecksums bool
	// ZlibLevel is the zlib compression level (zlib.DefaultCompression when 0
	// is passed via the option struct is treated as default). Accepts the
	// standard compress/zlib levels.
	ZlibLevel int
}

const (
	encodeDefaultChunkSectors = 2048 // 1 MiB chunks
	udifChecksumTypeNone      = 0
	udifChecksumTypeCRC32     = 2
)

// SourceBlock is one blkx block to encode. Its raw bytes cover the half-open
// sector range [StartSector, StartSector+SectorCount).
type SourceBlock struct {
	Name        string
	CFName      string
	ID          string
	Attributes  string
	StartSector uint64
	// SectorCount is the number of 512-byte sectors the block covers. When
	// Data is non-nil it must equal len(Data)/512; otherwise it is authoritative.
	SectorCount uint64
	// Data is the exact uncompressed bytes for the block, length a multiple of
	// 512. A nil Data and a nil Reader mean an all-zero block of SectorCount
	// sectors.
	Data []byte
	// Reader supplies the block's uncompressed bytes lazily, covering
	// [0, SectorCount*512) in block-relative coordinates. It is the alternative
	// to Data for a block too large to hold in memory; setting both is an error.
	//
	// The encoder reads it in ascending, chunk-sized windows and never retains
	// more than one chunk, so a block of any size costs a fixed amount of memory.
	Reader io.ReaderAt
}

// udifPlist mirrors the plist shape produced/consumed by hdiutil and this
// package's reader. It is used for both marshalling (writer) and unmarshalling
// (reconstruction) and carries every key hdiutil emits per blkx entry.
type udifPlist struct {
	ResourceFork udifResourceFork `plist:"resource-fork"`
}

type udifResourceFork struct {
	Blkx []udifBlkx `plist:"blkx"`
}

type udifBlkx struct {
	Attributes string `plist:"Attributes"`
	CFName     string `plist:"CFName"`
	Data       []byte `plist:"Data"`
	ID         string `plist:"ID"`
	Name       string `plist:"Name"`
}

func resolveEncodeOptions(o *EncodeOptions) EncodeOptions {
	out := EncodeOptions{
		Compression:  CompressionZlib,
		ChunkSectors: encodeDefaultChunkSectors,
		ZlibLevel:    zlib.DefaultCompression,
	}
	if o != nil {
		out.Compression = o.Compression
		out.NoChecksums = o.NoChecksums
		if o.ChunkSectors != 0 {
			out.ChunkSectors = o.ChunkSectors
		}
		if o.ZlibLevel != 0 {
			out.ZlibLevel = o.ZlibLevel
		}
	}
	return out
}

// udifChecksum builds a 136-byte UDIFChecksum: uint32 Type, uint32 Size(bits),
// then 128 bytes of data. For CRC32 the 32-bit value is stored big-endian in
// the first 4 data bytes. A none checksum is all zeros.
func udifChecksum(crc uint32, none bool) [136]byte {
	var out [136]byte
	if none {
		return out
	}
	binary.BigEndian.PutUint32(out[0:4], udifChecksumTypeCRC32)
	binary.BigEndian.PutUint32(out[4:8], 32) // size in bits
	binary.BigEndian.PutUint32(out[8:12], crc)
	return out
}

// dataForkWriter counts bytes and CRC32s the data fork as it is streamed out.
type dataForkWriter struct {
	w   io.Writer
	crc hash.Hash32
	n   uint64
}

func (d *dataForkWriter) Write(p []byte) (int, error) {
	n, err := d.w.Write(p)
	if n > 0 {
		d.crc.Write(p[:n])
		d.n += uint64(n)
	}
	return n, err
}

// isAllZero reports whether b is entirely zero bytes.
func isAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// encodeChunkRecord serialises one chunk record in the exact field order the
// reader expects: Type, Comment, SectorNumber, SectorCount, CompressedOffset,
// CompressedLength (all big-endian).
func encodeChunkRecord(buf *bytes.Buffer, typ uint32, sectorNumber, sectorCount, compressedOffset, compressedLength uint64) {
	var rec [40]byte
	binary.BigEndian.PutUint32(rec[0:4], typ)
	binary.BigEndian.PutUint32(rec[4:8], 0) // Comment
	binary.BigEndian.PutUint64(rec[8:16], sectorNumber)
	binary.BigEndian.PutUint64(rec[16:24], sectorCount)
	binary.BigEndian.PutUint64(rec[24:32], compressedOffset)
	binary.BigEndian.PutUint64(rec[32:40], compressedLength)
	buf.Write(rec[:])
}

// EncodeUDIF writes a complete UDIF DMG for the given source blocks to dst.
// Blocks are emitted in slice order; each block's chunks are written to the
// data fork with absolute CompressedOffsets. dst is written strictly in order
// (data fork, plist, koly trailer) so it need not be seekable.
func EncodeUDIF(dst io.Writer, blocks []SourceBlock, opts *EncodeOptions) error {
	o := resolveEncodeOptions(opts)
	if len(blocks) == 0 {
		return fmt.Errorf("EncodeUDIF: no source blocks")
	}

	dfw := &dataForkWriter{w: dst, crc: crc32.NewIEEE()}

	var (
		blkxEntries  []udifBlkx
		blockCRCs    []uint32
		totalSectors uint64
	)

	// One chunk-sized window, shared by every block that reads lazily. This is
	// the whole of the encoder's per-image memory cost: a block is never held.
	var window []byte
	for i := range blocks {
		if blocks[i].Reader != nil {
			window = make([]byte, o.ChunkSectors*sectorSize)
			break
		}
	}

	for bi := range blocks {
		blk := &blocks[bi]
		if blk.Data != nil && blk.Reader != nil {
			return fmt.Errorf("EncodeUDIF: block %q sets both Data and Reader", blk.Name)
		}
		secCount := blk.SectorCount
		if blk.Data != nil {
			if len(blk.Data)%sectorSize != 0 {
				return fmt.Errorf("EncodeUDIF: block %q data length %d not a multiple of %d", blk.Name, len(blk.Data), sectorSize)
			}
			secCount = uint64(len(blk.Data)) / sectorSize
		}

		mish, blockCRC, err := encodeBlock(dfw, bi, blk, secCount, &o, window)
		if err != nil {
			return fmt.Errorf("EncodeUDIF: block %q: %w", blk.Name, err)
		}

		blkxEntries = append(blkxEntries, udifBlkx{
			Attributes: firstNonEmpty(blk.Attributes, "0x0050"),
			CFName:     firstNonEmpty(blk.CFName, blk.Name),
			Data:       mish,
			ID:         firstNonEmpty(blk.ID, fmt.Sprintf("%d", bi)),
			Name:       blk.Name,
		})
		blockCRCs = append(blockCRCs, blockCRC)

		if end := blk.StartSector + secCount; end > totalSectors {
			totalSectors = end
		}
	}

	dataForkLen := dfw.n
	dataForkCRC := dfw.crc.Sum32()

	// Marshal the plist. Kept separate from the reader's structs so both read
	// and write paths can share udifPlist.
	plistBytes, err := marshalPlist(blkxEntries)
	if err != nil {
		return fmt.Errorf("EncodeUDIF: marshal plist: %w", err)
	}
	if _, err := dst.Write(plistBytes); err != nil {
		return fmt.Errorf("EncodeUDIF: write plist: %w", err)
	}

	// Master checksum: CRC32 over the concatenation of each block's CRC32
	// value (big-endian). Matches the libdmg-hfsplus / hdiutil convention.
	masterHash := crc32.NewIEEE()
	var tmp [4]byte
	for _, c := range blockCRCs {
		binary.BigEndian.PutUint32(tmp[:], c)
		masterHash.Write(tmp[:])
	}
	masterCRC := masterHash.Sum32()

	footer := DMGFooter{
		Version:        udifVersion,
		HeaderSize:     dmgFooterSize,
		Flags:          1,
		DataForkOffset: 0,
		DataForkLength: dataForkLen,
		SegmentNumber:  1,
		SegmentCount:   1,
		DataChecksum:   udifChecksum(dataForkCRC, o.NoChecksums),
		PlistOffset:    dataForkLen, // DataForkOffset=0, plist follows the data fork
		PlistLength:    uint64(len(plistBytes)),
		MasterChecksum: udifChecksum(masterCRC, o.NoChecksums),
		ImageVariant:   1,
		SectorCount:    totalSectors,
	}
	copy(footer.Signature[:], dmgSignature)

	if err := binary.Write(dst, binary.BigEndian, &footer); err != nil {
		return fmt.Errorf("EncodeUDIF: write koly footer: %w", err)
	}

	return nil
}

// encodeBlock chunks a single source block, streams its compressed chunk data
// to dfw, and returns the serialised mish block bytes plus the CRC32 of the
// block's uncompressed data.
// window, when non-nil, is a scratch buffer of ChunkSectors*512 bytes shared
// across blocks, used only when the block reads lazily.
func encodeBlock(dfw *dataForkWriter, index int, blk *SourceBlock, secCount uint64, o *EncodeOptions, window []byte) ([]byte, uint32, error) {
	var chunks bytes.Buffer
	chunkCount := uint32(0)
	blockCRC := crc32.NewIEEE()

	var sector uint64
	for sector < secCount {
		n := o.ChunkSectors
		if remaining := secCount - sector; n > remaining {
			n = remaining
		}

		var raw []byte
		switch {
		case blk.Data != nil:
			start := sector * sectorSize
			raw = blk.Data[start : start+n*sectorSize]
		case blk.Reader != nil:
			raw = window[:n*sectorSize]
			if _, err := readFullAt(blk.Reader, raw, int64(sector*sectorSize)); err != nil {
				return nil, 0, fmt.Errorf("read sector %d: %w", sector, err)
			}
		}
		// A nil raw slice (neither Data nor Reader) is treated as all-zero.

		if raw == nil || isAllZero(raw) {
			// Feed zeros into the block CRC to keep it over the full
			// uncompressed image, then emit a zero-fill chunk (no data).
			writeZeros(blockCRC, int(n*sectorSize))
			encodeChunkRecord(&chunks, chunkTypeZeroFill, sector, n, dfw.n, 0)
			chunkCount++
			sector += n
			continue
		}

		blockCRC.Write(raw)

		payload := raw
		typ := uint32(chunkTypeUncompressed)
		if o.Compression == CompressionZlib {
			compressed, err := zlibCompress(raw, o.ZlibLevel)
			if err != nil {
				return nil, 0, err
			}
			if len(compressed) < len(raw) {
				payload = compressed
				typ = chunkTypeCompressZLIB
			}
		}

		coff := dfw.n
		if _, err := dfw.Write(payload); err != nil {
			return nil, 0, err
		}
		encodeChunkRecord(&chunks, typ, sector, n, coff, uint64(len(payload)))
		chunkCount++
		sector += n
	}

	// Terminator chunk: type 0xffffffff, SectorNumber = end sector, no data.
	encodeChunkRecord(&chunks, chunkTypeLastBlock, secCount, 0, dfw.n, 0)
	chunkCount++

	header := dmgBlockData{
		Version:          1,
		StartSector:      blk.StartSector,
		SectorCount:      secCount,
		DataOffset:       0,
		BuffersNeeded:    uint32(o.ChunkSectors) + 8,
		BlockDescriptors: uint32(index),
		Checksum:         udifChecksum(blockCRC.Sum32(), o.NoChecksums),
		ChunkCount:       chunkCount,
	}
	copy(header.Signature[:], mishSignature)

	var out bytes.Buffer
	if err := binary.Write(&out, binary.BigEndian, &header); err != nil {
		return nil, 0, err
	}
	out.Write(chunks.Bytes())

	return out.Bytes(), blockCRC.Sum32(), nil
}

// readFullAt fills p from r at off. It exists because an io.ReaderAt is
// permitted both to return fewer bytes than asked for and to report io.EOF
// alongside a full read, so a single ReadAt call cannot be trusted to have
// filled the buffer.
func readFullAt(r io.ReaderAt, p []byte, off int64) (int, error) {
	n := 0
	for n < len(p) {
		read, err := r.ReadAt(p[n:], off+int64(n))
		n += read
		if err != nil {
			if err == io.EOF && n == len(p) {
				return n, nil
			}
			return n, err
		}
		if read == 0 {
			return n, io.ErrUnexpectedEOF
		}
	}
	return n, nil
}

var zeroScratch = make([]byte, 64<<10)

// writeZeros feeds n zero bytes into h without allocating.
func writeZeros(h io.Writer, n int) {
	for n > 0 {
		c := n
		if c > len(zeroScratch) {
			c = len(zeroScratch)
		}
		h.Write(zeroScratch[:c])
		n -= c
	}
}

// zlibCompress returns the zlib-compressed form of data.
func zlibCompress(data []byte, level int) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&buf, level)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(data); err != nil {
		zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// RepackDMG reconstructs the raw image layout of the source DMG at srcPath and
// re-encodes it losslessly to dstPath, preserving every block boundary and
// name so both this package's reader and hdiutil handle the output exactly as
// they handle the input. The chunk data is recompressed per opts.
func RepackDMG(srcPath, dstPath string, opts *EncodeOptions) error {
	blocks, _, closer, err := reconstructBlocks(srcPath)
	if err != nil {
		return fmt.Errorf("RepackDMG: reconstruct %s: %w", srcPath, err)
	}
	// The blocks read from the open DMG lazily, so it must stay open until the
	// encode finishes.
	defer closer.Close()
	if err := encodeToFile(dstPath, blocks, opts); err != nil {
		return fmt.Errorf("RepackDMG: %w", err)
	}
	return nil
}

// encodeToFile encodes blocks to a new file at dstPath through a buffered
// writer. A failure removes the partial file rather than leaving a truncated
// DMG behind, which would otherwise look like a valid output to anything that
// only checks the path exists.
func encodeToFile(dstPath string, blocks []SourceBlock, opts *EncodeOptions) error {
	out, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", dstPath, err)
	}

	fail := func(err error) error {
		out.Close()
		os.Remove(dstPath)
		return err
	}

	bw := bufio.NewWriterSize(out, 1<<20)
	if err := EncodeUDIF(bw, blocks, opts); err != nil {
		return fail(fmt.Errorf("encode: %w", err))
	}
	if err := bw.Flush(); err != nil {
		return fail(fmt.Errorf("flush: %w", err))
	}
	if err := out.Close(); err != nil {
		os.Remove(dstPath)
		return fmt.Errorf("close: %w", err)
	}
	return nil
}

// wholeDiskBlock describes a raw file system image as the single Apple
// partition block a DMG wraps it in. partitionHint is the Apple partition type
// name embedded in the block name so the reader (and hdiutil) locate the file
// system, e.g. "Apple_HFSX", "Apple_HFS" or "Apple_APFS".
func wholeDiskBlock(partitionHint string, sectors uint64) SourceBlock {
	name := fmt.Sprintf("whole disk (%s : 0)", partitionHint)
	return SourceBlock{
		Name:        name,
		CFName:      name,
		ID:          "0",
		Attributes:  "0x0050",
		StartSector: 0,
		SectorCount: sectors,
	}
}

// WrapRawImageDMG writes a UDIF DMG at dstPath wrapping a raw file system
// image as a single Apple partition block. partitionHint is the Apple
// partition type name embedded in the block name so the reader (and hdiutil)
// locate the file system, e.g. "Apple_HFSX", "Apple_HFS" or "Apple_APFS".
//
// The whole image is held in memory. WrapRawImageDMGFrom takes the same image
// as an io.ReaderAt and does not.
func WrapRawImageDMG(dstPath string, raw []byte, partitionHint string, opts *EncodeOptions) error {
	if len(raw)%sectorSize != 0 {
		return fmt.Errorf("WrapRawImageDMG: raw image length %d is not a multiple of %d", len(raw), sectorSize)
	}
	block := wholeDiskBlock(partitionHint, uint64(len(raw)/sectorSize))
	block.Data = raw

	if err := encodeToFile(dstPath, []SourceBlock{block}, opts); err != nil {
		return fmt.Errorf("WrapRawImageDMG: %w", err)
	}
	return nil
}

// WrapRawImageDMGFrom writes a UDIF DMG at dstPath wrapping the raw file system
// image read from src, which must cover [0, size). It is WrapRawImageDMG
// without holding the image in memory: nothing larger than one chunk is
// retained, so src may be an *os.File of any size.
//
// The output is byte-identical to what WrapRawImageDMG produces for the same
// bytes; only where they come from differs.
func WrapRawImageDMGFrom(dstPath string, src io.ReaderAt, size int64, partitionHint string, opts *EncodeOptions) error {
	if size%sectorSize != 0 {
		return fmt.Errorf("WrapRawImageDMGFrom: raw image length %d is not a multiple of %d", size, sectorSize)
	}
	if src == nil {
		return fmt.Errorf("WrapRawImageDMGFrom: nil source")
	}
	block := wholeDiskBlock(partitionHint, uint64(size/sectorSize))
	block.Reader = src

	if err := encodeToFile(dstPath, []SourceBlock{block}, opts); err != nil {
		return fmt.Errorf("WrapRawImageDMGFrom: %w", err)
	}
	return nil
}

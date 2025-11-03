// DMG reader with decompression support for APFS extraction
// Based on go-apfs/pkg/disk/dmg implementation by blacktop
package disk

import (
	"bytes"
	"compress/bzip2"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/blacktop/ipsw/pkg/lzfse"
	"howett.net/plist"
)

const (
	sectorSize    = 0x200
	dmgFooterSize = 512
	dmgSignature  = "koly"
	mishSignature = "mish"
	udifVersion   = 4
)

// Chunk types
const (
	chunkTypeZeroFill      = 0x00000000
	chunkTypeUncompressed  = 0x00000001
	chunkTypeIgnored       = 0x00000002
	chunkTypeCompressADC   = 0x80000004
	chunkTypeCompressZLIB  = 0x80000005
	chunkTypeCompressBZ2   = 0x80000006
	chunkTypeCompressLZFSE = 0x80000007
	chunkTypeComment       = 0x7ffffffe
	chunkTypeLastBlock     = 0xffffffff
)

// DMGFooter represents the UDIF Resource File footer
type DMGFooter struct {
	Signature             [4]byte
	Version               uint32
	HeaderSize            uint32
	Flags                 uint32
	RunningDataForkOffset uint64
	DataForkOffset        uint64
	DataForkLength        uint64
	RsrcForkOffset        uint64
	RsrcForkLength        uint64
	SegmentNumber         uint32
	SegmentCount          uint32
	SegmentID             [16]byte
	DataChecksum          [136]byte
	PlistOffset           uint64
	PlistLength           uint64
	Reserved1             [64]byte
	CodeSignatureOffset   uint64
	CodeSignatureLength   uint64
	Reserved2             [40]byte
	MasterChecksum        [136]byte
	ImageVariant          uint32
	SectorCount           uint64
	Reserved3             uint32
	Reserved4             uint32
	Reserved5             uint32
}

// DMGBlockData represents a partition in the DMG
type dmgBlockData struct {
	Signature        [4]byte
	Version          uint32
	StartSector      uint64
	SectorCount      uint64
	DataOffset       uint64
	BuffersNeeded    uint32
	BlockDescriptors uint32
	Reserved         [6]uint32
	Checksum         [136]byte
	ChunkCount       uint32
}

// DMGChunk represents a compressed chunk in a DMG partition
type DMGChunk struct {
	Type             uint32
	Comment          uint32
	DiskOffset       uint64 // Logical offset in bytes
	DiskLength       uint64 // Length in bytes
	CompressedOffset uint64 // Offset in DMG file
	CompressedLength uint64 // Compressed size in bytes
}

// DMGPartition represents a partition within a DMG
type DMGPartition struct {
	Name        string
	StartSector uint64
	SectorCount uint64
	DataOffset  uint64
	Chunks      []DMGChunk
}

// DMGReader implements io.ReaderAt for reading from compressed DMG files
type DMGReader struct {
	file             *os.File
	footer           DMGFooter
	partitions       []DMGPartition
	apfsPartitionIdx int
	apfsOffset       uint64
	apfsSize         uint64
	maxChunkSize     int
}

// dmgPlist represents the structure of a DMG plist
type dmgPlist struct {
	ResourceFork *resourceFork `plist:"resource-fork"`
}

// resourceFork represents the resource-fork section
type resourceFork struct {
	Blkx []blkxEntry `plist:"blkx"`
}

// blkxEntry represents a block entry in the plist
type blkxEntry struct {
	Name   string `plist:"Name"`
	CFName string `plist:"CFName"`
	Data   []byte `plist:"Data"`
}

// OpenDMG opens a DMG file and prepares it for reading
func OpenDMG(filename string) (*DMGReader, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to open DMG: %w", err)
	}

	reader := &DMGReader{
		file: file,
	}

	// Read footer
	if err := reader.readFooter(); err != nil {
		file.Close()
		return nil, fmt.Errorf("unable to read DMG footer: %w", err)
	}

	// Parse plist to get partition information
	if err := reader.parsePlist(); err != nil {
		file.Close()
		return nil, fmt.Errorf("unable to parse DMG plist: %w", err)
	}

	// Find APFS partition
	if err := reader.findAPFSPartition(); err != nil {
		file.Close()
		return nil, fmt.Errorf("unable to find APFS partition: %w", err)
	}

	return reader, nil
}

// Close closes the DMG reader
func (r *DMGReader) Close() error {
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}

// readFooter reads the DMG footer from the end of the file
func (r *DMGReader) readFooter() error {
	_, err := r.file.Seek(-dmgFooterSize, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("unable to seek to footer: %w", err)
	}

	if err := binary.Read(r.file, binary.BigEndian, &r.footer); err != nil {
		return fmt.Errorf("unable to read footer: %w", err)
	}

	if string(r.footer.Signature[:]) != dmgSignature {
		return fmt.Errorf("invalid DMG signature: %s", string(r.footer.Signature[:]))
	}

	return nil
}

// parsePlist parses the DMG plist to extract partition and chunk information
func (r *DMGReader) parsePlist() error {
	if r.footer.PlistOffset == 0 || r.footer.PlistLength == 0 {
		return fmt.Errorf("no plist data in DMG")
	}

	// Seek to plist
	_, err := r.file.Seek(int64(r.footer.PlistOffset), io.SeekStart)
	if err != nil {
		return fmt.Errorf("unable to seek to plist: %w", err)
	}

	// Read plist data
	plistData := make([]byte, r.footer.PlistLength)
	if _, err := io.ReadFull(r.file, plistData); err != nil {
		return fmt.Errorf("unable to read plist: %w", err)
	}

	// Parse plist using howett.net/plist library
	var dmgPlistData dmgPlist
	_, err = plist.Unmarshal(plistData, &dmgPlistData)
	if err != nil {
		return fmt.Errorf("unable to unmarshal plist: %w", err)
	}

	// Check if resource-fork exists and has blkx entries
	if dmgPlistData.ResourceFork == nil || len(dmgPlistData.ResourceFork.Blkx) == 0 {
		return fmt.Errorf("no blkx blocks found in plist")
	}

	// Parse each block (partition)
	for _, block := range dmgPlistData.ResourceFork.Blkx {
		partition, err := r.parsePartition(&block)
		if err != nil {
			// Skip invalid partitions
			continue
		}
		r.partitions = append(r.partitions, *partition)
	}

	if len(r.partitions) == 0 {
		return fmt.Errorf("no partitions found in DMG")
	}

	return nil
}

// parsePartition parses a single partition from a blkx entry
func (r *DMGReader) parsePartition(block *blkxEntry) (*DMGPartition, error) {
	partition := &DMGPartition{}

	// Set partition name
	partition.Name = block.Name
	if partition.Name == "" {
		partition.Name = block.CFName
	}

	if len(block.Data) == 0 {
		return nil, fmt.Errorf("no data in partition")
	}

	// Parse binary block data
	buf := bytes.NewReader(block.Data)

	// Read udifBlockData header
	var blockData dmgBlockData
	if err := binary.Read(buf, binary.BigEndian, &blockData); err != nil {
		return nil, fmt.Errorf("unable to read block data: %w", err)
	}

	if string(blockData.Signature[:]) != mishSignature {
		return nil, fmt.Errorf("invalid block signature: %s", string(blockData.Signature[:]))
	}

	partition.StartSector = blockData.StartSector
	partition.SectorCount = blockData.SectorCount
	partition.DataOffset = blockData.DataOffset

	// Read chunks
	for i := uint32(0); i < blockData.ChunkCount; i++ {
		var chunk DMGChunk
		if err := binary.Read(buf, binary.BigEndian, &chunk); err != nil {
			return nil, fmt.Errorf("unable to read chunk %d: %w", i, err)
		}

		// Adjust offsets and lengths
		chunk.DiskOffset = (chunk.DiskOffset + blockData.StartSector) * sectorSize
		chunk.DiskLength = chunk.DiskLength * sectorSize
		chunk.CompressedOffset = chunk.CompressedOffset + blockData.DataOffset + r.footer.DataForkOffset

		partition.Chunks = append(partition.Chunks, chunk)

		// Track max chunk size
		if int(chunk.CompressedLength) > r.maxChunkSize {
			r.maxChunkSize = int(chunk.CompressedLength)
		}
	}

	return partition, nil
}

// findAPFSPartition locates the APFS partition in the DMG
func (r *DMGReader) findAPFSPartition() error {
	// Parse GPT to find APFS partition
	if err := r.parseGPT(); err != nil {
		return err
	}

	if r.apfsPartitionIdx == -1 {
		return fmt.Errorf("no APFS partition found in DMG")
	}

	return nil
}

// parseGPT parses the GPT header and finds the APFS partition
func (r *DMGReader) parseGPT() error {
	// Find GPT header and table partitions
	var headerPart, tablePart *DMGPartition
	for i := range r.partitions {
		if r.partitions[i].Name == "GPT Header (Primary GPT Header : 1)" {
			headerPart = &r.partitions[i]
		}
		if r.partitions[i].Name == "GPT Partition Data (Primary GPT Table : 2)" {
			tablePart = &r.partitions[i]
		}
	}

	if headerPart == nil || tablePart == nil {
		// No GPT, try to find APFS partition by name
		for i, part := range r.partitions {
			if part.Name == "disk image" || part.Name == "(disk image)" ||
				part.Name == "GPT Partition Data" {
				r.apfsPartitionIdx = i
				r.apfsOffset = part.StartSector * sectorSize
				r.apfsSize = part.SectorCount * sectorSize
				return nil
			}
		}
		return fmt.Errorf("no GPT or named APFS partition found")
	}

	// Decompress GPT header
	var headerBuf bytes.Buffer
	for _, chunk := range headerPart.Chunks {
		data, err := r.decompressChunk(&chunk)
		if err != nil {
			return fmt.Errorf("unable to decompress GPT header chunk: %w", err)
		}
		headerBuf.Write(data)
	}

	// Parse GPT header
	var gptHeader GPTHeader
	if err := binary.Read(bytes.NewReader(headerBuf.Bytes()), binary.LittleEndian, &gptHeader); err != nil {
		return fmt.Errorf("unable to read GPT header: %w", err)
	}

	if err := gptHeader.Verify(); err != nil {
		return fmt.Errorf("GPT header verification failed: %w", err)
	}

	// Decompress GPT table
	var tableBuf bytes.Buffer
	for _, chunk := range tablePart.Chunks {
		data, err := r.decompressChunk(&chunk)
		if err != nil {
			return fmt.Errorf("unable to decompress GPT table chunk: %w", err)
		}
		tableBuf.Write(data)
	}

	// Parse GPT partitions
	partitions := make([]GPTPartition, gptHeader.EntriesCount)
	if err := binary.Read(bytes.NewReader(tableBuf.Bytes()), binary.LittleEndian, &partitions); err != nil {
		return fmt.Errorf("unable to read GPT partitions: %w", err)
	}

	// Find APFS partition
	for _, gptPart := range partitions {
		if gptPart.IsEmpty() {
			continue
		}
		guidStr := gptPart.Type.String()
		if guidStr == appleAPFSGUID || guidStr == appleHFSGUID {
			// Find corresponding DMG partition
			for i, dmgPart := range r.partitions {
				if dmgPart.StartSector == gptPart.StartingLBA {
					r.apfsPartitionIdx = i
					r.apfsOffset = gptPart.StartingLBA * sectorSize
					r.apfsSize = (gptPart.EndingLBA - gptPart.StartingLBA + 1) * sectorSize
					return nil
				}
			}
		}
	}

	return fmt.Errorf("APFS partition not found in GPT")
}

// ReadAt implements io.ReaderAt for decompressing DMG data on-the-fly
func (r *DMGReader) ReadAt(buf []byte, off int64) (n int, err error) {
	// Adjust offset to be relative to APFS partition
	off += int64(r.apfsOffset)

	if r.apfsPartitionIdx == -1 || r.apfsPartitionIdx >= len(r.partitions) {
		return 0, fmt.Errorf("invalid APFS partition index")
	}

	partition := &r.partitions[r.apfsPartitionIdx]
	remaining := len(buf)
	offset := 0

	// Binary search to find starting chunk
	chunks := partition.Chunks
	chunkIdx := -1
	left, right := 0, len(chunks)-1
	for left <= right {
		mid := (left + right) / 2
		chunkStart := int64(chunks[mid].DiskOffset)
		chunkEnd := int64(chunks[mid].DiskOffset + chunks[mid].DiskLength)

		if off >= chunkStart && off < chunkEnd {
			chunkIdx = mid
			break
		} else if off < chunkStart {
			right = mid - 1
		} else {
			left = mid + 1
		}
	}

	if chunkIdx == -1 {
		// Start from beginning if not found
		chunkIdx = 0
	}

	// Process chunks
	for remaining > 0 && chunkIdx < len(chunks) {
		chunk := &chunks[chunkIdx]
		chunkStart := int64(chunk.DiskOffset)
		chunkEnd := int64(chunk.DiskOffset + chunk.DiskLength)

		// Skip chunks before our read offset
		if off >= chunkEnd {
			chunkIdx++
			continue
		}

		// We're done if this chunk is after our read range
		if off+int64(len(buf)) <= chunkStart {
			break
		}

		// Decompress this chunk
		chunkData, err := r.decompressChunk(chunk)
		if err != nil {
			return n, fmt.Errorf("unable to decompress chunk: %w", err)
		}

		// Calculate read offsets within this chunk
		readStart := int64(0)
		if off > chunkStart {
			readStart = off - chunkStart
		}

		readEnd := int64(len(chunkData))
		if off+int64(remaining) < chunkEnd {
			readEnd = readStart + int64(remaining)
		}

		// Copy data
		copyLen := copy(buf[offset:], chunkData[readStart:readEnd])
		n += copyLen
		offset += copyLen
		remaining -= copyLen
		off += int64(copyLen)

		chunkIdx++
	}

	if n == 0 && len(buf) > 0 {
		return 0, io.EOF
	}

	return n, nil
}

// decompressChunk decompresses a single DMG chunk
func (r *DMGReader) decompressChunk(chunk *DMGChunk) ([]byte, error) {
	switch chunk.Type {
	case chunkTypeZeroFill, chunkTypeIgnored:
		return make([]byte, chunk.DiskLength), nil

	case chunkTypeUncompressed:
		data := make([]byte, chunk.CompressedLength)
		_, err := r.file.ReadAt(data, int64(chunk.CompressedOffset))
		return data, err

	case chunkTypeCompressZLIB:
		compressed := make([]byte, chunk.CompressedLength)
		_, err := r.file.ReadAt(compressed, int64(chunk.CompressedOffset))
		if err != nil {
			return nil, err
		}

		zlibReader, err := zlib.NewReader(bytes.NewReader(compressed))
		if err != nil {
			return nil, err
		}
		defer zlibReader.Close()

		var buf bytes.Buffer
		if _, err := buf.ReadFrom(zlibReader); err != nil {
			return nil, err
		}

		return buf.Bytes(), nil

	case chunkTypeCompressBZ2:
		compressed := make([]byte, chunk.CompressedLength)
		_, err := r.file.ReadAt(compressed, int64(chunk.CompressedOffset))
		if err != nil {
			return nil, err
		}

		bz2Reader := bzip2.NewReader(bytes.NewReader(compressed))
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(bz2Reader); err != nil {
			return nil, err
		}

		return buf.Bytes(), nil

	case chunkTypeCompressLZFSE:
		compressed := make([]byte, chunk.CompressedLength)
		_, err := r.file.ReadAt(compressed, int64(chunk.CompressedOffset))
		if err != nil {
			return nil, err
		}

		decoder := lzfse.NewDecoder(compressed)
		decompressed, err := decoder.DecodeBuffer()
		if err != nil {
			return nil, fmt.Errorf("LZFSE decompression failed: %w", err)
		}

		return decompressed, nil

	case chunkTypeCompressADC:
		compressed := make([]byte, chunk.CompressedLength)
		_, err := r.file.ReadAt(compressed, int64(chunk.CompressedOffset))
		if err != nil {
			return nil, err
		}

		return DecompressADC(compressed), nil

	case chunkTypeComment, chunkTypeLastBlock:
		return []byte{}, nil

	default:
		return nil, fmt.Errorf("unsupported chunk type: 0x%x", chunk.Type)
	}
}

package disk

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"howett.net/plist"
)

type countedDMGSource struct {
	*bytes.Reader
	bytes  int
	closed bool
	reads  [][2]int64
}

func (s *countedDMGSource) ReadAt(p []byte, off int64) (int, error) {
	n, err := s.Reader.ReadAt(p, off)
	s.bytes += n
	s.reads = append(s.reads, [2]int64{off, off + int64(n)})
	return n, err
}

func (s *countedDMGSource) Close() error { s.closed = true; return nil }

func TestDMGReaderAt(t *testing.T) {
	const chunkSize = 4096
	data := append(bytes.Repeat([]byte("A"), chunkSize), bytes.Repeat([]byte("B"), chunkSize)...)
	data = append(data, make([]byte, chunkSize)...)
	data = append(data, bytes.Repeat([]byte("C"), chunkSize)...)
	for _, codec := range []struct {
		name        string
		compression Compression
	}{{"zlib", CompressionZlib}, {"raw", CompressionNone}, {"lzfse", CompressionLZFSE}, {"lzma", CompressionLZMA}} {
		t.Run(codec.name, func(t *testing.T) {
			var encoded bytes.Buffer
			if err := EncodeUDIF(&encoded, []SourceBlock{{Name: "disk image", SectorCount: uint64(len(data) / 512), Data: data}}, &EncodeOptions{Compression: codec.compression, ChunkSectors: chunkSize / 512}); err != nil {
				t.Fatal(err)
			}
			source := &countedDMGSource{Reader: bytes.NewReader(encoded.Bytes())}
			reader, err := NewDMGReader(source, int64(encoded.Len()), DMGLimits{})
			if err != nil {
				t.Fatal(err)
			}
			for _, part := range reader.Partitions() {
				for _, chunk := range part.Chunks {
					if chunk.CompressedLength == 0 {
						continue
					}
					for _, read := range source.reads {
						if read[0] < int64(chunk.CompressedOffset+chunk.CompressedLength) && read[1] > int64(chunk.CompressedOffset) {
							t.Fatal("opening read payload chunks")
						}
					}
				}
			}
			source.bytes = 0
			got := make([]byte, 16)
			if n, err := reader.ReadAt(got, chunkSize-8); err != nil || n != len(got) || !bytes.Equal(got, data[chunkSize-8:chunkSize+8]) {
				t.Fatalf("cross-chunk read %q (%d): %v", got, n, err)
			}
			before := source.bytes
			if _, err := reader.ReadAt(got, chunkSize-8); err != nil {
				t.Fatal(err)
			}
			if codec.compression == CompressionNone {
				if source.bytes != 32 {
					t.Fatalf("raw reads consumed %d bytes, want 32", source.bytes)
				}
			} else if source.bytes != before {
				t.Fatal("repeated read decompressed cached chunks")
			}
			before = source.bytes
			if _, err := reader.ReadAt(got, 2*chunkSize); err != nil || !bytes.Equal(got, make([]byte, len(got))) {
				t.Fatalf("zero extent: %v", err)
			}
			if source.bytes != before {
				t.Fatal("zero extent read the source")
			}
			got = make([]byte, 6)
			if n, err := reader.ReadAt(got, int64(len(data)-3)); n != 3 || !errors.Is(err, io.EOF) || string(got[:n]) != "CCC" {
				t.Fatalf("partial EOF: %d, %v", n, err)
			}
			if _, err := reader.ReadAt(got, -1); err == nil {
				t.Fatal("accepted negative offset")
			}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			if source.closed {
				t.Fatal("closed caller-owned source")
			}
			// The chunk limit bounds decoding, so it rejects a compressed
			// image and leaves raw extents, which are never buffered, alone.
			_, err = NewDMGReader(bytes.NewReader(encoded.Bytes()), int64(encoded.Len()), DMGLimits{ChunkBytes: 512})
			if codec.compression == CompressionNone && err != nil {
				t.Fatalf("chunk limit rejected raw extents: %v", err)
			} else if codec.compression != CompressionNone && err == nil {
				t.Fatal("ignored chunk limit")
			}
			if _, err := NewDMGReader(bytes.NewReader(encoded.Bytes()), int64(encoded.Len()), DMGLimits{MetadataBytes: 1}); err == nil {
				t.Fatal("ignored metadata limit")
			}
			if _, err := NewDMGReader(bytes.NewReader(encoded.Bytes()), int64(encoded.Len()), DMGLimits{ImageBytes: 512}); err == nil {
				t.Fatal("ignored image limit")
			}
			if _, err := NewDMGReader(bytes.NewReader(encoded.Bytes()), int64(encoded.Len()-1), DMGLimits{}); err == nil {
				t.Fatal("accepted truncated image")
			}
		})
	}
}

func TestDMGReaderLargeRawChunk(t *testing.T) {
	const size = 65 << 20
	var encoded bytes.Buffer
	if err := EncodeUDIF(&encoded, []SourceBlock{{Name: "disk image", Data: bytes.Repeat([]byte{0x5a}, size)}}, &EncodeOptions{Compression: CompressionNone, ChunkSectors: size / sectorSize}); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "large.dmg")
	if err := os.WriteFile(filename, encoded.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	source := &countedDMGSource{Reader: bytes.NewReader(encoded.Bytes())}
	reader, err := NewDMGReader(source, int64(encoded.Len()), DMGLimits{})
	if err != nil {
		t.Fatal(err)
	}
	source.bytes = 0
	buf := make([]byte, 16)
	if n, err := reader.ReadAt(buf, size-16); n != len(buf) || err != nil || !bytes.Equal(buf, bytes.Repeat([]byte{0x5a}, 16)) {
		t.Fatalf("large raw read: %x (%d), %v", buf, n, err)
	}
	if source.bytes != len(buf) {
		t.Fatalf("partial read consumed %d bytes, want %d", source.bytes, len(buf))
	}
	if n, err := ReconstructRawImageTo(repeatedByteWriter{t: t, value: 0x5a}, filename); err != nil || n != size {
		t.Fatalf("reconstruct large writer chunk: %d, %v", n, err)
	}
}

type repeatedByteWriter struct {
	t     *testing.T
	value byte
}

func (w repeatedByteWriter) WriteAt(p []byte, off int64) (int, error) {
	for i, value := range p {
		if value != w.value {
			w.t.Fatalf("byte at %d: %x, want %x", off+int64(i), value, w.value)
		}
	}
	return len(p), nil
}

func TestDMGReaderRecoveryLayouts(t *testing.T) {
	for _, name := range []string{"gap", "unrecognised resource"} {
		t.Run(name, func(t *testing.T) {
			data := bytes.Repeat([]byte{0x5a}, 3*sectorSize)
			var encoded bytes.Buffer
			if err := EncodeUDIF(&encoded, []SourceBlock{{Name: "disk image", Data: data}}, &EncodeOptions{Compression: CompressionNone, ChunkSectors: 1}); err != nil {
				t.Fatal(err)
			}
			var footer DMGFooter
			if err := binary.Read(bytes.NewReader(encoded.Bytes()[encoded.Len()-dmgFooterSize:]), binary.BigEndian, &footer); err != nil {
				t.Fatal(err)
			}
			var doc dmgPlist
			if _, err := plist.Unmarshal(encoded.Bytes()[footer.PlistOffset:footer.PlistOffset+footer.PlistLength], &doc); err != nil {
				t.Fatal(err)
			}
			if name == "gap" {
				block := &doc.ResourceFork.Blkx[0]
				buf := bytes.NewReader(block.Data)
				var header dmgBlockData
				if err := binary.Read(buf, binary.BigEndian, &header); err != nil {
					t.Fatal(err)
				}
				chunks := make([]DMGChunk, header.ChunkCount)
				if err := binary.Read(buf, binary.BigEndian, chunks); err != nil {
					t.Fatal(err)
				}
				header.ChunkCount--
				var changed bytes.Buffer
				if err := binary.Write(&changed, binary.BigEndian, header); err != nil {
					t.Fatal(err)
				}
				chunks = append(chunks[:1], chunks[2:]...)
				if err := binary.Write(&changed, binary.BigEndian, chunks); err != nil {
					t.Fatal(err)
				}
				block.Data = changed.Bytes()
				clear(data[sectorSize : 2*sectorSize])
			} else {
				doc.ResourceFork.Blkx = append(doc.ResourceFork.Blkx, blkxEntry{Name: "unrelated resource", Data: []byte("not a mish block")})
			}
			metadata, err := plist.Marshal(doc, plist.XMLFormat)
			if err != nil {
				t.Fatal(err)
			}
			image := bytes.NewBuffer(bytes.Clone(encoded.Bytes()[:footer.PlistOffset]))
			image.Write(metadata)
			footer.PlistLength = uint64(len(metadata))
			if err := binary.Write(image, binary.BigEndian, footer); err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(t.TempDir(), "recovery.dmg")
			if err := os.WriteFile(filename, image.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			reader, err := OpenDMG(filename)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			got := make([]byte, len(data))
			if n, err := reader.ReadAt(got, 0); n != len(got) || err != nil || !bytes.Equal(got, data) {
				t.Fatalf("recovery layout read: %d, %v; matches = %t", n, err, bytes.Equal(got, data))
			}
			if name == "gap" {
				reconstructed, err := ReconstructRawImage(filename)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(reconstructed, data) {
					t.Fatal("reader and reconstruction disagree about gap")
				}
			}
		})
	}
}

func TestDMGPartitionReaders(t *testing.T) {
	const sectors = 8
	a := bytes.Repeat([]byte("A"), sectors*sectorSize)
	b := bytes.Repeat([]byte("B"), sectors*sectorSize)
	var encoded bytes.Buffer
	blocks := []SourceBlock{
		{Name: "EFI", SectorCount: sectors, Data: a},
		{Name: "HFS", StartSector: sectors, SectorCount: sectors, Data: b},
	}
	if err := EncodeUDIF(&encoded, blocks, &EncodeOptions{Compression: CompressionZlib, ChunkSectors: sectors}); err != nil {
		t.Fatal(err)
	}
	r, err := NewDMGLayoutReader(bytes.NewReader(encoded.Bytes()), int64(encoded.Len()), DMGLayoutOptions{Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, 1, 0} {
		part, err := r.PartitionReader(i)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(part)
		if err != nil || !bytes.Equal(got, blocks[i].Data) {
			t.Fatalf("partition %d returned wrong contents: %v", i, err)
		}
	}
	if _, err := r.PartitionReader(2); err == nil {
		t.Fatal("accepted an out-of-range partition")
	}
}

func TestDMGStrictFooter(t *testing.T) {
	var encoded bytes.Buffer
	blocks := []SourceBlock{{Name: "HFS", SectorCount: 1, Data: make([]byte, sectorSize)}}
	if err := EncodeUDIF(&encoded, blocks, nil); err != nil {
		t.Fatal(err)
	}
	invalid := bytes.Clone(encoded.Bytes())
	invalid[len(invalid)-dmgFooterSize+7] = 3
	if _, err := NewDMGLayoutReader(bytes.NewReader(invalid), int64(len(invalid)), DMGLayoutOptions{Strict: true}); err == nil {
		t.Fatal("accepted an invalid footer version")
	}
}

func TestDMGStrictDescriptor(t *testing.T) {
	last := DMGChunk{Type: chunkTypeLastBlock}
	run := DMGChunk{Type: chunkTypeUncompressed, DiskLength: 2, CompressedLength: 2 * sectorSize}
	sparse := DMGChunk{Type: chunkTypeZeroFill, DiskOffset: 1, DiskLength: 1}
	tests := []struct {
		name   string
		chunks []DMGChunk
		change func(*dmgBlockData)
		tail   bool
		want   string
	}{
		{name: "gap", chunks: []DMGChunk{sparse, last}},
		{name: "empty run", chunks: []DMGChunk{run, {Type: chunkTypeZeroFill, DiskOffset: 1}, last}},
		{name: "overlap", chunks: []DMGChunk{sparse, run, last}, want: "overlapping partition chunks"},
		{name: "image bounds", chunks: []DMGChunk{last}, change: func(h *dmgBlockData) { h.StartSector = 1 }, want: "partition exceeds image bounds"},
		{name: "sparse data offset", chunks: []DMGChunk{sparse, last}, change: func(h *dmgBlockData) { h.DataOffset = 2*sectorSize + 1 }, want: "partition data offset exceeds data fork bounds"},
		{name: "stored run bounds", chunks: []DMGChunk{run, last}, change: func(h *dmgBlockData) { h.DataOffset = 1 }, want: "chunk exceeds source bounds"},
		{name: "missing terminator", chunks: []DMGChunk{run}, want: "missing partition terminator"},
		{name: "early terminator", chunks: []DMGChunk{last, run}, want: "partition terminator before last chunk"},
		{name: "stored sparse", chunks: []DMGChunk{{Type: chunkTypeZeroFill, DiskLength: 1, CompressedLength: 1}, last}, want: "stored bytes for sparse chunk"},
		{name: "version", chunks: []DMGChunk{last}, change: func(h *dmgBlockData) { h.Version++ }, want: "invalid partition version or chunk table size"},
		{name: "extra table bytes", chunks: []DMGChunk{last}, tail: true, want: "invalid partition version or chunk table size"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := dmgBlockData{Version: 1, SectorCount: 2, ChunkCount: uint32(len(tt.chunks))}
			copy(header.Signature[:], mishSignature)
			if tt.change != nil {
				tt.change(&header)
			}
			var data bytes.Buffer
			if err := binary.Write(&data, binary.BigEndian, header); err != nil {
				t.Fatal(err)
			}
			if err := binary.Write(&data, binary.BigEndian, tt.chunks); err != nil {
				t.Fatal(err)
			}
			if tt.tail {
				data.WriteByte(0)
			}
			block := &blkxEntry{Data: data.Bytes()}
			reader := &DMGReader{size: 4 * sectorSize, footer: DMGFooter{DataForkLength: 2 * sectorSize, SectorCount: 2}, limits: (DMGLimits{}).defaults()}
			if _, err := reader.parsePartition(block); err != nil {
				t.Fatalf("recovery reader rejected descriptor: %v", err)
			}
			reader.strict = true
			part, err := reader.parsePartition(block)
			if tt.want != "" {
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("got %v, want %q", err, tt.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(part.Chunks) != 1 {
				t.Fatalf("got %d runs, want one", len(part.Chunks))
			}
		})
	}
}

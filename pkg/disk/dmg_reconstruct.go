// Reconstruction helpers for the UDIF/DMG writer: materialise the full raw
// disk image (or per-block raw data) from an existing DMG so it can be
// losslessly re-encoded or compared byte-for-byte.
package disk

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"howett.net/plist"
)

// marshalPlist renders the resource-fork/blkx plist as an XML property list,
// matching the shape hdiutil and this package's reader expect.
func marshalPlist(entries []udifBlkx) ([]byte, error) {
	doc := udifPlist{ResourceFork: udifResourceFork{Blkx: entries}}
	return plist.MarshalIndent(&doc, plist.XMLFormat, "\t")
}

// readFooterAndPlist opens dmgPath, reads its koly trailer, and unmarshals the
// resource-fork plist. It returns the open file (caller must close), the
// footer, and the parsed blkx entries.
func readFooterAndPlist(dmgPath string) (*os.File, DMGFooter, []udifBlkx, error) {
	f, err := os.Open(dmgPath)
	if err != nil {
		return nil, DMGFooter{}, nil, fmt.Errorf("open: %w", err)
	}

	var footer DMGFooter
	if _, err := f.Seek(-dmgFooterSize, io.SeekEnd); err != nil {
		f.Close()
		return nil, DMGFooter{}, nil, fmt.Errorf("seek footer: %w", err)
	}
	if err := binary.Read(f, binary.BigEndian, &footer); err != nil {
		f.Close()
		return nil, DMGFooter{}, nil, fmt.Errorf("read footer: %w", err)
	}
	if string(footer.Signature[:]) != dmgSignature {
		f.Close()
		return nil, DMGFooter{}, nil, fmt.Errorf("invalid DMG signature %q", footer.Signature[:])
	}
	if footer.PlistOffset == 0 || footer.PlistLength == 0 {
		f.Close()
		return nil, DMGFooter{}, nil, fmt.Errorf("no plist in DMG")
	}

	plistData := make([]byte, footer.PlistLength)
	if _, err := f.ReadAt(plistData, int64(footer.PlistOffset)); err != nil {
		f.Close()
		return nil, DMGFooter{}, nil, fmt.Errorf("read plist: %w", err)
	}

	var doc udifPlist
	if _, err := plist.Unmarshal(plistData, &doc); err != nil {
		f.Close()
		return nil, DMGFooter{}, nil, fmt.Errorf("unmarshal plist: %w", err)
	}
	if len(doc.ResourceFork.Blkx) == 0 {
		f.Close()
		return nil, DMGFooter{}, nil, fmt.Errorf("no blkx blocks in plist")
	}

	return f, footer, doc.ResourceFork.Blkx, nil
}

// reconstructBlocks decompresses every blkx block of the DMG at dmgPath into
// per-block raw byte buffers, preserving block names/IDs and sector ranges.
// The returned totalSectors is the full raw image size in 512-byte sectors.
func reconstructBlocks(dmgPath string) ([]SourceBlock, uint64, error) {
	f, footer, blkx, err := readFooterAndPlist(dmgPath)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	// decompressChunk only touches r.file and the chunk fields, so a minimal
	// reader is sufficient to reuse the reader's decompression logic.
	r := &DMGReader{file: f}

	blocks := make([]SourceBlock, 0, len(blkx))
	var totalSectors uint64

	for _, entry := range blkx {
		if len(entry.Data) == 0 {
			continue
		}

		buf := bytes.NewReader(entry.Data)
		var bd dmgBlockData
		if err := binary.Read(buf, binary.BigEndian, &bd); err != nil {
			return nil, 0, fmt.Errorf("block %q: read mish header: %w", entry.Name, err)
		}
		if string(bd.Signature[:]) != mishSignature {
			// Not a mish block (e.g. license-agreement resource); skip.
			continue
		}

		data := make([]byte, bd.SectorCount*sectorSize)

		for i := uint32(0); i < bd.ChunkCount; i++ {
			var c DMGChunk
			if err := binary.Read(buf, binary.BigEndian, &c); err != nil {
				return nil, 0, fmt.Errorf("block %q: read chunk %d: %w", entry.Name, i, err)
			}

			// Reproduce the reader's offset arithmetic. DiskOffset is made
			// block-relative here (do not add StartSector) because we fill a
			// per-block buffer.
			blockRelSector := c.DiskOffset // still the on-disk SectorNumber
			c.DiskOffset = (c.DiskOffset + bd.StartSector) * sectorSize
			c.DiskLength = c.DiskLength * sectorSize
			c.CompressedOffset = c.CompressedOffset + bd.DataOffset + footer.DataForkOffset

			switch c.Type {
			case chunkTypeComment, chunkTypeLastBlock:
				continue
			case chunkTypeZeroFill, chunkTypeIgnored:
				// The block buffer is already zeroed; nothing to copy.
				continue
			}

			decompressed, err := r.decompressChunk(&c)
			if err != nil {
				return nil, 0, fmt.Errorf("block %q: decompress chunk %d (type 0x%x): %w", entry.Name, i, c.Type, err)
			}

			off := blockRelSector * sectorSize
			if off+uint64(len(decompressed)) > uint64(len(data)) {
				return nil, 0, fmt.Errorf("block %q: chunk %d overflows block (off=%d len=%d cap=%d)", entry.Name, i, off, len(decompressed), len(data))
			}
			copy(data[off:], decompressed)
		}

		blocks = append(blocks, SourceBlock{
			Name:        entry.Name,
			CFName:      entry.CFName,
			ID:          entry.ID,
			Attributes:  entry.Attributes,
			StartSector: bd.StartSector,
			SectorCount: bd.SectorCount,
			Data:        data,
		})

		if end := bd.StartSector + bd.SectorCount; end > totalSectors {
			totalSectors = end
		}
	}

	if len(blocks) == 0 {
		return nil, 0, fmt.Errorf("no mish blocks found in %s", dmgPath)
	}

	if footer.SectorCount > totalSectors {
		totalSectors = footer.SectorCount
	}

	return blocks, totalSectors, nil
}

// ReconstructRawImage returns the complete raw disk image encoded by the DMG at
// dmgPath: every block (zero-fill and ignored materialised as zeros, others
// decompressed) placed at its absolute sector offset. The result is a
// byte-exact reproduction of the original raw image.
//
// Note: the entire raw image is held in memory. For the large images this
// package targets (a few hundred MB) that is acceptable; callers repacking
// very large images should prefer RepackDMG, which never assembles the full
// image at once.
func ReconstructRawImage(dmgPath string) ([]byte, error) {
	blocks, totalSectors, err := reconstructBlocks(dmgPath)
	if err != nil {
		return nil, err
	}

	raw := make([]byte, totalSectors*sectorSize)
	for i := range blocks {
		b := &blocks[i]
		off := b.StartSector * sectorSize
		if off+uint64(len(b.Data)) > uint64(len(raw)) {
			return nil, fmt.Errorf("block %q overflows raw image", b.Name)
		}
		copy(raw[off:], b.Data)
	}

	return raw, nil
}

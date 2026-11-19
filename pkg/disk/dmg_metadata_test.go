package disk

import (
	"bytes"
	"testing"
)

func TestDMGFooterMetadata(t *testing.T) {
	var image bytes.Buffer
	blocks := []SourceBlock{{Name: "disk image", Data: make([]byte, sectorSize)}}
	if err := EncodeUDIF(&image, blocks, nil); err != nil {
		t.Fatal(err)
	}
	r, err := NewDMGReader(bytes.NewReader(image.Bytes()), int64(image.Len()), DMGLimits{})
	if err != nil {
		t.Fatal(err)
	}
	footer := r.Footer()
	if footer.Version != udifVersion || footer.HeaderSize != dmgFooterSize || footer.SectorCount != 1 {
		t.Fatalf("footer: version %d, header size %d, sectors %d", footer.Version, footer.HeaderSize, footer.SectorCount)
	}
}

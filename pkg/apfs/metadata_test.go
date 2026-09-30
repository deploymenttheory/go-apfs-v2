package apfs

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
)

func TestImageMetadataInvalidVolume(t *testing.T) {
	for _, v := range []*Volume{nil, {}} {
		got, err := v.Metadata(".")
		var pe *fs.PathError
		if !errors.As(err, &pe) || pe.Op != "metadata" || got != (hostmeta.ImageMetadata{}) {
			t.Fatalf("%+v %v", got, err)
		}
	}
}

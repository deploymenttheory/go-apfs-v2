//go:build !darwin

package hostmeta

import (
	"errors"
	"os"
)

func newHeldMetadata(*os.File) (heldMetadataOperations, error) { return nil, errors.ErrUnsupported }

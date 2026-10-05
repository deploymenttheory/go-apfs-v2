//go:build !darwin

package hostdata

import (
	"errors"
	"os"
)

func newHeldCompressionCommit(*os.File) (CompressionCommitBackend, error) {
	return nil, errors.ErrUnsupported
}

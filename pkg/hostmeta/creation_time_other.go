//go:build !darwin

package hostmeta

import (
	"os"
	"time"
)

func setCreationTime(_ *os.File, _ time.Time) error {
	return ErrCreationTimeUnsupported
}

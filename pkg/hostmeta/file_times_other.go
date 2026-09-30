//go:build !darwin && !linux && !windows

package hostmeta

import (
	"os"
	"time"
)

func setFileTimes(_ *os.File, _, _ time.Time) error { return ErrFileTimesUnsupported }

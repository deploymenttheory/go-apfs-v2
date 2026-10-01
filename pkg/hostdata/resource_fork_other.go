//go:build !darwin

package hostdata

import (
	"errors"
	"os"
)

func openNativeResourceFork(int, bool) (*os.File, error) { return nil, errors.ErrUnsupported }

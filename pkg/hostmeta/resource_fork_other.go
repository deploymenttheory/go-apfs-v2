//go:build !darwin

package hostmeta

import (
	"errors"
	"os"
)

func openNativeResourceFork(int, bool) (*os.File, error) { return nil, errors.ErrUnsupported }

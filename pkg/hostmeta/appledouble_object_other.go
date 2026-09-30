//go:build !darwin

package hostmeta

import (
	"errors"
	"os"
)

func newHostObjectAttributes(*os.File) (objectAttributes, error) { return nil, errors.ErrUnsupported }

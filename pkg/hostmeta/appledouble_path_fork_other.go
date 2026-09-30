//go:build !darwin

package hostmeta

import (
	"errors"
	"io"
	"os"
)

func openPathResourceForkNative(*os.File, bool, uint32) (io.Closer, error) {
	return nil, errors.ErrUnsupported
}

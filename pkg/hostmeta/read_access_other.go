//go:build !darwin

package hostmeta

import "os"

func recordReadAccess(_ *os.File) error {
	return ErrReadAccessUnsupported
}

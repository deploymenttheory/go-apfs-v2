//go:build !darwin

package hostmeta

import "errors"

func captureAppSandbox() (bool, error) { return false, errors.ErrUnsupported }

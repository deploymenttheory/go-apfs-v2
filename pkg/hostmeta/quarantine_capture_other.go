//go:build !darwin

package hostmeta

import (
	"context"
	"errors"
)

func captureNativeQuarantineProcess(context.Context) (*QuarantineProcessCapture, error) {
	return nil, errors.ErrUnsupported
}

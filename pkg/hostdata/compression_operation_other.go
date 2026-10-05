//go:build !darwin

package hostdata

import (
	"context"
	"errors"
)

func openNativeCompressionInput(context.Context, string) (CompressionInput, error) {
	return nil, errors.ErrUnsupported
}

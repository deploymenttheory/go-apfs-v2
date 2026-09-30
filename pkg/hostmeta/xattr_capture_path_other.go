//go:build !darwin && !linux && !windows

package hostmeta

import "context"

func captureXattrsPath(context.Context, string, XattrCaptureLimits) (map[string][]byte, error) {
	return nil, ErrXattrUnsupported
}

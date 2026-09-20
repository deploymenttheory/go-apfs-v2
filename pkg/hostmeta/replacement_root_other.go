//go:build !darwin && !linux && !windows

package hostmeta

import "os"

func prepareReplacementAt(_ *os.File, _ *os.Root, _ os.FileInfo) (*os.File, error) {
	return nil, ErrUnsupportedReplacement
}

func restoreReplacementMetadataAt(_, _ *os.File, _ os.FileInfo) error {
	return ErrUnsupportedReplacement
}

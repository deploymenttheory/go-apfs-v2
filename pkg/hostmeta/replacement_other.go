//go:build !darwin && !linux && !windows

package hostmeta

import "os"

func prepareReplacement(_ *os.File, _ string, _ os.FileInfo) (*os.File, error) {
	return nil, ErrUnsupportedReplacement
}

func restoreReplacementMetadata(_, _ *os.File, _ os.FileInfo) error {
	return ErrUnsupportedReplacement
}

//go:build !windows

package hostdata

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func prepareReplacementPrivateContext(ctx context.Context, source *os.File, parent string, info os.FileInfo) (*Replacement, error) {
	dir, err := os.MkdirTemp(parent, ".apfs-replacement-")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "replacement")
	f, err := prepareReplacementContext(ctx, source, path, info)
	err = errors.Join(err, ctx.Err())
	if err != nil {
		if f != nil {
			err = errors.Join(err, f.Close())
		}
		return nil, errors.Join(fmt.Errorf("prepare replacement: %w", err), cleanupReplacement(
			func() error { return os.Chmod(path, 0600) }, func() error { return os.RemoveAll(dir) }))
	}
	return &Replacement{File: f, source: source, info: info, dir: dir}, nil
}

func makeReplacementDirectoryAt(ctx context.Context, root *os.Root, name string) (func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := root.Mkdir(name, 0700); err != nil {
		return nil, err
	}
	return func() error { return nil }, ctx.Err()
}

func replacementCleanupCapability(_ *os.File) (*os.File, error) { return nil, nil }
func replacementCleanupMetadata(stage *os.Root, _ *os.File) error {
	return stage.Chmod("replacement", 0600)
}

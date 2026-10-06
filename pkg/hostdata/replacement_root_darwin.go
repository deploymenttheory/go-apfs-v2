package hostdata

import (
	"context"
	"fmt"
	"os"

	hostflags "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/bsdflags"
	"golang.org/x/sys/unix"
)

func prepareReplacementAtContext(ctx context.Context, source *os.File, stage *os.Root, info os.FileInfo) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	flags, _ := hostflags.Flags(info)
	if flags&(unix.UF_IMMUTABLE|unix.UF_APPEND|unix.SF_IMMUTABLE|unix.SF_APPEND) != 0 {
		return nil, fmt.Errorf("%w: protected source", ErrUnsupportedReplacement)
	}
	dir, err := stage.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	// Setattrlist has no descriptor variant in x/sys. Darwin's fdescfs path
	// names this held directory descriptor, not any caller-controlled pathname.
	if err := clearReplacementACL(fmt.Sprintf("/dev/fd/%d", dir.Fd())); err != nil {
		return nil, err
	}
	return prepareReplacementUsingContext(ctx,
		func() error {
			// Rewritten logical contents must not inherit the old compressed
			// storage. A fresh file also avoids decompression writes against
			// a clone before the caller has supplied the replacement bytes.
			if flags&UFCompressed != 0 {
				return unix.ENOTSUP
			}
			return unix.Fclonefileat(int(source.Fd()), int(dir.Fd()), "replacement", 0)
		},
		replacementCloneUnavailable,
		func(cloned bool) (*os.File, error) {
			if !cloned {
				return stage.OpenFile("replacement", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			}
			if err := stage.Chmod("replacement", 0600); err != nil {
				return nil, err
			}
			return stage.OpenFile("replacement", os.O_RDWR, 0)
		},
		func(target *os.File) error { return copyReplacementMetadataContext(ctx, source, target, info) },
	)
}

func restoreReplacementMetadataAtContext(ctx context.Context, source, target *os.File, info os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return restoreReplacementMetadataContext(ctx, source, target, info)
}

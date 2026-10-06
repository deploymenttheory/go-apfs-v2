package hostdata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func prepareReplacementContext(ctx context.Context, _ *os.File, path string, _ os.FileInfo) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
}

func restoreReplacementMetadataContext(ctx context.Context, source, target *os.File, info os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s := info.Sys().(*syscall.Stat_t)
	if err := replacementStep(ctx, func() error { return target.Chown(int(s.Uid), int(s.Gid)) }); err != nil {
		return err
	}
	// ListXattrs is intentionally best effort for image extraction. Replacing a
	// file requires a bounded descriptor-based copy which fails on lost metadata.
	fd, to := int(source.Fd()), int(target.Fd())
	// A newly created staging file may have inherited a default directory ACL.
	// Remove it before copying, including when the original file has no ACL.
	if err := replacementStep(ctx, func() error {
		err := unix.Fremovexattr(to, PosixACLAccessName)
		// Only the native absence/capability result is harmless. Let the
		// surrounding checkpoint retain any concurrent cancellation.
		if errors.Is(err, unix.ENODATA) || isUnsupported(err) {
			return nil
		}
		return err
	}); err != nil {
		return err
	}
	size, err := replacementValue(ctx, func() (int, error) { return unix.Flistxattr(fd, nil) })
	if isUnsupported(err) {
		return replacementStep(ctx, func() error { return target.Chmod(info.Mode()) })
	}
	if err != nil {
		return err
	}
	const limit = 8 << 20
	if size > limit {
		return fmt.Errorf("%w: extended attribute names exceed limit", ErrUnsupportedReplacement)
	}
	names := make([]byte, size)
	size, err = replacementValue(ctx, func() (int, error) { return unix.Flistxattr(fd, names) })
	if err != nil {
		return err
	}
	if size > len(names) {
		return fmt.Errorf("extended attribute list changed")
	}
	budget := limit
	for _, name := range bytes.Split(names[:size], []byte{0}) {
		if len(name) == 0 {
			continue
		}
		size, err := replacementValue(ctx, func() (int, error) { return unix.Fgetxattr(fd, string(name), nil) })
		if err != nil {
			return err
		}
		if size > budget {
			return fmt.Errorf("%w: extended attributes exceed limit", ErrUnsupportedReplacement)
		}
		budget -= size
		value := make([]byte, size)
		size, err = replacementValue(ctx, func() (int, error) { return unix.Fgetxattr(fd, string(name), value) })
		if err != nil {
			return err
		}
		if size > len(value) {
			return fmt.Errorf("extended attribute value changed")
		}
		if err := replacementStep(ctx, func() error { return unix.Fsetxattr(to, string(name), value[:size], 0) }); err != nil {
			return err
		}
	}
	return replacementStep(ctx, func() error { return target.Chmod(info.Mode()) })
}

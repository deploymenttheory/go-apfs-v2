package hostdata

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"golang.org/x/sys/unix"
)

func replacementCloneUnavailable(err error) bool {
	return errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EXDEV) || errors.Is(err, unix.ENOSYS)
}

func copyReplacementMetadata(source, target *os.File, info os.FileInfo) error {
	birth := info.Sys().(*syscall.Stat_t).Birthtimespec
	return copyReplacementMetadataUsing(replacementCopyOps{
		list:     func() ([]string, error) { return ListXattrNames(source, MaxXattrListSize) },
		read:     func(name string, limit int) ([]byte, bool, error) { return ReadXattr(source, name, limit) },
		write:    func(name string, value []byte) error { return SetXattr(target, name, value) },
		openFork: func() (replacementFork, error) { return OpenResourceFork(source, false) },
		replaceFork: func(value appledouble.Value) error {
			_, err := ReplaceResourceFork(context.Background(), target, value)
			return err
		},
		birth: func() error { return SetCreationTime(target, time.Unix(birth.Sec, birth.Nsec)) },
	})
}

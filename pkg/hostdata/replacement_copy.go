package hostdata

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// Clone failure is not generally permission to copy: authorization, storage and
// source errors must survive. The platform supplies its precise capability errors.
func prepareReplacementUsing(clone func() error, unavailable func(error) bool, open func(bool) (*os.File, error), metadata func(*os.File) error) (*os.File, error) {
	err := clone()
	cloned := err == nil
	if err != nil && !unavailable(err) {
		return nil, err
	}
	target, err := open(cloned)
	if err != nil {
		return nil, err
	}
	if !cloned {
		if err = metadata(target); err != nil {
			return nil, errors.Join(err, target.Close())
		}
	}
	return target, nil
}

type replacementFork interface {
	io.ReaderAt
	Stat() (os.FileInfo, error)
	Close() error
}

type replacementCopyOps struct {
	compressed  bool
	list        func() ([]string, error)
	read        func(string, int) ([]byte, bool, error)
	write       func(string, []byte) error
	openFork    func() (replacementFork, error)
	replaceFork func(appledouble.Value) error
	birth       func() error
}

// Only ordinary xattrs share the existing allocation budget. Resource forks are
// streamed through held descriptors and never squeezed into an xattr buffer.
// Security is deliberately deferred to RestoreMetadata, after content writes.
func copyReplacementMetadataUsing(ops replacementCopyOps) error {
	compressionFork := false
	if ops.compressed {
		value, present, err := ops.read(DecmpfsName, decmpfs.MaxAttributeSize)
		if err != nil {
			return fmt.Errorf("replacement compression: %w", err)
		}
		if !present {
			return fmt.Errorf("replacement compression: %w", ErrXattrChanged)
		}
		compressionFork, err = decmpfs.UsesResourceFork(bytes.NewReader(value))
		if err != nil {
			return fmt.Errorf("replacement compression: %w", err)
		}
	}
	names, err := ops.list()
	if err != nil {
		return err
	}
	remaining := MaxXattrReadSize
	for _, name := range names {
		if ops.compressed && (name == DecmpfsName || (compressionFork && name == ResourceForkName)) {
			continue
		}
		if name == "com.apple.ResourceFork" {
			if err := copyReplacementFork(ops); err != nil {
				return fmt.Errorf("replacement resource fork: %w", err)
			}
			continue
		}
		value, present, err := ops.read(name, remaining)
		if err != nil {
			return fmt.Errorf("replacement attribute %q: %w", name, err)
		}
		if !present {
			return fmt.Errorf("replacement attribute %q: %w", name, ErrXattrChanged)
		}
		remaining -= len(value)
		if err := ops.write(name, value); err != nil {
			return fmt.Errorf("replacement attribute %q: %w", name, err)
		}
	}
	return ops.birth()
}

func copyReplacementFork(ops replacementCopyOps) (err error) {
	fork, err := ops.openFork()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, fork.Close()) }()
	info, err := fork.Stat()
	if err != nil {
		return err
	}
	return ops.replaceFork(io.NewSectionReader(fork, 0, info.Size()))
}

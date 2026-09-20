package hostmeta

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Replacement is a private, writable file prepared from an existing regular
// file. Write and truncate File, then call RestoreMetadata before closing and
// renaming it. Call Close to discard the staging directory on every path.
// The source must remain open and unchanged until RestoreMetadata returns.
//
// This API never changes the source or commits a rename. It deliberately fails
// if it cannot preserve the supported metadata; unlike ListXattrs/SetXattrs,
// missing metadata is not treated as a recoverable fidelity loss.
type Replacement struct {
	File   *os.File
	source *os.File
	info   os.FileInfo
	dir    string
}

// PrepareReplacement creates a private staging directory under parent on the
// source filesystem. Its initial data is unspecified: callers
// must write the complete replacement and truncate to its intended length.
//
// On Darwin this requires clonefile support and preserves the clone's ACL,
// extended attributes and creation time. Protected and compressed files are
// unsupported. On Linux ownership, mode and readable extended attributes
// (including POSIX ACLs) are restored. On Windows CopyFile preserves streams
// and attributes; the owner, group and DACL are restored explicitly. Unix xattr
// names and values each have an 8 MiB aggregate limit. Modification/access
// timestamps and Linux inode flags are not preserved. No cgo is required.
func PrepareReplacement(source *os.File, parent string) (*Replacement, error) {
	info, err := source.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("prepare replacement: %w: non-regular source", ErrUnsupportedReplacement)
	}
	dir, err := os.MkdirTemp(parent, ".apfs-replacement-")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "replacement")
	f, err := prepareReplacement(source, path, info)
	if err != nil {
		_ = os.Chmod(path, 0600)
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("prepare replacement: %w", err)
	}
	return &Replacement{File: f, source: source, info: info, dir: dir}, nil
}

// RestoreMetadata restores metadata after all replacement content has been
// written. On failure the caller must discard the replacement without renaming
// it over the source. It does not sync or close either file.
func (r *Replacement) RestoreMetadata() error {
	current, err := r.source.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(r.info, current) {
		return fmt.Errorf("replacement source changed")
	}
	return restoreReplacementMetadata(r.source, r.File, r.info)
}

// Close closes File if necessary and removes the private staging directory.
// It is safe after the caller closes or renames File. It never closes source.
func (r *Replacement) Close() error {
	err := r.File.Close()
	if errors.Is(err, os.ErrClosed) {
		err = nil
	}
	_ = os.Chmod(r.File.Name(), 0600) // allow removal of a Windows read-only copy
	return errors.Join(err, os.RemoveAll(r.dir))
}

// ErrUnsupportedReplacement identifies file types, metadata or filesystems
// whose replacement metadata this package cannot safely preserve.
var ErrUnsupportedReplacement = errors.New("unsupported replacement metadata")

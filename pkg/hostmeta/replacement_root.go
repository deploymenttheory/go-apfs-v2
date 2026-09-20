package hostmeta

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// RootReplacement is a writable replacement staged beneath an opened root.
// Path is relative to the root supplied to PrepareReplacementAt, suitable for
// root.Rename after writing, RestoreMetadata, syncing and closing File.
// Preparation and cleanup never rename or modify the source.
//
// The caller owns source and root: keep source open and unchanged through
// RestoreMetadata, and root open through Close. Close must be called on success
// and failure, including after a successful rename. Methods are not concurrent.
type RootReplacement struct {
	File *os.File
	Path string

	source        *os.File
	info          os.FileInfo
	root, staging *os.Root
	dir           string
	closed        bool
}

// PrepareReplacementAt prepares a regular source file in a private directory
// beneath parent, relative to root. Destination operations use opened roots and
// handles rather than reconstructing absolute paths. The initial content of
// File is unspecified; write the complete replacement and truncate it.
//
// The supported metadata and Darwin clone requirement match PrepareReplacement.
// Windows additionally rejects compressed, encrypted, sparse and reparse files;
// ordinary alternate data streams, attributes, owner/group and DACL are retained.
// Concurrent modification of the source or staging tree is unsupported. The
// caller must validate destination identity before committing its own rename.
func PrepareReplacementAt(source *os.File, root *os.Root, parent string) (*RootReplacement, error) {
	info, err := source.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("prepare replacement: %w: non-regular source", ErrUnsupportedReplacement)
	}
	dir := filepath.Join(parent, ".apfs-replacement-"+rand.Text())
	if err := root.Mkdir(dir, 0700); err != nil {
		return nil, err
	}
	stage, err := root.OpenRoot(dir)
	if err != nil {
		return nil, errors.Join(err, root.Remove(dir))
	}
	r := &RootReplacement{source: source, info: info, root: root, staging: stage, dir: dir, Path: filepath.Join(dir, "replacement")}
	r.File, err = prepareReplacementAt(source, stage, info)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("prepare replacement: %w", err), r.Close())
	}
	return r, nil
}

// RestoreMetadata restores supported metadata after content writes, without
// syncing or closing either file. A failure requires discarding the replacement.
func (r *RootReplacement) RestoreMetadata() error {
	if r.closed {
		return os.ErrClosed
	}
	current, err := r.source.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(r.info, current) {
		return fmt.Errorf("replacement source changed")
	}
	return restoreReplacementMetadataAt(r.source, r.File, r.info)
}

// Close closes the staged file and removes its private directory. It is
// idempotent and safe after File has been closed or renamed. It does not close
// source or the caller's root and does not chmod a committed replacement.
func (r *RootReplacement) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	var closeErr error
	if r.File != nil {
		closeErr = r.File.Close()
		if errors.Is(closeErr, os.ErrClosed) {
			closeErr = nil
		}
	}
	// A readonly Windows copy needs its attribute cleared for deletion. Only
	// touch the private staging name, which is absent after a successful commit.
	chmodErr := r.staging.Chmod("replacement", 0600)
	if errors.Is(chmodErr, os.ErrNotExist) {
		chmodErr = nil
	}
	removeErr := r.staging.Remove("replacement")
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	return errors.Join(closeErr, chmodErr, removeErr, r.staging.Close(), r.root.Remove(r.dir))
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import (
	"fmt"
	"os"
)

// setRoot retains caller-supplied metadata on the special root inode, without
// counting it as a user directory or allocating a new inode number. Stream IDs
// follow the user entries so metadata-free roots retain the existing layout.
func (b volCtx) setRoot(source *Entry, nextOID uint64) (uint64, error) {
	if source == nil {
		return nextOID, nil
	}
	root := *source
	if kind := root.Mode.Type(); kind != 0 && kind != os.ModeDir {
		return nextOID, fmt.Errorf("apfswrite: volume root must be a directory, got %s", kind)
	}
	// The root's name and payload have never represented a user file. Work on
	// a copy so neither normalization nor validation mutates the caller's tree.
	root.Name, root.Data = "root", nil
	root.Mode |= os.ModeDir
	xattrs, flags, bsdFlags, err := validateXattrs(&root)
	if err != nil {
		return nextOID, err
	}
	embedded, streamed := splitXattrs(xattrs)
	mode := uint16(sIFDIR) | uint16(source.Mode.Perm())
	if source.Mode == 0 {
		mode |= 0755
	}
	for _, bit := range []struct {
		host os.FileMode
		disk uint16
	}{{os.ModeSetuid, 04000}, {os.ModeSetgid, 02000}, {os.ModeSticky, 01000}} {
		if root.Mode&bit.host != 0 {
			mode |= bit.disk
		}
	}
	b.root = &builderEntry{name: "root", oid: rootDirInoNum, parent: rootDirParent, isDir: true, mode: mode, uid: root.UID, gid: root.GID, mtime: b.entryTime(root.ModTime), timeSet: true, xattrs: embedded, xattrFlags: flags, bsdFlags: bsdFlags}
	return b.addXattrStreams(b.root, streamed, nextOID), nil
}

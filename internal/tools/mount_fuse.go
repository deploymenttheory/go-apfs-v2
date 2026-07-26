//go:build linux || darwin

// FUSE filesystem integration for APFS mounting
// Uses github.com/hanwen/go-fuse/v2 for FUSE operations
package tools

import (
	"context"
	"fmt"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// APFSFileSystem implements the FUSE filesystem interface for APFS
type APFSFileSystem struct {
	fs.Inode
	mountHandle    *MountHandle
	fileSystem     *MountFileSystem
	volumeIndex    int
	inodeCache     map[uint64]*MountFileEntry
	openFiles      map[uint64]*apfs.FileEntry
	nextFileHandle uint64
}

// NewAPFSFileSystem creates a new APFS FUSE filesystem
func NewAPFSFileSystem(mountHandle *MountHandle, volumeIndex int) (*APFSFileSystem, error) {
	if mountHandle == nil {
		return nil, fmt.Errorf("mount handle cannot be nil")
	}

	// Get the volume
	volume, err := mountHandle.VolumeByIndex(volumeIndex)
	if err != nil {
		return nil, fmt.Errorf("unable to get volume %d: %w", volumeIndex, err)
	}

	// Create mount file system
	fileSystem := NewMountFileSystem()
	if err := fileSystem.SetVolume(volume); err != nil {
		return nil, fmt.Errorf("unable to set volume: %w", err)
	}

	return &APFSFileSystem{
		mountHandle:    mountHandle,
		fileSystem:     fileSystem,
		volumeIndex:    volumeIndex,
		inodeCache:     make(map[uint64]*MountFileEntry),
		openFiles:      make(map[uint64]*apfs.FileEntry),
		nextFileHandle: 1,
	}, nil
}

// Ensure APFSFileSystem implements required interfaces
var _ fs.NodeGetattrer = (*APFSFileSystem)(nil)
var _ fs.NodeReaddirer = (*APFSFileSystem)(nil)
var _ fs.NodeLookuper = (*APFSFileSystem)(nil)
var _ fs.NodeOpener = (*APFSFileSystem)(nil)
var _ fs.NodeReadlinker = (*APFSFileSystem)(nil)

// Getattr implements fs.NodeGetattrer
// This returns file attributes for the inode
func (afs *APFSFileSystem) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	// Get the file entry for this inode
	entry, err := afs.getFileEntryForInode(afs.StableAttr().Ino)
	if err != nil {
		return syscall.ENOENT
	}

	// Fill in the attributes
	if err := afs.fillAttr(entry, &out.Attr); err != nil {
		return syscall.EIO
	}

	return 0
}

// Lookup implements fs.NodeLookuper
// This looks up a child by name
func (afs *APFSFileSystem) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	// Get parent entry
	parentEntry, err := afs.getFileEntryForInode(afs.StableAttr().Ino)
	if err != nil {
		return nil, syscall.ENOENT
	}

	// Search for the child
	numChildren, err := parentEntry.NumberOfSubFileEntries()
	if err != nil {
		return nil, syscall.EIO
	}

	for i := 0; i < numChildren; i++ {
		childEntry, err := parentEntry.SubFileEntryByIndex(i)
		if err != nil {
			continue
		}

		childName, err := childEntry.Name()
		if err != nil {
			continue
		}

		if childName == name {
			// Found it - fill in attributes
			if err := afs.fillAttr(childEntry, &out.Attr); err != nil {
				return nil, syscall.EIO
			}

			// Get the inode number
			inode, err := childEntry.Identifier()
			if err != nil {
				return nil, syscall.EIO
			}

			// Cache the entry
			afs.inodeCache[inode] = childEntry

			// Create stable attributes
			stable := fs.StableAttr{
				Ino:  inode,
				Mode: uint32(out.Attr.Mode),
			}

			// Create child node
			child := &APFSFileSystem{
				mountHandle:    afs.mountHandle,
				fileSystem:     afs.fileSystem,
				volumeIndex:    afs.volumeIndex,
				inodeCache:     afs.inodeCache,
				openFiles:      afs.openFiles,
				nextFileHandle: afs.nextFileHandle,
			}

			return afs.NewInode(ctx, child, stable), 0
		}
	}

	return nil, syscall.ENOENT
}

// Readdir implements fs.NodeReaddirer
// This reads directory entries
func (afs *APFSFileSystem) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	entry, err := afs.getFileEntryForInode(afs.StableAttr().Ino)
	if err != nil {
		return nil, syscall.ENOENT
	}

	numChildren, err := entry.NumberOfSubFileEntries()
	if err != nil {
		return nil, syscall.EIO
	}

	var entries []fuse.DirEntry

	// Add . and ..
	entries = append(entries, fuse.DirEntry{
		Mode: fuse.S_IFDIR,
		Name: ".",
		Ino:  afs.StableAttr().Ino,
	})

	// Add .. entry if not root
	if afs.StableAttr().Ino != 1 && afs.StableAttr().Ino != 2 {
		entries = append(entries, fuse.DirEntry{
			Mode: fuse.S_IFDIR,
			Name: "..",
			Ino:  1, // Parent is typically root
		})
	}

	// Add children
	for i := 0; i < numChildren; i++ {
		childEntry, err := entry.SubFileEntryByIndex(i)
		if err != nil {
			continue
		}

		childName, err := childEntry.Name()
		if err != nil {
			continue
		}

		childInode, err := childEntry.Identifier()
		if err != nil {
			continue
		}

		fileMode, err := childEntry.FileMode()
		if err != nil {
			continue
		}

		entries = append(entries, fuse.DirEntry{
			Mode: uint32(fileMode),
			Name: childName,
			Ino:  childInode,
		})
	}

	return fs.NewListDirStream(entries), 0
}

// Open implements fs.NodeOpener
func (afs *APFSFileSystem) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	entry, err := afs.getFileEntryForInode(afs.StableAttr().Ino)
	if err != nil {
		return nil, 0, syscall.ENOENT
	}

	// Store the file entry for reading
	fh := afs.nextFileHandle
	afs.nextFileHandle++
	afs.openFiles[fh] = entry.FileEntry

	return &APFSFileHandle{
		fileEntry: entry.FileEntry,
		handle:    fh,
	}, 0, 0
}

// Readlink implements fs.NodeReadlinker
func (afs *APFSFileSystem) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	entry, err := afs.getFileEntryForInode(afs.StableAttr().Ino)
	if err != nil {
		return nil, syscall.ENOENT
	}

	target, err := entry.SymbolicLinkTarget()
	if err != nil {
		return nil, syscall.EIO
	}

	return []byte(target), 0
}

// Helper methods

func (afs *APFSFileSystem) getFileEntryForInode(inode uint64) (*MountFileEntry, error) {
	// Check cache first
	if entry, ok := afs.inodeCache[inode]; ok {
		return entry, nil
	}

	// For root inode (typically 1 or 2), get root directory
	if inode == 1 || inode == 2 {
		root, err := afs.fileSystem.RootFileEntry()
		if err != nil {
			return nil, err
		}
		entry, err := NewMountFileEntry(afs.fileSystem, "/", root)
		if err != nil {
			return nil, err
		}
		afs.inodeCache[inode] = entry
		return entry, nil
	}

	return nil, fmt.Errorf("inode %d not found in cache", inode)
}

func (afs *APFSFileSystem) fillAttr(entry *MountFileEntry, attr *fuse.Attr) error {
	// Get file mode
	fileMode, err := entry.FileMode()
	if err != nil {
		return err
	}
	attr.Mode = uint32(fileMode)

	// Get size
	size, err := entry.Size()
	if err != nil {
		return err
	}
	attr.Size = size

	// Get inode
	inode, err := entry.Identifier()
	if err != nil {
		return err
	}
	attr.Ino = inode

	// Get owner and group
	uid, err := entry.OwnerIdentifier()
	if err == nil {
		attr.Uid = uid
	}
	gid, err := entry.GroupIdentifier()
	if err == nil {
		attr.Gid = gid
	}

	// Get number of links
	nlink, err := entry.NumberOfHardLinks()
	if err == nil {
		attr.Nlink = nlink
	}

	// Get timestamps (convert from nanoseconds to seconds)
	if atime, err := entry.AccessTime(); err == nil {
		atimeVal := time.Unix(0, atime)
		attr.SetTimes(&atimeVal, &atimeVal, &atimeVal)
	}
	if mtime, err := entry.ModificationTime(); err == nil {
		attr.Mtime = uint64(mtime / 1e9)
		attr.Mtimensec = uint32(mtime % 1e9)
	}
	if ctime, err := entry.InodeChangeTime(); err == nil {
		attr.Ctime = uint64(ctime / 1e9)
		attr.Ctimensec = uint32(ctime % 1e9)
	}

	return nil
}

// APFSFileHandle represents an open file
type APFSFileHandle struct {
	fileEntry *apfs.FileEntry
	handle    uint64
}

var _ fs.FileReader = (*APFSFileHandle)(nil)

// Read implements fs.FileReader
func (fh *APFSFileHandle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	// Seek to offset
	_, err := fh.fileEntry.Seek(off, 0)
	if err != nil {
		return nil, syscall.EIO
	}

	// Read data
	n, err := fh.fileEntry.Read(dest)
	if err != nil {
		return nil, syscall.EIO
	}

	return fuse.ReadResultData(dest[:n]), 0
}

// MountAPFS mounts an APFS volume using FUSE
func MountAPFS(mountHandle *MountHandle, volumeIndex int, mountPoint string, debug bool) (MountServer, error) {
	// Create the APFS filesystem
	root, err := NewAPFSFileSystem(mountHandle, volumeIndex)
	if err != nil {
		return nil, fmt.Errorf("unable to create APFS filesystem: %w", err)
	}

	// Mount options
	opts := &fs.Options{
		MountOptions: fuse.MountOptions{
			Name:          "apfs",
			FsName:        "apfs",
			Debug:         debug,
			DisableXAttrs: false,
			AllowOther:    false,
		},
	}

	// Mount the filesystem
	server, err := fs.Mount(mountPoint, root, opts)
	if err != nil {
		return nil, fmt.Errorf("unable to mount: %w", err)
	}

	return server, nil
}

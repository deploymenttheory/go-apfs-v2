// Package hostmeta reads the file metadata the Go standard library does not
// expose: extended attributes, hard-link identity and BSD flags.
//
// The writers need these to report what a directory-to-volume write cannot
// carry across. Every function degrades to "nothing here" on a platform that
// has no such concept, so callers need no build tags of their own.
package hostmeta

import "os"

// Attribute names that mean something more specific than "an extended
// attribute" and are worth reporting separately.
const (
	// ResourceForkName holds a file's resource fork — content, not metadata.
	ResourceForkName = "com.apple.ResourceFork"
	// DecmpfsName marks a transparently compressed file. Its content lives in
	// the resource fork or in the attribute itself.
	DecmpfsName = "com.apple.decmpfs"
	// SecurityName is where macOS keeps a file's ACL.
	SecurityName = "com.apple.system.Security"
	// PosixACLAccessName is the Linux equivalent.
	PosixACLAccessName = "system.posix_acl_access"
)

// IsACLName reports whether an attribute name holds an access control list.
func IsACLName(name string) bool {
	return name == SecurityName || name == PosixACLAccessName
}

// LinkIdentity identifies the inode behind a directory entry, so two names for
// one file can be recognized as such. ok is false on platforms that do not
// expose it, in which case hard links are indistinguishable from copies.
type LinkIdentity struct {
	Device uint64
	Inode  uint64
	Links  uint64 // st_nlink; greater than 1 means the file has several names
}

// IsSpecial reports whether mode describes something the writers cannot model:
// a device node, FIFO or socket. os.ModeIrregular covers whatever else a
// platform may report that is neither a regular file, a directory nor a
// symbolic link.
func IsSpecial(mode os.FileMode) bool {
	return mode&(os.ModeDevice|os.ModeNamedPipe|os.ModeSocket|os.ModeIrregular) != 0
}

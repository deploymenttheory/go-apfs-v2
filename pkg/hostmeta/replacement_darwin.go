package hostmeta

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// CLONE_ACL from the macOS SDK's sys/clonefile.h. x/sys exposes Fclonefileat
// through libSystem but does not export this option.
const cloneACL = 0x0004

func prepareReplacement(source *os.File, path string, info os.FileInfo) (*os.File, error) {
	flags, _ := Flags(info)
	if flags&(unix.UF_IMMUTABLE|unix.UF_APPEND|unix.SF_IMMUTABLE|unix.SF_APPEND|UFCompressed) != 0 {
		return nil, fmt.Errorf("%w: protected or compressed source", ErrUnsupportedReplacement)
	}
	// clonefile also applies inherited destination ACLs. The directory is ours:
	// clear its ACL before cloning so the source ACL is reproduced exactly.
	// This is kauth_filesec with KAUTH_FILESEC_NOACL (sys/kauth.h), preceded by
	// an attrreference_t (sys/attr.h). Setattrlist is a libSystem wrapper.
	acl := make([]byte, 52)
	binary.LittleEndian.PutUint32(acl, 8)
	binary.LittleEndian.PutUint32(acl[4:], 44)
	binary.LittleEndian.PutUint32(acl[8:], 0x012cc16d)
	binary.LittleEndian.PutUint32(acl[44:], 0xffffffff)
	list := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
	if err := unix.Setattrlist(filepath.Dir(path), &list, acl, unix.FSOPT_NOFOLLOW); err != nil {
		return nil, err
	}
	if err := unix.Fclonefileat(int(source.Fd()), unix.AT_FDCWD, path, cloneACL); err != nil {
		return nil, err
	}
	// A read-only source must produce a writable staging file; restore its mode
	// only after writing. The caller's private directory prevents access to it.
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_RDWR, 0)
}

func restoreReplacementMetadata(_ *os.File, target *os.File, info os.FileInfo) error {
	s := info.Sys().(*syscall.Stat_t)
	if err := target.Chown(int(s.Uid), int(s.Gid)); err != nil {
		return err
	}
	if err := target.Chmod(info.Mode()); err != nil {
		return err
	}
	return unix.Fchflags(int(target.Fd()), int(s.Flags))
}

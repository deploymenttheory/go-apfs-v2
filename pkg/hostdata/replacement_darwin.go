package hostdata

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	hostflags "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/bsdflags"
	"golang.org/x/sys/unix"
)

func prepareReplacement(source *os.File, path string, info os.FileInfo) (*os.File, error) {
	flags, _ := hostflags.Flags(info)
	if flags&(unix.UF_IMMUTABLE|unix.UF_APPEND|unix.SF_IMMUTABLE|unix.SF_APPEND|UFCompressed) != 0 {
		return nil, fmt.Errorf("%w: protected or compressed source", ErrUnsupportedReplacement)
	}
	// clonefile also applies inherited destination ACLs. The directory is ours:
	// clear its ACL before cloning. Source ACLs are restored after content writes,
	// so deny-write entries cannot prevent opening the private copy for writing.
	// This is kauth_filesec with KAUTH_FILESEC_NOACL (sys/kauth.h), preceded by
	// an attrreference_t (sys/attr.h). Setattrlist is a libSystem wrapper.
	if err := clearReplacementACL(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := unix.Fclonefileat(int(source.Fd()), unix.AT_FDCWD, path, 0); err != nil {
		return nil, err
	}
	// A read-only source must produce a writable staging file; restore its mode
	// only after writing. The caller's private directory prevents access to it.
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_RDWR, 0)
}

func clearReplacementACL(path string) error {
	acl := make([]byte, 52)
	binary.LittleEndian.PutUint32(acl, 8)
	binary.LittleEndian.PutUint32(acl[4:], 44)
	binary.LittleEndian.PutUint32(acl[8:], 0x012cc16d)
	binary.LittleEndian.PutUint32(acl[44:], 0xffffffff)
	list := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
	return unix.Setattrlist(path, &list, acl, unix.FSOPT_NOFOLLOW)
}

func restoreReplacementMetadata(source *os.File, target *os.File, info os.FileInfo) error {
	s := info.Sys().(*syscall.Stat_t)
	if err := target.Chown(int(s.Uid), int(s.Gid)); err != nil {
		return err
	}
	if err := target.Chmod(info.Mode()); err != nil {
		return err
	}
	if err := restoreReplacementACL(source, target); err != nil {
		return err
	}
	return unix.Fchflags(int(target.Fd()), int(s.Flags))
}

func restoreReplacementACL(source, target *os.File) error {
	from, err := NewHeldMetadata(source)
	if err != nil {
		return err
	}
	security, err := from.CaptureACL()
	if err != nil {
		return err
	}
	to, err := NewHeldMetadata(target)
	if err != nil {
		return err
	}
	return to.SetACL(security.Security.ACL)
}

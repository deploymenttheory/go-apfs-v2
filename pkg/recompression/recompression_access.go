package recompression

import (
	"encoding/binary"
	"errors"
	"maps"
	"slices"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

// ErrAuthority means a required foreign identity observation was
// not supplied. Missing observations are not implicit permission grants or denials.
var ErrAuthority = errors.New("uncaptured recompression authority")

// Membership records a source UUID membership query. Failed means
// a real source lookup failed; absent/zero is different and means uncaptured.
type Membership uint8

const (
	NotMember Membership = iota + 1
	Member
	MembershipFailed
)

// Authority supplies the foreign effective identity for regular-file
// discretionary access checks. Groups includes every applicable numeric group;
// it must be captured or explicitly selected, never inferred from the Go host.
// UserUUIDFailed records a failed source UID-to-UUID lookup. A nil UserUUID with
// UserUUIDFailed=false is uncaptured. Membership retains actual UUID lookup results.
// This does not transport sandbox entitlements, authorize host storage access, or
// emulate process-specific permission overrides. Those require separate evidence.
type Authority struct {
	UID            uint32
	Groups         []uint32
	UserUUID       *[16]byte
	UserUUIDFailed bool
	Membership     map[[16]byte]Membership
}

type recompressionAccess struct {
	authority Authority
	acl       []appledouble.ACLEntry
	volume    uint32
	profile   osversion.MacOSProfile
}

func newRecompressionAccess(record metatransport.Record, security *appledouble.FileSecurity, authority *Authority, volume uint32) (*recompressionAccess, error) {
	if authority == nil || record.Darwin.UID == nil || record.Darwin.GID == nil || authority.UserUUID != nil && authority.UserUUIDFailed {
		return nil, ErrAuthority
	}
	for _, membership := range authority.Membership {
		if membership < NotMember || membership > MembershipFailed {
			return nil, ErrAuthority
		}
	}
	result := &recompressionAccess{authority: *authority, volume: volume}
	result.authority.Groups = slices.Clone(authority.Groups)
	result.authority.Membership = maps.Clone(authority.Membership)
	if authority.UserUUID != nil {
		value := *authority.UserUUID
		result.authority.UserUUID = &value
	}
	if security != nil {
		if len(security.Trailing) != 0 {
			return nil, appledouble.ErrFileSecurity
		}
		if _, err := security.MarshalBinary(); err != nil {
			return nil, err
		}
		if security.ACL != nil {
			result.acl = slices.Clone(security.ACL.Entries)
		}
	}
	return result, nil
}

// Numeric rights and ordered ACL evaluation follow XNU xnu-11417.140.69:
// bsd/kern/kern_authorization.c kauth_acl_evaluate; bsd/vfs/vfs_subr.c
// vnode_authorize_simple, vnode_authorize_posix and vnode_authattr. Native
// operation corpora independently qualify the actual recompression call sites.
const (
	recompressionReadData        uint32 = 1 << 1
	recompressionWriteData       uint32 = 1 << 2
	recompressionWriteAttributes uint32 = 1 << 8
	recompressionReadXattr       uint32 = 1 << 9
	recompressionWriteXattr      uint32 = 1 << 10
	recompressionWriteSecurity   uint32 = 1 << 12
)

func (a *recompressionAccess) authorize(operation string, stat hostdata.StatCopySource) error {
	var rights uint32
	switch operation {
	case "open-data":
		rights = recompressionReadData | recompressionWriteData
	case "open-fork":
		switch a.profile {
		case osversion.MacOS15:
			rights = recompressionWriteXattr
		case osversion.MacOS26, osversion.MacOS27:
			rights = recompressionReadXattr | recompressionWriteXattr
		default:
			return osversion.ErrMacOSProfile
		}
		// O_CREAT first authorizes creation of the named fork against base data.
		if err := a.rights(recompressionWriteData, stat, false); err != nil {
			return err
		}
	case "attribute":
		rights = recompressionWriteXattr
	case "truncate":
		// A held writable descriptor carries data-write authorization.
		// ftruncate does not reauthorize a later ACL or mode change.
		if a.volume&1 != 0 {
			return syscall.EROFS
		}
		if stat.Flags&0x00040004 != 0 {
			return syscall.EPERM
		}
		return nil
	case "chmod", "flags":
		rights = recompressionWriteSecurity
	case "times":
		if a.authority.UID != 0 && a.authority.UID != stat.UID {
			return syscall.EPERM
		}
		rights = recompressionWriteAttributes
	default:
		return metatransport.ErrInvalid
	}
	err := a.rights(rights, stat, operation == "flags")
	// Explicit futimes and chmod translate authorization EACCES to EPERM.
	if (operation == "times" || operation == "chmod" || operation == "flags") && errors.Is(err, syscall.EACCES) {
		return syscall.EPERM
	}
	return err
}

// chmod additionally checks requested set-ID bits; authorization alone cannot
// infer those bits from the old mode. An unchanged mode requires no ACL check.
func (a *recompressionAccess) chmod(stat hostdata.StatCopySource, mode uint16) error {
	if stat.Mode&07777 == uint32(mode)&07777 {
		return nil
	}
	if a.authority.UID != 0 {
		if mode&02000 != 0 && !slices.Contains(a.authority.Groups, stat.GID) {
			return syscall.EPERM
		}
		if mode&04000 != 0 && a.authority.UID != stat.UID {
			return syscall.EPERM
		}
	}
	return a.authorize("chmod", stat)
}

func (a *recompressionAccess) rights(requested uint32, stat hostdata.StatCopySource, flagsOnly bool) error {
	if a.volume&1 != 0 {
		return syscall.EROFS
	}
	if requested&recompressionWriteXattr != 0 && a.volume&0x01000000 != 0 {
		return syscall.EACCES
	}
	// Activation only changes UF_COMPRESSED. Flag-only updates bypass user flags;
	// system immutable/append flags remain outside this operation's admitted state.
	mask := uint32(0x00020002)
	if requested&^recompressionWriteXattr != 0 {
		mask |= 0x00040004
	}
	if flagsOnly {
		mask = 0x00060000
	}
	if stat.Flags&mask != 0 {
		return syscall.EPERM
	}
	if a.authority.UID == 0 {
		return nil
	}
	owner := a.authority.UID == stat.UID
	if owner {
		requested &^= recompressionWriteSecurity
	}
	if requested == 0 {
		return nil
	}
	residual := requested
	for _, entry := range a.acl {
		kind := entry.Flags & 15
		if entry.Flags&256 != 0 || kind != 1 && kind != 2 {
			continue
		}
		rights := recompressionExpandRights(entry.Rights)
		relevant := residual
		if kind == 2 {
			relevant = requested
		}
		if relevant&rights == 0 {
			continue
		}
		applies, err := a.applies(entry.Principal, kind == 2, stat)
		if err != nil {
			return err
		}
		if !applies {
			continue
		}
		if kind == 2 {
			return syscall.EACCES
		}
		residual &^= rights
		if residual == 0 {
			return nil
		}
	}
	if owner {
		residual &^= recompressionWriteAttributes
	}
	if residual&recompressionWriteSecurity != 0 {
		return syscall.EACCES
	}
	var needed uint32
	if residual&(recompressionReadData|recompressionReadXattr) != 0 {
		needed |= 4
	}
	if residual&(recompressionWriteData|recompressionWriteAttributes|recompressionWriteXattr) != 0 {
		needed |= 2
	}
	bits := stat.Mode & 7
	if owner {
		bits = stat.Mode >> 6 & 7
	} else if slices.Contains(a.authority.Groups, stat.GID) {
		bits = stat.Mode >> 3 & 7
	}
	if bits&needed != needed {
		return syscall.EACCES
	}
	return nil
}

func recompressionExpandRights(rights uint32) uint32 {
	const read = recompressionReadData | 1<<7 | recompressionReadXattr | 1<<11
	const write = recompressionWriteData | 1<<5 | 1<<4 | 1<<6 | recompressionWriteAttributes | recompressionWriteXattr | recompressionWriteSecurity
	if rights&(1<<21) != 0 {
		rights |= read | write | 1<<3
	}
	if rights&(1<<22) != 0 {
		rights |= 1 << 3
	}
	if rights&(1<<23) != 0 {
		rights |= write
	}
	if rights&(1<<24) != 0 {
		rights |= read
	}
	return rights
}

func (a *recompressionAccess) applies(principal [16]byte, deny bool, stat hostdata.StatCopySource) (bool, error) {
	prefix := [12]byte{0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef}
	if [12]byte(principal[:12]) == prefix {
		switch binary.BigEndian.Uint32(principal[12:]) {
		case 12:
			return true, nil
		case 0xfffffffe:
			return false, nil
		case 10:
			return a.authority.UID == stat.UID, nil
		case 16:
			if a.authority.UserUUIDFailed {
				return deny, nil
			}
			if a.authority.UserUUID == nil {
				return false, ErrAuthority
			}
			return slices.Contains(a.authority.Groups, stat.GID), nil
		}
	}
	if a.authority.UserUUIDFailed {
		return deny, nil
	}
	if a.authority.UserUUID == nil {
		return false, ErrAuthority
	}
	if principal == *a.authority.UserUUID {
		return true, nil
	}
	switch a.authority.Membership[principal] {
	case NotMember:
		return false, nil
	case Member:
		return true, nil
	case MembershipFailed:
		return deny, nil
	default:
		return false, ErrAuthority
	}
}

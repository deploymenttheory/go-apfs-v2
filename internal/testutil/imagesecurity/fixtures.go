// Package imagesecurity supplies deterministic native and cross-platform image
// capture fixtures. It is test support, not a production metadata adapter.
package imagesecurity

import (
	"encoding/binary"
	"io/fs"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/securitycopy"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
)

type Profile struct {
	Name        string
	Data        []byte
	Disposition hostmeta.SecurityRecordDisposition
}

func Profiles() []Profile {
	record := func(count int, flags uint32) []byte {
		s := appledouble.FileSecurity{OwnerUUID: [16]byte{0x11}, GroupUUID: [16]byte{0x22}, ACL: &appledouble.ACL{Flags: flags}}
		for i := 0; i < count; i++ {
			s.ACL.Entries = append(s.ACL.Entries, appledouble.ACLEntry{Principal: [16]byte{0x11, 0x23, byte(i + 1)}, Flags: 1, Rights: 1})
		}
		b, e := s.MarshalBinary()
		if e != nil {
			panic(e)
		}
		return b
	}
	edit := func(b []byte, at int, value uint32) []byte {
		b = append([]byte{}, b...)
		binary.BigEndian.PutUint32(b[at:], value)
		return b
	}
	noacl := edit(record(0, 0), 36, 0xffffffff)
	return []Profile{
		{"absent", nil, hostmeta.SecurityRecordAbsent}, {"empty", []byte{}, hostmeta.SecurityRecordInvalid}, {"short", []byte{1}, hostmeta.SecurityRecordInvalid}, {"short-header", make([]byte, 43), hostmeta.SecurityRecordInvalid},
		{"noacl", noacl, hostmeta.SecurityRecordEmpty}, {"empty-acl", record(0, 0), hostmeta.SecurityRecordEmpty}, {"empty-flags", record(0, 1<<17), hostmeta.SecurityRecordEmpty},
		{"one", record(1, 0), hostmeta.SecurityRecordACL}, {"flags", record(1, 1<<17), hostmeta.SecurityRecordACL}, {"unknown", edit(edit(record(1, 0x80000000), 60, 0x8000000f), 64, 0xffffffff), hostmeta.SecurityRecordACL},
		{"two", record(2, 0), hostmeta.SecurityRecordACL}, {"entries127", record(127, 0), hostmeta.SecurityRecordACL}, {"entries128", record(128, 0), hostmeta.SecurityRecordACL},
		{"bad-magic", edit(record(1, 0), 0, 0xdeadbeef), hostmeta.SecurityRecordInvalid}, {"truncated", record(1, 0)[:50], hostmeta.SecurityRecordInvalid}, {"partial-extra", append(record(1, 0), 1), hostmeta.SecurityRecordInvalid},
		{"aligned-extra", append(record(1, 0), make([]byte, 24)...), hostmeta.SecurityRecordACL}, {"padded-empty", append(record(0, 0), make([]byte, 24)...), hostmeta.SecurityRecordEmpty}, {"padded-noacl", append(append([]byte{}, noacl...), make([]byte, 24)...), hostmeta.SecurityRecordEmpty},
		{"count-overflow", edit(record(1, 0), 36, 129), hostmeta.SecurityRecordInvalid}, {"count-short", edit(record(1, 0), 36, 2), hostmeta.SecurityRecordInvalid},
		{"max-padding", edit(record(128, 0), 36, 1), hostmeta.SecurityRecordACL}, {"too-large", append(record(128, 0), make([]byte, 24)...), hostmeta.SecurityRecordInvalid}, {"streamed-invalid", append(record(128, 0), make([]byte, 32000)...), hostmeta.SecurityRecordInvalid},
	}
}

type Case struct {
	Name, Profile, Kind string
	UID, GID            uint32
	Mode                uint16
	Disposition         hostmeta.SecurityRecordDisposition
}
type Observation struct {
	Code, Errno, ReferenceCode, ReferenceErrno int
	Properties, ReferenceProperties            securitycopy.Properties
	UID, GID, Mode, Flags                      uint32
	Inode                                      uint64
	SameIdentity                               bool
}
type NativeCase struct {
	Filesystem string
	Case       Case
	Native     Observation
}
type Fixture struct {
	HFSSources                                                                                      map[string]string
	Revision, Host, HelperSHA256, ParentSHA256, CopyfileSHA256, ChmodSHA256, StatxSHA256, XNUSHA256 string
	ActorUID, ActorGID                                                                              uint32
	Cases                                                                                           []NativeCase
	Images                                                                                          map[string]string
}

func Tree(uid, gid uint32) (*apfswrite.Entry, []Case) {
	root := &apfswrite.Entry{Mode: os.ModeDir | 0755, UID: uid, GID: gid, Xattrs: map[string][]byte{hostmeta.SecurityName: Profiles()[7].Data}}
	cases := []Case{{Name: ".", Profile: "one", Kind: "directory", UID: uid, GID: gid, Mode: 040755, Disposition: hostmeta.SecurityRecordACL}}
	var linkGroup uint64 = 1
	for _, p := range Profiles() {
		for _, identity := range []struct {
			name     string
			uid, gid uint32
		}{{"actor", uid, gid}, {"zero", 0, 0}, {"foreign", 42, 43}} {
			for _, kind := range []string{"file", "directory", "symlink", "hard-a", "hard-b"} {
				name := p.Name + "-" + identity.name + "-" + kind
				mode := os.FileMode(0644)
				rawMode := uint16(0100644)
				data := []byte("payload")
				var group uint64
				switch kind {
				case "directory":
					mode = os.ModeDir | 0755
					rawMode = 040755
					data = nil
				case "symlink":
					mode = os.ModeSymlink | 0755
					rawMode = 0120755
					data = []byte(p.Name + "-" + identity.name + "-file")
				case "hard-a", "hard-b":
					group = linkGroup
				}
				e := &apfswrite.Entry{Name: name, Mode: mode, UID: identity.uid, GID: identity.gid, Data: data, LinkGroup: group, Xattrs: map[string][]byte{"user.unrelated": []byte("retained")}}
				if p.Data != nil {
					e.Xattrs[hostmeta.SecurityName] = p.Data
				}
				root.Children = append(root.Children, e)
				cases = append(cases, Case{Name: name, Profile: p.Name, Kind: kind, UID: identity.uid, GID: identity.gid, Mode: rawMode, Disposition: p.Disposition})
			}
			linkGroup++
		}
	}
	return root, cases
}
func HFSTree(s *apfswrite.Entry) *hfsplus.Entry {
	d := &hfsplus.Entry{Name: s.Name, Mode: s.Mode, UID: s.UID, GID: s.GID, Data: s.Data, LinkGroup: s.LinkGroup, Xattrs: s.Xattrs}
	for _, c := range s.Children {
		d.Children = append(d.Children, HFSTree(c))
	}
	return d
}

type Volume interface {
	fs.FS
	Security(string) (hostmeta.ImageSecurity, error)
	Xattrs(string) (map[string][]byte, error)
	Readlink(string) (string, error)
}

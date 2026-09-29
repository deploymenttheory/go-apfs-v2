package imageacl

import (
	"bytes"
	"errors"
	"io/fs"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
)

func copyTo(root, target *entry, source hostmeta.SecurityCopySource, options hostmeta.SecurityCopyOptions) (hostmeta.SecurityCopyResult, error) {
	return Copy(root, target, source, options, func(e *entry, _ bool) (Node[*entry], error) { return e.node, e.fail }, func(e *entry, c Change) {
		e.node.UID, e.node.GID, e.node.Mode, e.node.Xattrs = c.UID, c.GID, c.Mode, c.Xattrs
	})
}
func TestImageSecurityCopyValidation(t *testing.T) {
	source := hostmeta.SecurityCopySource{Properties: hostmeta.DarwinChmodProperties{RemoveACL: true}}
	if r, e := copyTo(nil, nil, source, hostmeta.SecurityCopyOptions{}); e != nil || !r.Completed || r.Writes != 0 {
		t.Fatal(r, e)
	}
	options := hostmeta.SecurityCopyOptions{ACL: true}
	if _, e := copyTo(nil, nil, source, options); !errors.Is(e, appledouble.ErrFileSecurity) {
		t.Fatal(e)
	}
	source.Properties = hostmeta.DarwinChmodProperties{RawSecurity: &appledouble.FileSecurity{Trailing: []byte{1}}}
	if _, e := copyTo(nil, nil, source, options); !errors.Is(e, appledouble.ErrFileSecurity) {
		t.Fatal(e)
	}
	source = hostmeta.SecurityCopySource{}
	if _, e := copyTo(nil, nil, source, options); !errors.Is(e, fs.ErrInvalid) {
		t.Fatal(e)
	}
	inherited := &appledouble.ACL{Entries: []appledouble.ACLEntry{{Flags: 17, Rights: 1}}}
	raw, _ := (&appledouble.FileSecurity{ACL: inherited}).MarshalBinary()
	target := &entry{node: Node[*entry]{Mode: 0100644, Xattrs: map[string][]byte{hostmeta.SecurityName: raw}}}
	source.Properties.RawSecurity = &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: make([]appledouble.ACLEntry, 128)}}
	for i := range source.Properties.RawSecurity.ACL.Entries {
		source.Properties.RawSecurity.ACL.Entries[i].Flags = 1
	}
	before := bytes.Clone(raw)
	if r, e := copyTo(target, target, source, options); !errors.Is(e, appledouble.ErrACLCopy) || r.Completed || !bytes.Equal(before, target.node.Xattrs[hostmeta.SecurityName]) {
		t.Fatal(r, e)
	}
}
func TestImageSecurityCopyAliasesAndOwnership(t *testing.T) {
	uid, gid, mode := uint32(44), uint32(45), uint32(0106711)
	raw, _ := (&appledouble.FileSecurity{OwnerUUID: [16]byte{1}, GroupUUID: [16]byte{2}, ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Flags: 17, Rights: 2}}}}).MarshalBinary()
	a := &entry{node: Node[*entry]{Mode: 0100644, UID: 42, GID: 43, LinkGroup: 2, Xattrs: map[string][]byte{hostmeta.SecurityName: raw, "a": {1}}}}
	b := &entry{node: a.node}
	b.node.Xattrs = map[string][]byte{hostmeta.SecurityName: bytes.Clone(raw), "b": {2}}
	root := &entry{node: Node[*entry]{Mode: 040755, Children: []*entry{a, b}}}
	source := hostmeta.SecurityCopySource{UID: 99, GID: 98, Mode: 0106000, Properties: hostmeta.DarwinChmodProperties{UID: &uid, GID: &gid, Mode: &mode, OwnerUUID: &[16]byte{9}, RawSecurity: &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Flags: 1, Rights: 1}}}}}}
	original, _ := source.Properties.RawSecurity.MarshalBinary()
	oldMap := a.node.Xattrs
	r, e := copyTo(root, b, source, hostmeta.SecurityCopyOptions{ACL: true, Stat: true, SourceNoSetID: true})
	if e != nil || !r.Completed || r.Fallback || r.Writes != 1 || len(r.Failures) != 0 {
		t.Fatal(r, e)
	}
	for _, v := range []*entry{a, b} {
		if v.node.UID != 44 || v.node.GID != 45 || v.node.Mode != 0100711 {
			t.Fatal(v.node)
		}
		s, e := appledouble.ParseFileSecurity(v.node.Xattrs[hostmeta.SecurityName])
		if e != nil || s.OwnerUUID[0] != 1 || s.GroupUUID[0] != 2 || len(s.ACL.Entries) != 2 || s.ACL.Entries[0].Rights != 1 || s.ACL.Entries[1].Flags != 17 {
			t.Fatal(s, e)
		}
	}
	if !bytes.Equal(oldMap[hostmeta.SecurityName], raw) || a.node.Xattrs["a"][0] != 1 || b.node.Xattrs["b"][0] != 2 {
		t.Fatal("old or unrelated maps changed")
	}
	a.node.Xattrs[hostmeta.SecurityName][0] ^= 1
	if a.node.Xattrs[hostmeta.SecurityName][0] == b.node.Xattrs[hostmeta.SecurityName][0] {
		t.Fatal("shared output")
	}
	r.Source.Properties.RawSecurity.ACL.Entries[0].Rights = 7
	*r.Source.Properties.UID = 88
	after, _ := source.Properties.RawSecurity.MarshalBinary()
	if !bytes.Equal(after, original) || uid != 44 || mode != 0106711 {
		t.Fatal("source changed")
	}
}
func TestImageSecurityCopyStorageAndSelection(t *testing.T) {
	for _, withUUID := range []bool{false, true} {
		for _, record := range []string{"missing", "nil", "invalid", "noacl", "empty"} {
			t.Run(record+map[bool]string{true: "-uuid", false: "-zero"}[withUUID], func(t *testing.T) {
				attrs := map[string][]byte{"keep": {1}}
				switch record {
				case "nil":
					attrs[hostmeta.SecurityName] = nil
				case "invalid":
					attrs[hostmeta.SecurityName] = []byte{1}
				case "noacl", "empty":
					s := &appledouble.FileSecurity{}
					if withUUID {
						s.OwnerUUID[0] = 7
					}
					if record == "empty" {
						s.ACL = &appledouble.ACL{}
					}
					attrs[hostmeta.SecurityName], _ = s.MarshalBinary()
				}
				target := &entry{node: Node[*entry]{Mode: 0106755, UID: 42, GID: 43, Xattrs: attrs}}
				original := bytes.Clone(attrs[hostmeta.SecurityName])
				mode := uint32(0)
				source := hostmeta.SecurityCopySource{UID: 9, GID: 8, Mode: 0, Properties: hostmeta.DarwinChmodProperties{Mode: &mode}}
				// Null security preserves original storage. Stat-only never changes IDs.
				if r, e := copyTo(target, target, source, hostmeta.SecurityCopyOptions{Stat: true}); e != nil || !r.Completed || target.node.Mode != 0100000 || target.node.UID != 42 || !bytes.Equal(original, target.node.Xattrs[hostmeta.SecurityName]) {
					t.Fatal(r, e, target.node)
				}
				source.Properties.OwnerUUID = &[16]byte{9}
				if r, e := copyTo(target, target, source, hostmeta.SecurityCopyOptions{ACL: true}); e != nil || !r.Completed {
					t.Fatal(r, e)
				}
				value, present := target.node.Xattrs[hostmeta.SecurityName]
				if withUUID && (record == "noacl" || record == "empty") {
					s, e := appledouble.ParseFileSecurity(value)
					if e != nil || s.OwnerUUID[0] != 7 || s.NoACLFlags != [4]byte{} || s.ACL != nil {
						t.Fatal(s, e)
					}
				} else if present {
					t.Fatal("NOACL zero UUID must remove storage", value)
				}
				if !bytes.Equal(original, attrs[hostmeta.SecurityName]) || target.node.Xattrs["keep"][0] != 1 {
					t.Fatal("input mutated")
				}
			})
		}
	}
	target := &entry{node: Node[*entry]{Mode: 0100644}}
	if _, e := copyTo(target, target, hostmeta.SecurityCopySource{Properties: hostmeta.DarwinChmodProperties{RawSecurity: &appledouble.FileSecurity{ACL: &appledouble.ACL{}}}}, hostmeta.SecurityCopyOptions{ACL: true}); e != nil || len(target.node.Xattrs[hostmeta.SecurityName]) != 44 {
		t.Fatal(e)
	}
}
func TestImageSecurityCopyBackend(t *testing.T) {
	c := &copier{Change: Change{UID: 1, GID: 2, Mode: 0106644}}
	if e := c.WriteSecurity(hostmeta.DarwinChmodArguments{UID: 0xffffff9b, GID: 0xffffff9b, Mode: -1}); e != nil || c.ModeSelected || c.UID != 1 || c.GID != 2 {
		t.Fatal(c, e)
	}
	if e := c.WriteSecurity(hostmeta.DarwinChmodArguments{UID: 1, GID: 2, Mode: -1}); e != nil || c.Mode != 0100644 || !c.ModeSelected {
		t.Fatal("ownership must clear set-ID", c, e)
	}
	if e := c.WriteSecurity(hostmeta.DarwinChmodArguments{SecurityArgument: hostmeta.DarwinSecurityRecord, Security: []byte{1}}); !errors.Is(e, appledouble.ErrFileSecurity) {
		t.Fatal(e)
	}
	if e := c.SetACL(&appledouble.ACL{Entries: make([]appledouble.ACLEntry, 129)}); !errors.Is(e, appledouble.ErrFileSecurity) || c.securitySelected {
		t.Fatal(e)
	}
	if e := c.WriteSecurity(hostmeta.DarwinChmodArguments{UID: 3, GID: 4, Mode: 0, SecurityArgument: hostmeta.DarwinSecurityRemove}); e != nil || c.UID != 3 || c.GID != 4 || c.Mode != 0100000 || !c.securitySelected {
		t.Fatal(e, c)
	}
	if e := c.Chown(0xffffffff, 0xffffffff); e != nil || c.UID != 3 || c.GID != 4 {
		t.Fatal(c, e)
	}
	if e := c.Chown(5, 6); e != nil || c.UID != 5 || c.GID != 6 {
		t.Fatal(c, e)
	}
}
func FuzzImageSecurityCopy(f *testing.F) {
	f.Add([]byte{}, uint16(06755), true, true)
	raw, _ := (&appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Flags: 17, Rights: 1}}}}).MarshalBinary()
	f.Add(raw, uint16(0), true, false)
	f.Fuzz(func(t *testing.T, raw []byte, mode uint16, acl, stat bool) {
		original := bytes.Clone(raw)
		target := &entry{node: Node[*entry]{Mode: 0100644, Xattrs: map[string][]byte{hostmeta.SecurityName: raw}}}
		source := hostmeta.DecodeImageSecurity(42, 43, mode, raw).Source
		r, e := copyTo(target, target, source, hostmeta.SecurityCopyOptions{ACL: acl, Stat: stat, DestinationNoSetID: true})
		if !bytes.Equal(original, raw) {
			t.Fatal("input changed")
		}
		if e != nil {
			if !reflect.DeepEqual(target.node.Xattrs[hostmeta.SecurityName], raw) {
				t.Fatal("failed selection changed storage")
			}
			return
		}
		if !r.Completed || r.Fallback || len(r.Failures) != 0 || r.Writes > 1 {
			t.Fatal(r)
		}
		if target.node.Mode&0170000 != 0100000 {
			t.Fatal("type changed")
		}
	})
}

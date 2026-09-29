package apfswrite

import (
	"errors"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
	"io/fs"
	"os"
	"testing"
)

func TestImageSecurityCopyWriter(t *testing.T) {
	var absent *Entry
	if r, e := absent.CopySecurity(nil, hostmeta.SecurityCopySource{}, hostmeta.SecurityCopyOptions{}); e != nil || !r.Completed || r.Writes != 0 {
		t.Fatal(r, e)
	}
	source := hostmeta.SecurityCopySource{Mode: 0, Properties: hostmeta.DarwinChmodProperties{RawSecurity: &appledouble.FileSecurity{ACL: &appledouble.ACL{}}}}
	options := hostmeta.SecurityCopyOptions{ACL: true, Stat: true}
	for _, root := range []*Entry{{Mode: os.ModeSymlink}, {Mode: os.ModeDevice}, {Mode: os.ModeDir, Children: []*Entry{nil}}, {Mode: os.ModeDir, Children: []*Entry{{Mode: 0644, Children: []*Entry{{}}}}}} {
		if _, e := root.CopySecurity(root, source, options); !errors.Is(e, fs.ErrInvalid) {
			t.Fatal(e)
		}
	}
	a := &Entry{Name: "a", Mode: os.ModeSetuid | os.ModeSetgid | os.ModeSticky | 0644, ModeExplicit: true, UID: 42, GID: 43, LinkGroup: 1, Data: []byte("payload")}
	b := *a
	b.Name = "b"
	root := &Entry{Children: []*Entry{a, {Name: "nested", Mode: os.ModeDir, Children: []*Entry{&b}}}}
	if _, e := root.CopySecurity(&b, source, hostmeta.SecurityCopyOptions{ACL: true}); e != nil {
		t.Fatal(e)
	}
	if a.Mode != b.Mode || a.Mode.Perm() != 0644 || a.Mode&os.ModeSetuid == 0 {
		t.Fatal("ACL-only changed mode")
	}
	if _, e := root.CopySecurity(a, source, hostmeta.SecurityCopyOptions{Stat: true}); e != nil {
		t.Fatal(e)
	}
	for _, entry := range []*Entry{a, &b} {
		if entry.Mode != 0 || !entry.ModeExplicit || entry.UID != 42 || entry.GID != 43 || string(entry.Data) != "payload" {
			t.Fatal(entry)
		}
	}
	// A mode update to an implicit root must retain its directory type and 0000.
	if _, e := root.CopySecurity(root, source, hostmeta.SecurityCopyOptions{Stat: true}); e != nil || root.Mode != os.ModeDir || !root.ModeExplicit {
		t.Fatal(e, root.Mode)
	}
	// A deferred replacement remains later than an ordinary merged copy.
	update := appledouble.ACLUpdate{ACL: &appledouble.ACL{Flags: 1 << 17}}
	if _, e := root.RestoreACL(a, update); e != nil {
		t.Fatal(e)
	}
	sec, e := appledouble.ParseFileSecurity(a.Xattrs[hostmeta.SecurityName])
	if e != nil || sec.ACL.Flags != 1<<17 {
		t.Fatal(sec, e)
	}
}

func TestImageSecurityCopyInferredDirectory(t *testing.T) {
	child := &Entry{Name: "child", Data: []byte("kept")}
	directory := &Entry{Name: "implicit", Children: []*Entry{child}, LinkGroup: 7}
	file := &Entry{Name: "file", Mode: 0644, LinkGroup: 7, Data: []byte("other")}
	root := &Entry{Children: []*Entry{directory, file}}
	if _, err := root.CopySecurity(directory, hostmeta.SecurityCopySource{Mode: 0}, hostmeta.SecurityCopyOptions{Stat: true}); err != nil {
		t.Fatal(err)
	}
	if directory.Mode != os.ModeDir || !directory.ModeExplicit || file.Mode != 0644 || directory.Children[0] != child || string(child.Data) != "kept" {
		t.Fatal("inferred directory lost type or collided with file alias")
	}
}

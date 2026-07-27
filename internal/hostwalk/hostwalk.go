// Package hostwalk walks a host directory tree into a file-system writer's
// entry tree, recording everything it cannot carry across.
//
// pkg/apfswrite and pkg/hfsplus want the same walk and differ only in the entry
// type they build, so the walk lives here once and each writer supplies a
// constructor. Before this existed the two packages carried byte-identical
// copies, which is how one of them came to skip special files while the other
// did not.
package hostwalk

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/hostmeta"
	"github.com/deploymenttheory/go-apfs-v2/pkg/fidelity"
)

// Options tunes a walk.
type Options struct {
	// Xattrs reads each entry's extended attributes so they can be counted,
	// and carried when Keep accepts them. It costs a syscall or two per entry,
	// so it is opt-in; without it the report says nothing about attributes
	// rather than saying there were none.
	Xattrs bool

	// Keep decides whether an attribute can be written. One it rejects is
	// reported as dropped, exactly as every attribute was before any could be
	// carried. A nil Keep drops all of them.
	Keep func(name string, value []byte) bool

	// HardLinks says the writer can represent several names for one file. When
	// it cannot, a second name is reported as collapsed into a copy, which is
	// what the volume will actually contain.
	HardLinks bool

	// Warn, when non-nil, is called once for each thing the walk cannot carry
	// across, as it is found.
	Warn func(path string, kind fidelity.Kind, detail string)
}

// Node is one directory entry, in the platform-neutral form a writer needs to
// build its own entry type. Data holds a regular file's contents or a symbolic
// link's target; it is nil for a directory.
type Node struct {
	Name     string
	Mode     os.FileMode
	ModTime  time.Time
	UID, GID uint32
	Data     []byte
	// Xattrs are the attributes Options.Keep accepted. The rest are counted in
	// the report instead.
	Xattrs map[string][]byte
	// LinkGroup is non-zero when this entry shares an inode with others in the
	// walk, and identical across every name for that inode. It is only set
	// when Options.HardLinks says the writer can use it.
	LinkGroup uint64
}

// Walk reads the tree rooted at dir and returns the entry mk builds for it,
// along with an account of what could not be represented. dir's own name is
// dropped: its contents become the returned root's children, so the root Node
// carries no name or mode.
//
// The returned report is never nil, even on error.
func Walk[E any](dir string, opts *Options, mk func(Node, []E) E) (E, *fidelity.Report, error) {
	if opts == nil {
		opts = &Options{}
	}
	w := &walker[E]{
		opts:       opts,
		report:     &fidelity.Report{},
		inodes:     map[hostmeta.LinkIdentity]string{},
		linkGroups: map[hostmeta.LinkIdentity]uint64{},
		mk:         mk,
	}

	children, err := w.readDir(dir, ".")
	if err != nil {
		var zero E
		return zero, w.report, err
	}
	return mk(Node{}, children), w.report, nil
}

// walker carries the state one walk needs: where to report, and which inodes
// have already been seen, so a second name for one can be recognized as a hard
// link rather than mistaken for another file.
type walker[E any] struct {
	opts   *Options
	report *fidelity.Report
	inodes map[hostmeta.LinkIdentity]string
	mk     func(Node, []E) E

	// Grouping keys handed to a writer that can represent hard links, one per
	// inode. Numbered from one so zero can mean "not linked".
	linkGroups    map[hostmeta.LinkIdentity]uint64
	nextLinkGroup uint64
}

func (w *walker[E]) warn(rel string, kind fidelity.Kind, detail string) {
	w.report.Add(kind, rel)
	if w.opts.Warn != nil {
		w.opts.Warn(rel, kind, detail)
	}
}

// readDir reads one directory level, recursing into subdirectories. rel is the
// path relative to the walk root, used for reporting; it uses forward slashes
// on every platform because it names a location inside the image, not on the
// host.
func (w *walker[E]) readDir(dir, rel string) ([]E, error) {
	names, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var out []E
	for _, name := range names {
		full := filepath.Join(dir, name.Name())
		childRel := name.Name()
		if rel != "." {
			childRel = path.Join(rel, name.Name())
		}

		info, err := os.Lstat(full)
		if err != nil {
			return nil, err
		}

		// Anything that is not a regular file, a directory or a symbolic link
		// is skipped rather than read. Reading one does not merely produce a
		// wrong entry, it breaks the run: opening a FIFO blocks until a writer
		// appears, a character device such as /dev/zero reads until memory runs
		// out, and a socket fails outright.
		if hostmeta.IsSpecial(info.Mode()) {
			w.warn(childRel, fidelity.SpecialFile, describeSpecial(info.Mode()))
			continue
		}

		node := Node{Name: name.Name(), Mode: info.Mode(), ModTime: info.ModTime()}
		if st, ok := info.Sys().(interface {
			Uid() uint32
			Gid() uint32
		}); ok {
			node.UID, node.GID = st.Uid(), st.Gid()
		}

		node.Xattrs = w.collectXattrs(full, childRel)
		node.LinkGroup = w.noteLinks(childRel, info)
		w.noteBSDFlags(childRel, info)

		var children []E
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(full)
			if err != nil {
				return nil, err
			}
			node.Data = []byte(target)
		case info.IsDir():
			if children, err = w.readDir(full, childRel); err != nil {
				return nil, err
			}
		default:
			if node.Data, err = os.ReadFile(full); err != nil {
				return nil, err
			}
		}
		out = append(out, w.mk(node, children))
	}
	return out, nil
}

// describeSpecial names a special file in words, because a reader tracking down
// what was skipped is better served by "named pipe" than by "p---------".
func describeSpecial(mode os.FileMode) string {
	switch {
	case mode&os.ModeNamedPipe != 0:
		return "named pipe (FIFO)"
	case mode&os.ModeSocket != 0:
		return "socket"
	case mode&os.ModeCharDevice != 0:
		return "character device"
	case mode&os.ModeDevice != 0:
		return "block device"
	default:
		return "irregular file (" + mode.Type().String() + ")"
	}
}

// collectXattrs reads the entry's extended attributes, returning those the
// writer can keep and reporting the rest as dropped. Resource forks and ACLs
// are reported under their own kinds: losing file content is a different
// statement to losing metadata.
func (w *walker[E]) collectXattrs(full, rel string) map[string][]byte {
	if !w.opts.Xattrs {
		return nil
	}
	attrs, err := hostmeta.ListXattrs(full)
	if err != nil || len(attrs) == 0 {
		return nil
	}

	var kept map[string][]byte
	for name, value := range attrs {
		if w.opts.Keep != nil && w.opts.Keep(name, value) {
			if kept == nil {
				kept = make(map[string][]byte, len(attrs))
			}
			kept[name] = value
			continue
		}
		switch {
		case name == hostmeta.ResourceForkName:
			w.warn(rel, fidelity.ResourceFork, name)
		case hostmeta.IsACLName(name):
			w.warn(rel, fidelity.ACL, name)
		default:
			w.warn(rel, fidelity.Xattr, name)
		}
	}
	return kept
}

// noteBSDFlags records BSD flags, which no writer here carries.
func (w *walker[E]) noteBSDFlags(rel string, info os.FileInfo) {
	if flags, ok := hostmeta.Flags(info); ok && flags != 0 {
		w.warn(rel, fidelity.BSDFlags, fmt.Sprintf("st_flags=%#x", flags))
	}
}

// noteLinks handles a file with several names. When the writer can represent
// them it returns a grouping key shared by every name for that inode; when it
// cannot, it reports the second and later names as collapsed into copies,
// which is what the volume will actually hold.
//
// Directories legitimately carry a link count above one — every subdirectory's
// ".." counts — so only files are considered.
func (w *walker[E]) noteLinks(rel string, info os.FileInfo) uint64 {
	if !info.Mode().IsRegular() {
		return 0
	}
	id, ok := hostmeta.Link(info)
	if !ok || id.Links <= 1 {
		return 0
	}

	first, seen := w.inodes[id]
	if !seen {
		w.inodes[id] = rel
	}

	if w.opts.HardLinks {
		// Any stable non-zero value will do, and the inode number is both
		// stable and already unique within a device.
		if group, ok := w.linkGroups[id]; ok {
			return group
		}
		w.nextLinkGroup++
		w.linkGroups[id] = w.nextLinkGroup
		return w.nextLinkGroup
	}

	if seen {
		w.warn(rel, fidelity.HardLink, "also linked as "+first)
	}
	return 0
}

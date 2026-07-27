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
	// Xattrs reads each entry's extended attributes so they can be counted.
	// It costs a syscall or two per entry, so it is opt-in; without it the
	// report says nothing about attributes rather than saying there were none.
	Xattrs bool

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
	w := &walker[E]{opts: opts, report: &fidelity.Report{}, inodes: map[hostmeta.LinkIdentity]string{}, mk: mk}

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

		w.noteMetadataLoss(full, childRel, info)

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

// noteMetadataLoss records the metadata that will not survive this entry:
// extended attributes, resource forks, ACLs, BSD flags, and second-or-later
// names for an inode already seen.
func (w *walker[E]) noteMetadataLoss(full, rel string, info os.FileInfo) {
	if w.opts.Xattrs {
		if attrs, err := hostmeta.ListXattrs(full); err == nil {
			for name := range attrs {
				switch {
				case name == hostmeta.ResourceForkName:
					w.warn(rel, fidelity.ResourceFork, name)
				case hostmeta.IsACLName(name):
					w.warn(rel, fidelity.ACL, name)
				default:
					w.warn(rel, fidelity.Xattr, name)
				}
			}
		}
	}

	if flags, ok := hostmeta.Flags(info); ok && flags != 0 {
		w.warn(rel, fidelity.BSDFlags, fmt.Sprintf("st_flags=%#x", flags))
	}

	// Directories legitimately carry a link count above one — every
	// subdirectory's ".." counts — so only files can be hard links here.
	if info.Mode().IsRegular() {
		if id, ok := hostmeta.Link(info); ok && id.Links > 1 {
			if first, seen := w.inodes[id]; seen {
				w.warn(rel, fidelity.HardLink, "also linked as "+first)
			} else {
				w.inodes[id] = rel
			}
		}
	}
}

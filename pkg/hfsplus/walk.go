package hfsplus

import (
	"github.com/deploymenttheory/go-apfs-v2/internal/hostwalk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/fidelity"
)

// WalkOptions tunes EntryTreeFromDir.
type WalkOptions struct {
	// Xattrs reads each entry's extended attributes so they can be counted.
	// It costs a syscall or two per entry, so it is opt-in; without it the
	// report says nothing about attributes rather than saying there were none.
	Xattrs bool

	// Warn, when non-nil, is called once for each thing the walk cannot carry
	// across, as it is found. The library never writes to stderr itself —
	// deciding whether a warning is worth showing, and how many, belongs to the
	// caller.
	Warn func(path string, kind fidelity.Kind, detail string)
}

// EntryTreeFromDir walks srcDir into an Entry tree and reports everything it
// could not represent. srcDir's own name is dropped; its contents become the
// returned root's children.
//
// The returned Report is never nil. A caller wanting only the tree can ignore
// it, but it is returned rather than hidden because a lossy conversion that
// does not say so is the failure mode this exists to prevent.
//
// This writer produces no attributes file, so every extended attribute is
// dropped — including any resource fork — and it has no hard links, so a second
// name for one file becomes an independent copy.
func EntryTreeFromDir(srcDir string, opts *WalkOptions) (*Entry, *fidelity.Report, error) {
	var o hostwalk.Options
	if opts != nil {
		o = hostwalk.Options{Xattrs: opts.Xattrs, Warn: opts.Warn}
	}

	root, report, err := hostwalk.Walk(srcDir, &o, newEntry)
	if err != nil {
		return nil, report, err
	}
	return root, report, nil
}

// newEntry builds one HFS+ Entry from the walker's platform-neutral node.
func newEntry(n hostwalk.Node, children []*Entry) *Entry {
	return &Entry{
		Name:     n.Name,
		Mode:     n.Mode,
		ModTime:  n.ModTime,
		UID:      n.UID,
		GID:      n.GID,
		Data:     n.Data,
		Children: children,
	}
}

package hfsplus

import (
	"github.com/deploymenttheory/go-apfs-v2/internal/hostmeta"
	"github.com/deploymenttheory/go-apfs-v2/internal/hostwalk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/fidelity"
)

// WalkOptions tunes EntryTreeFromDir.
type WalkOptions struct {
	// Xattrs reads each entry's extended attributes so they can be counted,
	// and carried when this writer can represent them. It costs a syscall or
	// two per entry, so it is opt-in; without it the report says nothing about
	// attributes rather than saying there were none.
	//
	// A resource fork reaches the walk as an extended attribute even though
	// HFS+ stores it as a fork, so carrying one needs this set.
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
// Resource forks are carried, in the catalog record's resource fork where HFS+
// keeps them. Ordinary extended attributes are still dropped: this writer emits
// no attributes file. Several names for one file become independent copies.
func EntryTreeFromDir(srcDir string, opts *WalkOptions) (*Entry, *fidelity.Report, error) {
	var o hostwalk.Options
	if opts != nil {
		o = hostwalk.Options{Xattrs: opts.Xattrs, Warn: opts.Warn, Keep: CanWriteXattr}
	}

	root, report, err := hostwalk.Walk(srcDir, &o, newEntry)
	if err != nil {
		return nil, report, err
	}
	return root, report, nil
}

// CanWriteXattr reports whether this writer can carry an extended attribute.
//
// It exists so a caller walking a source tree can tell in advance what will
// survive, rather than discovering it afterwards. It must agree exactly with
// what the writer does: an attribute accepted here and then silently discarded
// would make the fidelity report claim a loss did not happen.
func CanWriteXattr(name string, value []byte) bool {
	// A resource fork is not an attributes-file record on HFS+ -- it is a fork
	// of the catalog record -- so it is carried, while ordinary attributes,
	// which would need the attributes file this writer does not emit, are not.
	return name == hostmeta.ResourceForkName
}

// newEntry builds one HFS+ Entry from the walker's platform-neutral node.
func newEntry(n hostwalk.Node, children []*Entry) *Entry {
	return &Entry{
		Name:         n.Name,
		Mode:         n.Mode,
		ModTime:      n.ModTime,
		UID:          n.UID,
		GID:          n.GID,
		Data:         n.Data,
		ResourceFork: n.Xattrs[hostmeta.ResourceForkName],
		Children:     children,
	}
}

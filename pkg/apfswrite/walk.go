// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import (
	"strings"

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
// Extended attributes are carried, whatever their size: small values live
// inside their record and larger ones, along with any resource fork, get a data
// stream of their own. com.apple.decmpfs is the exception — it declares content
// this writer does not produce — and is reported as dropped. Several names for
// one file are written as hard links rather than as copies.
func EntryTreeFromDir(srcDir string, opts *WalkOptions) (*Entry, *fidelity.Report, error) {
	var o hostwalk.Options
	if opts != nil {
		o = hostwalk.Options{Xattrs: opts.Xattrs, Warn: opts.Warn, Keep: CanWriteXattr, HardLinks: true}
	}

	root, report, err := hostwalk.Walk(srcDir, &o, newEntry)
	if err != nil {
		return nil, report, err
	}
	return root, report, nil
}

// newEntry builds one APFS Entry from the walker's platform-neutral node.
func newEntry(n hostwalk.Node, children []*Entry) *Entry {
	return &Entry{
		Name:      n.Name,
		Mode:      n.Mode,
		ModTime:   n.ModTime,
		UID:       n.UID,
		GID:       n.GID,
		Data:      n.Data,
		Xattrs:    n.Xattrs,
		LinkGroup: n.LinkGroup,
		Children:  children,
	}
}

// CanWriteXattr reports whether this writer can carry an extended attribute.
//
// It exists so a caller walking a source tree can tell in advance what will
// survive, rather than discovering it when CreateContainer refuses the whole
// image. Size is no longer a limit: a value too large to embed gets a stream.
// See validateXattrs for why a compression header still cannot be written.
func CanWriteXattr(name string, value []byte) bool {
	switch name {
	case symlinkName, decmpfsName:
		return false
	}
	return name != "" && !strings.ContainsRune(name, 0)
}

// Package fidelity describes what a directory-to-volume write cannot carry
// across.
//
// Building a volume from a directory tree is lossy: the writers model regular
// files, directories and symbolic links, and a source tree routinely holds more
// than that. Silently dropping the rest is the worst outcome for a repackaging
// tool, because the damage surfaces later and somewhere else. Both
// pkg/apfswrite and pkg/hfsplus report through this package, and the apfs
// command renders it, so the vocabulary is identical everywhere.
//
// It lives under pkg/ for the same reason pkg/exitcode does: a consumer of the
// writer libraries has to be able to name the type it is handed.
package fidelity

import "sort"

// Kind is one category of thing a write could not carry across.
type Kind int

const (
	// SpecialFile is a device node, FIFO or socket. These are skipped: the
	// writers cannot represent them, and reading one would hang or exhaust
	// memory rather than fail cleanly.
	SpecialFile Kind = iota
	// Xattr is an extended attribute other than a resource fork or an ACL.
	Xattr
	// ResourceFork is a com.apple.ResourceFork attribute. Counted separately
	// from Xattr because losing one is materially different: it is file
	// content, not metadata.
	ResourceFork
	// ACL is an access control list, which arrives as an extended attribute.
	// Counted separately because "ACLs were dropped" is a different statement
	// to a forensic reader than "3 attributes were dropped".
	ACL
	// HardLink is a second or later name for one inode, written as an
	// independent copy rather than as a link.
	HardLink
	// BSDFlags are st_flags — uchg, hidden and friends.
	BSDFlags
	// VolumeIdentity is a volume's role or volume-group membership, lost when
	// rebuilding a volume rather than a directory. Volume-to-volume writes only.
	VolumeIdentity
)

// kindInfo carries a kind's stable JSON key and the phrasing the command line
// uses when summarizing.
type kindInfo struct {
	key  string
	noun string // singular, for "N <noun>(s) ..."
	note string // the summary line, given a count
}

var kinds = map[Kind]kindInfo{
	SpecialFile:    {"specialFilesSkipped", "special file", "skipped: device nodes, FIFOs and sockets cannot be represented"},
	Xattr:          {"xattrsDropped", "extended attribute", "dropped: extended attributes are not written"},
	ResourceFork:   {"resourceForksDropped", "resource fork", "dropped: resource forks are not written"},
	ACL:            {"aclsDropped", "access control list", "dropped: ACLs are not written"},
	HardLink:       {"hardLinksCollapsed", "hard link", "written as separate copies rather than links"},
	BSDFlags:       {"bsdFlagsDropped", "entry with BSD flags", "dropped: BSD flags (uchg, hidden, …) are not written"},
	VolumeIdentity: {"volumeIdentityDropped", "volume identity field", "dropped: role and volume-group membership are not carried"},
}

// allKinds is every kind in declaration order, so output ordering is stable.
var allKinds = []Kind{SpecialFile, Xattr, ResourceFork, ACL, HardLink, BSDFlags, VolumeIdentity}

// String returns the kind's singular noun.
func (k Kind) String() string {
	if info, ok := kinds[k]; ok {
		return info.noun
	}
	return "unknown"
}

// Key returns the kind's stable JSON key.
func (k Kind) Key() string {
	if info, ok := kinds[k]; ok {
		return info.key
	}
	return "unknown"
}

// Note returns the kind's summary phrasing, without a count.
func (k Kind) Note() string {
	if info, ok := kinds[k]; ok {
		return info.note
	}
	return "dropped"
}

// ExampleLimit is how many paths a Report retains per kind. A tree with an
// extended attribute on every file would otherwise produce one warning per
// file, which buries the summary it is meant to support.
const ExampleLimit = 10

// Report accumulates what a walk could not represent. The zero value is a
// lossless walk, and a nil *Report is usable: Add is a no-op on it, so callers
// that do not want a report need no special case.
type Report struct {
	counts   map[Kind]int
	examples map[Kind][]string
}

// Add records one occurrence of kind k at path.
func (r *Report) Add(k Kind, path string) {
	if r == nil {
		return
	}
	if r.counts == nil {
		r.counts = make(map[Kind]int)
		r.examples = make(map[Kind][]string)
	}
	r.counts[k]++
	if len(r.examples[k]) < ExampleLimit {
		r.examples[k] = append(r.examples[k], path)
	}
}

// Count returns how many occurrences of kind k were recorded.
func (r *Report) Count(k Kind) int {
	if r == nil {
		return 0
	}
	return r.counts[k]
}

// Examples returns up to ExampleLimit paths recorded for kind k, in the order
// they were seen.
func (r *Report) Examples(k Kind) []string {
	if r == nil {
		return nil
	}
	return r.examples[k]
}

// Total returns the number of occurrences across every kind.
func (r *Report) Total() int {
	if r == nil {
		return 0
	}
	total := 0
	for _, n := range r.counts {
		total += n
	}
	return total
}

// Lossless reports whether the walk carried everything across.
func (r *Report) Lossless() bool { return r.Total() == 0 }

// Kinds returns the kinds that occurred at least once, in a stable order.
func (r *Report) Kinds() []Kind {
	if r == nil {
		return nil
	}
	var out []Kind
	for _, k := range allKinds {
		if r.counts[k] > 0 {
			out = append(out, k)
		}
	}
	return out
}

// EntriesSkipped returns the number of source entries omitted from the volume
// altogether, as opposed to entries written with some metadata missing. The
// distinction drives the exit code: a missing file is a different kind of
// problem to a missing extended attribute.
func (r *Report) EntriesSkipped() int { return r.Count(SpecialFile) }

// JSON returns the report as stable camelCase keys suitable for embedding in a
// command's JSON output. Every kind is present, so a consumer can rely on the
// shape rather than testing for absence.
func (r *Report) JSON() map[string]any {
	out := make(map[string]any, len(allKinds)+1)
	for _, k := range allKinds {
		out[k.Key()] = r.Count(k)
	}
	out["lossless"] = r.Lossless()
	return out
}

// Keys returns every JSON key JSON() emits, sorted. Useful for tests and for
// documenting the schema.
func Keys() []string {
	keys := make([]string, 0, len(allKinds)+1)
	for _, k := range allKinds {
		keys = append(keys, k.Key())
	}
	keys = append(keys, "lossless")
	sort.Strings(keys)
	return keys
}

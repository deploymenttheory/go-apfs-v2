// Package imageacl applies deferred ACL updates to in-memory image trees.
package imageacl

import (
	"bytes"
	"fmt"
	"io/fs"
	"maps"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
)

// Node is the metadata needed to bind a writer entry and its hard-link aliases.
// Read must report the writer's resolved mode, including its root/default rules.
type Node[T comparable] struct {
	Children  []T
	UID, GID  uint32
	Mode      uint16
	LinkGroup uint64
	Xattrs    map[string][]byte
}

// Restore binds a target by object identity rather than following a host path.
// Read-only validation precedes every edit. The caller excludes concurrent tree
// mutation; write must only assign the supplied map and cannot fail. Matching
// regular-file LinkGroups are updated together. Conflicting security metadata
// across aliases is an error rather than an order-dependent successful write.
func Restore[T comparable](root, target T, update appledouble.ACLUpdate, read func(T, bool) (Node[T], error), write func(T, map[string][]byte)) (hostmeta.ACLRestoreResult, error) {
	if update.ACL == nil || update.Invalid {
		return hostmeta.RestoreACL(update, nil)
	}
	if _, err := update.FileSecurity(&appledouble.FileSecurity{}); err != nil {
		return hostmeta.ACLRestoreResult{}, err
	}
	var zero T
	if root == zero || target == zero {
		return hostmeta.ACLRestoreResult{}, fs.ErrInvalid
	}
	nodes := map[T]Node[T]{}
	stack := []T{root}
	for len(stack) > 0 {
		entry := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, exists := nodes[entry]; entry == zero || exists {
			return hostmeta.ACLRestoreResult{}, fmt.Errorf("image ACL: nil, repeated or cyclic entry: %w", fs.ErrInvalid)
		}
		node, err := read(entry, entry == root)
		if err != nil {
			return hostmeta.ACLRestoreResult{}, err
		}
		nodes[entry] = node
		stack = append(stack, node.Children...)
	}
	destination, found := nodes[target]
	if !found {
		return hostmeta.ACLRestoreResult{}, fs.ErrNotExist
	}
	aliases := []T{target}
	if destination.LinkGroup != 0 && destination.Mode&0170000 == 0100000 {
		for entry, node := range nodes {
			if entry == target || node.Mode&0170000 != 0100000 || node.LinkGroup != destination.LinkGroup {
				continue
			}
			a, ap := destination.Xattrs[hostmeta.SecurityName]
			b, bp := node.Xattrs[hostmeta.SecurityName]
			if node.UID != destination.UID || node.GID != destination.GID || node.Mode != destination.Mode || ap != bp || !bytes.Equal(a, b) {
				return hostmeta.ACLRestoreResult{}, fmt.Errorf("image ACL: conflicting hard-link security: %w", fs.ErrInvalid)
			}
			aliases = append(aliases, entry)
		}
	}
	backend := &restorer{uid: destination.UID, gid: destination.GID, mode: destination.Mode}
	if raw, present := destination.Xattrs[hostmeta.SecurityName]; present {
		backend.raw = []byte{} // Present nil/oversized values are invalid, not absent.
		if hostmeta.SecurityRecordSizeValid(uint64(len(raw))) {
			backend.raw = bytes.Clone(raw)
		}
	}
	result, err := hostmeta.RestoreACL(update, backend)
	if err != nil || !result.Applied {
		return result, err
	}
	// Allocate every changed map before publishing any update; unrelated values
	// and payloads retain their original storage. Each alias owns its new ACL.
	prepared := make([]map[string][]byte, len(aliases))
	for i, entry := range aliases {
		attrs := maps.Clone(nodes[entry].Xattrs)
		if attrs == nil {
			attrs = map[string][]byte{}
		}
		attrs[hostmeta.SecurityName] = bytes.Clone(backend.output)
		prepared[i] = attrs
	}
	for i, entry := range aliases {
		write(entry, prepared[i])
	}
	return result, nil
}

type restorer struct {
	uid, gid    uint32
	mode        uint16
	raw, output []byte
}

func (r *restorer) CaptureACL() (hostmeta.ACLMetadata, error) {
	view := hostmeta.DecodeImageSecurity(r.uid, r.gid, r.mode, r.raw)
	security := view.Source.Properties.RawSecurity
	if security == nil {
		security = &appledouble.FileSecurity{}
	}
	return hostmeta.ACLMetadata{UID: r.uid, GID: r.gid, Mode: uint32(r.mode), Security: security}, nil
}

func (r *restorer) WriteACL(m hostmeta.ACLMetadata) error {
	// Extended chmod selects an ACL, not new UUID ownership. Retain the stored
	// UUIDs even when Libc's zero-entry statx view omitted them during capture.
	security := &appledouble.FileSecurity{ACL: m.Security.ACL}
	if hostmeta.SecurityRecordSizeValid(uint64(len(r.raw))) {
		if stored, err := appledouble.ParseFileSecurity(r.raw); err == nil {
			security.OwnerUUID, security.GroupUUID = stored.OwnerUUID, stored.GroupUUID
		}
	}
	var err error
	r.output, err = security.MarshalBinary()
	return err
}

// This backend has no cached source security or unsupported-operation fallback.
func (*restorer) ClearSourceSecurity() error { return nil }

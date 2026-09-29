package hfsplus

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/internal/bsdflags"
)

func (b *builder) prepareBSDFlags() error {
	for _, n := range b.allNodes {
		// Stubs retain their fixed legacy representation.
		if n.isLink {
			continue
		}
		flags, err := bsdflags.Select(n.entry.BSDFlags, compressedFlag(n) != 0, true)
		if err != nil {
			return fmt.Errorf("hfsplus: %s: %w", n.name, err)
		}
		n.bsdFlags = flags
	}
	return nil
}

// HFS stores document IDs in the host-order opaque Finder extension on modern Macs.
func setDocumentID(info *FinderOpaqueInfo, id uint32) {
	for i := 0; i < 4; i++ {
		info.Opaque[i] = int8(id >> (8 * i))
	}
}

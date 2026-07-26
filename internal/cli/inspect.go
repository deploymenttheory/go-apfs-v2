// apfs inspect IMAGE [SECTION] — low-level structural inspection.
package cli

import (
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var (
	inspectFSTreeRoot uint64
	inspectOmapRoot   uint64
)

var inspectCmd = &cobra.Command{
	Use:   "inspect IMAGE [block N | fstree]",
	Short: "Low-level structural inspection of a container",
	Long: `Walk the on-disk structures of an APFS container for debugging and
forensics. Text output only.

Modes:
  inspect IMAGE            structural walk: superblock, checkpoints, object
                           maps, volumes (the default)
  inspect IMAGE block N    decode one block by physical address (N accepts
                           decimal or 0x hex)
  inspect IMAGE fstree     interactively explore the file-system tree
                           (tree roots are resolved automatically)

Examples:
  apfs inspect image.dmg
  apfs inspect image.dmg block 0
  apfs inspect image.dmg block 0x1b0c1
  apfs inspect image.dmg fstree`,
	Args: rangeArgs(1, 3, "IMAGE [block N | fstree]"),
	RunE: runInspect,
}

func init() {
	inspectCmd.Flags().Uint64Var(&inspectFSTreeRoot, "fstree-root", 0,
		"fstree mode: override the physical address of the file-system tree root")
	inspectCmd.Flags().Uint64Var(&inspectOmapRoot, "omap-root", 0,
		"fstree mode: override the physical address of the object map tree root")
}

func runInspect(cmd *cobra.Command, args []string) error {
	imagePath := args[0]

	if opts.Output == "json" {
		return usageErrorf("inspect produces text output only")
	}

	if len(args) == 1 {
		volumeIndex := -1
		if opts.Volume != "" {
			index, err := strconv.Atoi(opts.Volume)
			if err != nil {
				return usageErrorf("inspect selects volumes by index: %v", err)
			}
			volumeIndex = index
		}
		return runInspectWalk(imagePath, volumeIndex, opts.Verbose)
	}

	switch args[1] {
	case "block":
		if len(args) != 3 {
			return usageErrorf("expected: inspect IMAGE block N")
		}
		blockAddr, err := strconv.ParseUint(strings.TrimPrefix(args[2], "0x"), addrBase(args[2]), 64)
		if err != nil {
			return usageErrorf("invalid block address %q: %v", args[2], err)
		}
		return runInspectBlock(imagePath, blockAddr, opts.Verbose)

	case "fstree":
		return runInspectFSTree(imagePath, inspectFSTreeRoot, inspectOmapRoot)

	default:
		return usageErrorf("unknown inspect mode %q (expected: block or fstree)", args[1])
	}
}

func addrBase(s string) int {
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		return 16
	}
	return 10
}

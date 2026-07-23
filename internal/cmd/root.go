// Package cmd provides the CLI commands for APFS tools
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const version = "0.1.0"

var (
	showVersion bool

	// Root command
	rootCmd = &cobra.Command{
		Use:   "apfs",
		Short: "APFS container tools",
		Long: `A comprehensive toolkit for working with Apple File System (APFS) containers.

Provides commands for:
  - Inspecting containers and volumes (info)
  - Detailed container inspection (inspect)
  - Reading and analyzing specific blocks (read)
  - Listing directory contents (list)
  - Writing file contents to stdout (cat)
  - Extracting files from volumes (extract)
  - Interactively exploring filesystem B-tree (explore-fs-tree)
  - Mounting APFS filesystems via FUSE (mount)`,
		Version:           version,
		SilenceUsage:      true,
		SilenceErrors:     true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion {
				fmt.Printf("apfs version %s\n", version)
				return nil
			}
			return cmd.Help()
		},
	}
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(&showVersion, "version", "V", false, "show version information")

	// Add subcommands
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(inspectCmd)
	rootCmd.AddCommand(readCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(catCmd)
	rootCmd.AddCommand(extractCmd)
	rootCmd.AddCommand(exploreFSTreeCmd)
	rootCmd.AddCommand(mountCmd)
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

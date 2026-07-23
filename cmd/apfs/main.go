// APFS Tools - Unified CLI for APFS container operations
package main

import (
	"fmt"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/internal/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

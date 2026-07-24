// APFS Tools - Unified CLI for APFS container operations
package main

import (
	"os"

	"github.com/deploymenttheory/go-apfs-v2/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}

//go:build ignore

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"os"
	"time"
)

func main() {
	dir := flag.String("dir", "", "exact downloaded native producer directory")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "native producer directory is required")
		os.Exit(1)
	}
	if err := captureprovenance.VerifyExecution(ctx, *dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

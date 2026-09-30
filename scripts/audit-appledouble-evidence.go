//go:build ignore

// Audit the complete portable qualification inventory against this checkout.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"
)

func main() {
	artifacts := flag.String("artifacts", "artifacts", "directory containing portable evidence")
	revision := flag.String("revision", "", "tested revision; defaults to git HEAD")
	goos := flag.String("goos", runtime.GOOS, "tested operating system")
	flag.Parse()
	status, err := exec.Command("git", "status", "--porcelain", "--untracked-files=normal").Output()
	if err != nil || len(status) != 0 {
		fmt.Fprintf(os.Stderr, "evidence audit requires a clean committed checkout: %s%v\n", status, err)
		os.Exit(1)
	}
	if *revision == "" {
		b, err := exec.Command("git", "rev-parse", "HEAD").Output()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		*revision = strings.TrimSpace(string(b))
	}
	// Keep the auditor independently covered; scripts themselves are qualification
	// glue, while all evidence-validation decisions live in the tested package.
	selfDir := filepath.Join(*artifacts, "evidence-audit")
	if err := os.MkdirAll(selfDir, 0755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	profile := filepath.Join(selfDir, "coverage.out")
	cmd := exec.Command("go", "test", "-count=1", "-json", "-covermode=atomic", "-coverprofile="+profile, "./internal/evidenceaudit")
	output, err := cmd.CombinedOutput()
	if writeErr := os.WriteFile(filepath.Join(selfDir, "tests.jsonl"), output, 0600); writeErr != nil {
		fmt.Fprintln(os.Stderr, writeErr)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n%v\n", output, err)
		os.Exit(1)
	}
	output, err = exec.Command("go", "tool", "cover", "-func="+profile).Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fields := strings.Fields(string(output))
	var coverage float64
	if len(fields) != 0 {
		coverage, err = strconv.ParseFloat(strings.TrimSuffix(fields[len(fields)-1], "%"), 64)
	}
	if err != nil || coverage <= 95 {
		fmt.Fprintln(os.Stderr, "evidence auditor coverage must exceed 95%")
		os.Exit(1)
	}
	for _, dir := range evidenceaudit.CoverageDirectories() {

		if err := evidenceaudit.Coverage(os.DirFS("."), os.DirFS(*artifacts), dir, *revision, *goos); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("Verified", dir)
	}
}

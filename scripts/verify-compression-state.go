//go:build ignore

// Replay complete native compression states and export portable writer outputs.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"
)

const artifact = "artifacts/compression-state-portable"

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	if e := os.MkdirAll(artifact, 0755); e != nil {
		return e
	}
	out, e := filepath.Abs(artifact)
	if e != nil {
		return e
	}
	names := []string{"TestCompressionStateImages", "TestCompressionStorageHeaderBoundaries", "TestCompressionStorageBindings", "TestFileEntryInactiveCompression", "TestCarrierInactiveCompression", "TestCarrierNativeInactiveCompressionValues", "TestProjectionInactiveCompression"}
	if runtime.GOOS == "darwin" {
		names = append(names, "TestCarrierNativeInactiveCompressionFiles")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	profile := filepath.Join(out, "coverage.out")
	cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-json", "-run=^("+strings.Join(names, "|")+")$", "-covermode=atomic", "-coverprofile="+profile, "-coverpkg=./pkg/apfs", "./pkg/apfs", "./internal/hostwalk", "./internal/tools", "./acceptance")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "APFS_COMPRESSION_STATE_OUTPUT="+out)
	log, e := os.Create(filepath.Join(out, "tests.jsonl"))
	if e != nil {
		return e
	}
	var transcript bytes.Buffer
	cmd.Stdout = io.MultiWriter(log, &transcript)
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if e = errors.Join(err, log.Close()); e != nil {
		return e
	}
	passed := map[string]bool{}
	leaves := 0
	scan := bufio.NewScanner(&transcript)
	scan.Buffer(make([]byte, 4096), 1<<20)
	for scan.Scan() {
		var event struct{ Action, Test string }
		if e = json.Unmarshal(scan.Bytes(), &event); e != nil {
			return e
		}
		if event.Action == "skip" {
			return fmt.Errorf("compression state test skipped: %s", event.Test)
		}
		if event.Action == "pass" && event.Test != "" {
			passed[event.Test] = true
			if strings.HasPrefix(event.Test, "TestCompressionStateImages/") && strings.Contains(event.Test, "/codec-") {
				leaves++
			}
		}
	}
	if e = scan.Err(); e != nil {
		return e
	}
	for _, name := range names {
		if !passed[name] {
			return fmt.Errorf("required test did not pass: %s", name)
		}
	}
	if leaves != 480 {
		return fmt.Errorf("complete state case inventory %d != 480", leaves)
	}
	b, e := os.ReadFile(profile)
	if e != nil {
		return e
	}
	covered, total := 0, 0
	blocks := map[string][2]int{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || !strings.Contains(fields[0], "/pkg/apfs/compression_storage.go:") {
			continue
		}
		n, e := strconv.Atoi(fields[1])
		if e != nil {
			return e
		}
		hits, e := strconv.Atoi(fields[2])
		if e != nil {
			return e
		}
		previous := blocks[fields[0]]
		if previous[0] != 0 && previous[0] != n {
			return fmt.Errorf("inconsistent coverage block %s", fields[0])
		}
		blocks[fields[0]] = [2]int{n, previous[1] + hits}
	}
	for _, block := range blocks {
		total += block[0]
		if block[1] > 0 {
			covered += block[0]
		}
	}
	if total == 0 || covered*100 <= total*95 {
		return fmt.Errorf("compression storage coverage must exceed 95%%: %d/%d", covered, total)
	}
	hashes, e := evidenceaudit.SourceHashes(os.DirFS("."), []string{"pkg/apfs/*.go", "pkg/apfswrite/*.go", "pkg/hfsplus/*.go", "internal/bsdflags/*.go", "internal/hostwalk/*.go", "internal/tools/*.go", "acceptance/compression_state_test.go", "scripts/*compression-state.go", "testdata/appledouble/native/compression-state.c", "testdata/appledouble/native/compression-state.json.gz", "testdata/appledouble/native/compression-state-*.dmg", "go.mod", "go.sum"})
	if e != nil {
		return e
	}
	revision, e := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	if e != nil {
		return e
	}
	report := map[string]any{"revision": strings.TrimSpace(string(revision)), "source_sha256": hashes, "go": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "state_cases": leaves, "passed_tests": len(passed), "covered": covered, "statements": total, "coverage_files": map[string][2]int{"pkg/apfs/compression_storage.go": {covered, total}}}
	b, e = json.MarshalIndent(report, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(out, "coverage.json"), b, 0644); e != nil {
		return e
	}
	if e = evidenceaudit.Coverage(os.DirFS("."), os.DirFS("artifacts"), "compression-state-portable", strings.TrimSpace(string(revision)), runtime.GOOS); e != nil {
		return e
	}
	fmt.Printf("480 complete native/image/carrier states; compression storage coverage %d/%d; every required test passed\n", covered, total)
	return nil
}

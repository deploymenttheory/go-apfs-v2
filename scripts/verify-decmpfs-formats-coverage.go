//go:build ignore

// Verify shared compression storage against retained native evidence.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"
)

func main() {
	if e := verify(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func verify() error {
	const dir = "artifacts/decmpfs-formats-coverage"
	if e := os.MkdirAll(dir, 0755); e != nil {
		return e
	}
	log, e := os.Create(filepath.Join(dir, "tests.jsonl"))
	if e != nil {
		return e
	}
	defer log.Close()
	var transcript bytes.Buffer
	profile := filepath.Join(dir, "coverage.out")
	cmd := exec.Command("go", "test", "-count=1", "-json", "-run", "^Test", "-covermode=atomic", "-coverprofile="+profile, "-coverpkg=./internal/decmpfs,./pkg/compression/lzbitmap", "./internal/decmpfs", "./pkg/compression/lzbitmap")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Stdout = io.MultiWriter(os.Stdout, log, &transcript)
	cmd.Stderr = io.MultiWriter(os.Stderr, log)
	if e := cmd.Run(); e != nil {
		return e
	}
	passed := 0
	required := map[string]bool{"TestLargeCompressionIndexBoundedRanges": true, "TestLargeCompressionIndexRejectsMalformedTables": true, "TestLargeCompressionNativeRanges": true, "TestDecoderInvalidLifecycle": true, "TestDecoderPropagatesHeaderAndBlockFailures": true, "TestDecoderLogicalEndAndPartialFailure": true, "TestDecoderLeafFailures": true}
	for _, line := range bytes.Split(transcript.Bytes(), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var event struct{ Action, Test string }
		if e := json.Unmarshal(line, &event); e != nil {
			return e
		}
		if event.Action == "skip" {
			return fmt.Errorf("compression test skipped: %s", event.Test)
		}
		if event.Action == "pass" && event.Test != "" {
			passed++
			delete(required, event.Test)
		}
	}
	if len(required) != 0 {
		return fmt.Errorf("missing large compression tests: %v", required)
	}
	b, e := os.ReadFile(profile)
	if e != nil {
		return e
	}
	covered, total := 0, 0
	coverageFiles := map[string][2]int{"internal/decmpfs/decmpfs.go": {}, "internal/decmpfs/storage.go": {}, "internal/decmpfs/block_index.go": {}, "pkg/compression/lzbitmap/lzbitmap.go": {}, "pkg/compression/lzbitmap/encode.go": {}}
	var decoderCounts [2]int
	blocks := map[string][2]int{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		file := strings.TrimPrefix(strings.SplitN(fields[0], ":", 2)[0], "github.com/deploymenttheory/go-apfs-v2/")
		_, tracked := coverageFiles[file]
		if !tracked && !strings.HasPrefix(file, "internal/decmpfs/") {
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
		blocks[fields[0]] = [2]int{n, previous[1] + hits}
	}
	for block, value := range blocks {
		file := strings.TrimPrefix(strings.SplitN(block, ":", 2)[0], "github.com/deploymenttheory/go-apfs-v2/")
		n, hits := value[0], value[1]
		if strings.HasPrefix(file, "internal/decmpfs/") {
			decoderCounts[1] += n
			if hits > 0 {
				decoderCounts[0] += n
			}
		}
		counts, tracked := coverageFiles[file]
		if !tracked {
			continue
		}
		total += n
		counts[1] += n
		if hits > 0 {
			covered += n
			counts[0] += n
		}
		coverageFiles[file] = counts
	}
	if decoderCounts[1] == 0 || decoderCounts[0]*100 <= decoderCounts[1]*95 {
		return fmt.Errorf("complete decmpfs package coverage must exceed 95%%: %d/%d", decoderCounts[0], decoderCounts[1])
	}
	for file, counts := range coverageFiles {
		if counts[1] == 0 || counts[0]*100 <= counts[1]*95 {
			return fmt.Errorf("%s coverage must exceed 95%%: %d/%d", file, counts[0], counts[1])
		}
	}
	if total == 0 || covered*100 <= total*95 {
		return fmt.Errorf("packing coverage must exceed 95%%: %d/%d", covered, total)
	}
	if passed < 30 {
		return fmt.Errorf("incomplete packing tests: %d", passed)
	}
	files := []string{"scripts/verify-decmpfs-formats.go", "scripts/verify-decmpfs-formats-coverage.go", "testdata/appledouble/native/decmpfs-formats.c", "testdata/appledouble/native/decmpfs-formats.json.gz", "pkg/compression/lzbitmap/testdata/aa-lzbitmap.aar", "pkg/compression/lzbitmap/testdata/aa-lzbitmap-raw.aar", "go.mod", "go.sum"}
	files = append(files, "internal/evidenceaudit/*.go", "internal/decmpfs/*.go", "pkg/compression/lzbitmap/*.go")
	files = append(files, "scripts/verify-large-compression*.go", "testdata/appledouble/native/decmpfs-large.c", "testdata/appledouble/native/decmpfs-expand.c", "testdata/appledouble/native/large-compression/*")
	hashes, e := evidenceaudit.SourceHashes(os.DirFS("."), files)
	if e != nil {
		return e
	}
	revision, e := exec.Command("git", "rev-parse", "HEAD").Output()
	if e != nil {
		return e
	}
	report := map[string]any{"coverage_files": coverageFiles, "covered": covered, "statements": total, "passed_tests": passed, "source_sha256": hashes, "revision": strings.TrimSpace(string(revision)), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "go": runtime.Version()}
	report["decoder_package_coverage"] = decoderCounts
	b, e = json.MarshalIndent(report, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "coverage.json"), append(b, '\n'), 0600); e != nil {
		return e
	}
	fmt.Printf("Compression storage: %d/%d covered statements; %d passing test records on %s/%s\n", covered, total, passed, runtime.GOOS, runtime.GOARCH)
	return nil
}

//go:build ignore

// Verify replacement fallback decisions, metadata transfer and failure cleanup.
package main

import (
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

func main() {
	if e := verify(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func verify() error {
	const dir = "artifacts/replacement-coverage"
	if e := os.MkdirAll(dir, 0755); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	fullLog, e := os.Create(filepath.Join(dir, "full-hostdata-tests.jsonl"))
	if e != nil {
		return e
	}
	fullProfile := filepath.Join(dir, "full-hostdata-coverage.out")
	full := exec.CommandContext(ctx, "go", "test", "-count=1", "-json", "-covermode=atomic", "-coverprofile="+fullProfile, "./pkg/hostdata")
	full.Env = append(os.Environ(), "CGO_ENABLED=0")
	full.Stdout = io.MultiWriter(os.Stdout, fullLog)
	full.Stderr = io.MultiWriter(os.Stderr, fullLog)
	if e = errors.Join(full.Run(), fullLog.Close()); e != nil {
		return e
	}
	packageCovered, packageTotal, e := completeHostdataCoverage(fullProfile)
	if e != nil {
		return e
	}
	if packageTotal == 0 || packageCovered*100 <= packageTotal*95 {
		return fmt.Errorf("complete hostdata coverage must exceed 95%%: %d/%d", packageCovered, packageTotal)
	}
	log, e := os.Create(filepath.Join(dir, "tests.jsonl"))
	if e != nil {
		return e
	}
	defer log.Close()
	var transcript bytes.Buffer
	profile := filepath.Join(dir, "coverage.out")
	cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-json", "-run", "^Test(Replacement|RootReplacement)", "-covermode=atomic", "-coverprofile="+profile, "-coverpkg=./pkg/hostdata/...", "./pkg/hostdata")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Stdout = io.MultiWriter(os.Stdout, log, &transcript)
	cmd.Stderr = io.MultiWriter(os.Stderr, log)
	if e := cmd.Run(); e != nil {
		return e
	}
	passed := 0
	passedNames := map[string]bool{}
	for _, line := range bytes.Split(transcript.Bytes(), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var event struct{ Action, Test string }
		if e := json.Unmarshal(line, &event); e != nil {
			return e
		}
		if event.Action == "skip" {
			return fmt.Errorf("replacement test skipped: %s", event.Test)
		}
		if event.Action == "pass" && event.Test != "" {
			passed++
			passedNames[event.Test] = true
		}
	}
	for _, name := range []string{"TestReplacementNativeTimestampOracle", "TestReplacementCompressedMetadata", "TestReplacementCompressedMetadataFailures", "TestReplacementCompressedNativeFixture", "TestReplacementCopyStrategy", "TestReplacementCopyMetadata", "TestReplacementCopyNativeFixture", "TestReplacementCopyLargeFork", "TestReplacementBackupSparseStreams", "TestReplacementBackupMalformed", "TestReplacementBackupWriteFailures", "TestReplacementContextCancellation", "TestReplacementCleanupErrors", "TestReplacementContextSteps", "TestReplacementBackupBeyondLegacyLimits"} {
		if !passedNames[name] {
			return fmt.Errorf("required replacement suite missing: %s", name)
		}
	}
	if runtime.GOOS == "darwin" {
		for _, name := range []string{"TestReplacementCompressedDarwinNative", "TestReplacementCompressedTargetState", "TestReplacementCopyCloneErrors", "TestReplacementCopyDarwinNative"} {
			if !passedNames[name] {
				return fmt.Errorf("required Darwin suite missing: %s", name)
			}
		}
	}
	if runtime.GOOS == "windows" {
		for _, name := range []string{"TestRootReplacementWindowsSparse", "TestRootReplacementWindowsLargeStream", "TestReplacementWindowsNativeCapabilities", "TestReplacementWindowsCopyCallbacks", "TestReplacementWindowsEFSKeyComparison", "TestReplacementWindowsHeldRenamedSource"} {
			if !passedNames[name] {
				return fmt.Errorf("required Windows replacement suite missing: %s", name)
			}
		}
	}
	b, e := os.ReadFile(profile)
	if e != nil {
		return e
	}
	covered, total := 0, 0
	coverageFiles := map[string][2]int{"pkg/hostdata/replacement_copy.go": {}, "pkg/hostdata/replacement_backup.go": {}}
	for _, name := range []string{"replacement.go", "replacement_root.go", "replacement_context.go"} {
		coverageFiles["pkg/hostdata/"+name] = [2]int{}
	}
	if runtime.GOOS == "windows" {
		for _, name := range []string{"replacement_windows.go", "replacement_root_windows.go", "replacement_copy_windows.go", "replacement_efs_windows.go", "replacement_stage_windows.go"} {
			coverageFiles["pkg/hostdata/"+name] = [2]int{}
		}
		if runtime.GOARCH == "386" || runtime.GOARCH == "arm" {
			coverageFiles["pkg/hostdata/replacement_callback_windows_32.go"] = [2]int{}
		} else {
			coverageFiles["pkg/hostdata/replacement_callback_windows_64.go"] = [2]int{}
		}
	} else {
		coverageFiles["pkg/hostdata/replacement_stage_other.go"] = [2]int{}
		suffix := runtime.GOOS
		if suffix != "darwin" && suffix != "linux" {
			suffix = "other"
		}
		coverageFiles["pkg/hostdata/replacement_"+suffix+".go"] = [2]int{}
		coverageFiles["pkg/hostdata/replacement_root_"+suffix+".go"] = [2]int{}
	}
	if runtime.GOOS == "darwin" {
		coverageFiles["pkg/hostdata/replacement_copy_darwin.go"] = [2]int{}
	}
	blocks := map[string][2]int{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		file := strings.TrimPrefix(strings.SplitN(fields[0], ":", 2)[0], "github.com/deploymenttheory/go-apfs-v2/")
		n, e := strconv.Atoi(fields[1])
		if e != nil {
			return e
		}
		hits, e := strconv.Atoi(fields[2])
		if e != nil {
			return e
		}
		if _, tracked := coverageFiles[file]; !tracked {
			continue
		}
		previous := blocks[fields[0]]
		blocks[fields[0]] = [2]int{n, previous[1] + hits}
	}
	for block, value := range blocks {
		file := strings.TrimPrefix(strings.SplitN(block, ":", 2)[0], "github.com/deploymenttheory/go-apfs-v2/")
		counts := coverageFiles[file]
		n, hits := value[0], value[1]
		total += n
		counts[1] += n
		if hits > 0 {
			covered += n
			counts[0] += n
		}
		coverageFiles[file] = counts
	}
	for file, counts := range coverageFiles {
		if counts[1] == 0 || counts[0]*100 <= counts[1]*95 {
			return fmt.Errorf("%s coverage must exceed 95%%: %d/%d", file, counts[0], counts[1])
		}
	}
	if total == 0 || covered*100 <= total*95 {
		return fmt.Errorf("replacement coverage must exceed 95%%: %d/%d", covered, total)
	}
	if passed < 23 {
		return fmt.Errorf("incomplete replacement tests: %d", passed)
	}
	files := []string{"pkg/hostdata/replacement*.go", "scripts/verify-replacement.go", "scripts/verify-replacement-native.go", "testdata/appledouble/native/replacement-copy.c", "testdata/appledouble/native/quarantine-process-capture.h", "testdata/appledouble/native/replacement-copy.json", "testdata/appledouble/native/replacement-compressed.c", "testdata/appledouble/native/replacement-compressed.json", "testdata/appledouble/native/decmpfs-formats.c", "testdata/appledouble/native/decmpfs-formats.json.gz", "go.mod", "go.sum", ".github/workflows/replacement.yml"}
	hashes, e := evidenceaudit.SourceHashes(os.DirFS("."), files)
	if e != nil {
		return e
	}
	revision, e := exec.Command("git", "rev-parse", "HEAD").Output()
	if e != nil {
		return e
	}
	report := map[string]any{"hostdata_covered": packageCovered, "hostdata_statements": packageTotal, "coverage_files": coverageFiles, "covered": covered, "statements": total, "passed_tests": passed, "source_sha256": hashes, "revision": strings.TrimSpace(string(revision)), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "go": runtime.Version()}
	b, e = json.MarshalIndent(report, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "coverage.json"), append(b, '\n'), 0600); e != nil {
		return e
	}
	if e = evidenceaudit.Coverage(os.DirFS("."), os.DirFS(filepath.Dir(dir)), filepath.Base(dir), strings.TrimSpace(string(revision)), runtime.GOOS); e != nil {
		return e
	}
	fmt.Printf("Replacement fallback: %d/%d covered statements; %d passing test records on %s/%s\n", covered, total, passed, runtime.GOOS, runtime.GOARCH)
	return nil
}

// The full-package run is separate so the original focused transcript, strict
// skip rejection and evidenceaudit schema remain unchanged and independently
// auditable. Existing unrelated platform probes may legitimately skip in the
// full hostdata suite; every replacement test remains mandatory.
func completeHostdataCoverage(profile string) (covered, total int, err error) {
	b, err := os.ReadFile(profile)
	if err != nil {
		return 0, 0, err
	}
	blocks := map[string][2]int{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		name := strings.TrimPrefix(strings.SplitN(fields[0], ":", 2)[0], "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/")
		if strings.Contains(name, "/") {
			continue
		}
		n, e := strconv.Atoi(fields[1])
		if e != nil {
			return 0, 0, e
		}
		hits, e := strconv.Atoi(fields[2])
		if e != nil {
			return 0, 0, e
		}
		previous := blocks[fields[0]]
		blocks[fields[0]] = [2]int{n, previous[1] + hits}
	}
	for _, value := range blocks {
		total += value[0]
		if value[1] > 0 {
			covered += value[0]
		}
	}
	return covered, total, nil
}

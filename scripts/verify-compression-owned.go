//go:build ignore

// Require complete hostdata and changed-file coverage for owned native bindings.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

type counter struct{ Covered, Statements int }

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	const dir = "artifacts/compression-owned-coverage"
	if e := os.MkdirAll(dir, 0755); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	transcript, e := os.Create(filepath.Join(dir, "full-tests.jsonl"))
	if e != nil {
		return e
	}
	command := cirunner.CommandContext(ctx, "go", "test", "-count=1", "-json", "-covermode=atomic", "-coverprofile="+filepath.Join(dir, "coverage.out"), "./pkg/hostdata")
	command.Env = append(os.Environ(), "CGO_ENABLED=0")
	command.Stdout = transcript
	command.Stderr = os.Stderr
	runErr := command.Run()
	if e = errors.Join(runErr, transcript.Close()); e != nil {
		diagnose(filepath.Join(dir, "full-tests.jsonl"))
		return fmt.Errorf("complete hostdata tests: %w", e)
	}
	fullPassed, fullSkipped, e := inspectTranscript(filepath.Join(dir, "full-tests.jsonl"), false, nil)
	if e != nil {
		return e
	}
	required := []string{"TestNativeCompressionOwnedValidation", "TestCompressionVolumeObservation", "TestResourceForkContextOwnership", "TestCompressionOwnedNativeEvidence", "TestCompressionOwnedNativeEvidence/compression-owned-macos15.json.gz", "TestCompressionOwnedNativeEvidence/compression-owned-macos26.json.gz", "TestCompressionOwnedNativeEvidence/compression-owned-macos27.json.gz"}
	if runtime.GOOS == "darwin" {
		required = append(required, "TestNativeCompressionOwnedHeldAcquisition", "TestNativeCompressionOwnedNoAcquisitionCalls", "TestNativeCompressionOwnedReadOnlyAdmission", "TestNativeCompressionOwnedMounted", "TestNativeCompressionAcquisitionCancellationOwnership", "TestResourceForkContextVersionRouting", "TestResourceForkLegacyContextCheckpoints", "TestResourceForkNativeLateCancellationCloses", "TestResourceForkLegacyContextNativeBinding")
	} else {
		required = append(required, "TestNativeCompressionOwnedForeignHost")
	}
	focused, e := os.Create(filepath.Join(dir, "tests.jsonl"))
	if e != nil {
		return e
	}
	args := []string{"test", "-count=1", "-json", "-run=^Test(NativeCompressionOwned|NativeCompressionAcquisitionCancellationOwnership|CompressionVolumeObservation|CompressionOwnedNativeEvidence|ResourceForkContext|ResourceForkLegacyContext|ResourceForkNativeLateCancellationCloses)", "./pkg/hostdata"}
	command = cirunner.CommandContext(ctx, "go", args...)
	command.Env = append(os.Environ(), "CGO_ENABLED=0")
	command.Stdout = focused
	command.Stderr = os.Stderr
	runErr = command.Run()
	if e = errors.Join(runErr, focused.Close()); e != nil {
		diagnose(filepath.Join(dir, "tests.jsonl"))
		return fmt.Errorf("owned compression focused qualification: %w", e)
	}
	passed, _, e := inspectTranscript(filepath.Join(dir, "tests.jsonl"), true, required)
	if e != nil {
		return e
	}
	file, e := os.Open(filepath.Join(dir, "coverage.out"))
	if e != nil {
		return e
	}
	defer file.Close()
	totals := map[string]counter{}
	var total counter
	scan := bufio.NewScanner(file)
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) != 3 {
			continue
		}
		name, _, ok := strings.Cut(fields[0], ":")
		if !ok {
			return errors.New("invalid coverage location")
		}
		statements, e := strconv.Atoi(fields[1])
		if e != nil {
			return e
		}
		hits, e := strconv.Atoi(fields[2])
		if e != nil {
			return e
		}
		value := totals[filepath.Base(name)]
		value.Statements += statements
		total.Statements += statements
		if hits > 0 {
			value.Covered += statements
			total.Covered += statements
		}
		totals[filepath.Base(name)] = value
	}
	if e = scan.Err(); e != nil {
		return e
	}
	names := []string{"compression_operation_native.go", "compression_volume.go", "resource_fork.go"}
	if runtime.GOOS == "darwin" {
		names = append(names, "compression_operation_darwin.go", "compression_metadata_darwin.go", "resource_fork_darwin.go", "resource_fork_legacy_darwin.go")
	} else {
		names = append(names, "compression_operation_other.go", "compression_metadata_other.go", "resource_fork_other.go")
	}
	if total.Statements == 0 || total.Covered*100 <= total.Statements*95 {
		return fmt.Errorf("hostdata coverage must exceed95%%: %d/%d", total.Covered, total.Statements)
	}
	selected := map[string][2]int{}
	var focusedTotal counter
	for _, name := range names {
		value := totals[name]
		selected["pkg/hostdata/"+name] = [2]int{value.Covered, value.Statements}
		if value.Statements == 0 || value.Covered*100 <= value.Statements*95 {
			return fmt.Errorf("%s coverage must exceed 95%%: %d/%d", name, value.Covered, value.Statements)
		}
		focusedTotal.Covered += value.Covered
		focusedTotal.Statements += value.Statements
	}
	hashes, e := evidenceaudit.HarnessSourceHashes(os.DirFS("."), []string{"pkg/hostdata/*.go", "pkg/osversion/*.go", "pkg/appledouble/*.go", "pkg/compression/decmpfs/*.go", "internal/decmpfs/*.go", "internal/hostwalk/*.go", "internal/evidenceaudit/*.go", "scripts/verify-compression-owned.go", "scripts/capture-compression-owned.go", "testdata/appledouble/native/compression-owned*", ".github/workflows/compression-owned.yml", "go.mod", "go.sum"})
	if e != nil {
		return e
	}
	revision, e := cirunner.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	if e != nil {
		return e
	}
	rawHashes := map[string]string{}
	for _, name := range []string{"full-tests.jsonl", "tests.jsonl", "coverage.out"} {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			return e
		}
		sum := sha256.Sum256(b)
		rawHashes[name] = hex.EncodeToString(sum[:])
	}
	report := map[string]any{"evidence_sha256": rawHashes, "revision": strings.TrimSpace(string(revision)), "source_sha256": hashes, "go": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "passed_tests": passed, "full_passed_tests": fullPassed, "full_skipped_tests": fullSkipped, "required_suites": required, "retained_native_profiles": 3, "retained_native_cases": 216, "covered": focusedTotal.Covered, "statements": focusedTotal.Statements, "coverage_files": selected, "hostdata_covered": total.Covered, "hostdata_statements": total.Statements}
	b, e := json.MarshalIndent(report, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "coverage.json"), append(b, '\n'), 0644); e != nil {
		return e
	}
	if e = evidenceaudit.Coverage(os.DirFS("."), os.DirFS("artifacts"), "compression-owned-coverage", strings.TrimSpace(string(revision)), runtime.GOOS); e != nil {
		return e
	}

	fmt.Printf("hostdata %d/%d statements; all %d changed production files exceed95%%\n", total.Covered, total.Statements, len(names))
	return nil
}
func diagnose(path string) {
	file, e := os.Open(path)
	if e != nil {
		return
	}
	defer file.Close()
	last := map[string][]string{}
	scan := bufio.NewScanner(file)
	scan.Buffer(make([]byte, 65536), 1<<20)
	for scan.Scan() {
		var item struct{ Action, Test, Output string }
		if json.Unmarshal(scan.Bytes(), &item) != nil {
			continue
		}
		if item.Output != "" {
			rows := append(last[item.Test], item.Output)
			if len(rows) > 12 {
				rows = rows[len(rows)-12:]
			}
			last[item.Test] = rows
		}
		if item.Action == "fail" {
			fmt.Fprintln(os.Stderr, "FAILED", item.Test)
			for _, row := range last[item.Test] {
				fmt.Fprint(os.Stderr, row)
			}
		}
	}
	fmt.Fprintln(os.Stderr, "Full transcript:", path)
}

// Full package evidence remains unfiltered. Focused evidence is a separate actual
// command whose every test, including all native profile replays, must pass.
func inspectTranscript(path string, rejectSkips bool, required []string) (int, []string, error) {
	f, e := os.Open(path)
	if e != nil {
		return 0, nil, e
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 65536), 1<<20)
	passed, packages := 0, 0
	names := map[string]bool{}
	allowed := map[string]string{}
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		allowed["TestSetCreationTimeUnsupportedHost"] = "host supports creation-time updates; covered by native tests"
	}
	if runtime.GOOS == "windows" {
		allowed["TestListXattrsMissingFile"] = "extended attributes are not readable on this platform"
		allowed["TestLinkCountsNames"] = "this platform does not expose inode identity"
	}
	reasons := map[string]bool{}
	var skipped []string
	for scan.Scan() {
		var item struct{ Action, Package, Test, Output string }
		if e = json.Unmarshal(scan.Bytes(), &item); e != nil {
			return 0, nil, e
		}
		if item.Package != "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata" {
			return 0, nil, fmt.Errorf("unexpected qualification package %q", item.Package)
		}
		if reason, ok := allowed[item.Test]; ok && strings.Contains(item.Output, reason) {
			reasons[item.Test] = true
		}
		if item.Action == "fail" || item.Action == "skip" && rejectSkips {
			return 0, nil, fmt.Errorf("qualification %s: %s", item.Action, item.Test)
		}
		if item.Action == "skip" {
			if !reasons[item.Test] {
				return 0, nil, fmt.Errorf("unexpected full-suite skip: %s", item.Test)
			}
			skipped = append(skipped, item.Test)
		}
		if item.Action == "pass" {
			if item.Test == "" {
				packages++
			} else {
				passed++
				names[item.Test] = true
			}
		}
	}
	if e = scan.Err(); e != nil {
		return 0, nil, e
	}
	if packages != 1 || passed == 0 {
		return 0, nil, errors.New("incomplete hostdata transcript")
	}
	for _, name := range required {
		if !names[name] {
			return 0, nil, fmt.Errorf("required qualification suite missing: %s", name)
		}
	}
	return passed, skipped, nil
}

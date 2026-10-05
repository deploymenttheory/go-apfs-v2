//go:build ignore

// Verify complete hostdata coverage and non-skippable compression lifecycle cases.
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
	const dir = "artifacts/compression-lifecycle-coverage"
	if e := os.MkdirAll(dir, 0755); e != nil {
		return e
	}
	log, e := os.Create(filepath.Join(dir, "tests.jsonl"))
	if e != nil {
		return e
	}
	defer log.Close()
	profile := filepath.Join(dir, "coverage.out")
	var transcript bytes.Buffer
	cmd := exec.Command("go", "test", "-count=1", "-json", "-run=^(TestRecompress|TestCompressionResourceFork|TestPathResourceForkNative|TestNativeCompressionAcquisition|TestCompressionOperation|TestInstallHeldCompression|TestInstallCompression|TestCommitHeldCompression|TestCommitCompression|TestActivateCompression|TestCaptureCompressionMetadata|TestCompressionMetadata|TestCompressionLifecycle|TestQueryCompressionHeldNativeCorpus|TestCompressionNativeMetadata)", "-covermode=atomic", "-coverprofile="+profile, "./pkg/hostdata")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Stdout = io.MultiWriter(os.Stdout, log, &transcript)
	cmd.Stderr = io.MultiWriter(os.Stderr, log)
	if e = cmd.Run(); e != nil {
		return e
	}
	required := map[string]bool{}
	for _, name := range []string{"TestCompressionResourceForkProvenance", "TestRecompressNativeStorage", "TestRecompressNativeOperationProfiles", "TestRecompressAdmissionAndDeclines", "TestRecompressFailuresAndCancellation", "TestCompressionOperationProvenance", "TestInstallHeldCompressionBindingFailures", "TestInstallCompressionForeignFiles", "TestInstallCompressionStageFailures", "TestInstallCompressionForkNativeLifecycle", "TestInstallCompressionForkMultiBlockAndFailures", "TestInstallCompressionForkInvalidStorage", "TestCompressionMetadataHeldProviderBinding", "TestCommitHeldCompressionBinding", "TestCommitCompressionNativeLifecycle", "TestCommitCompressionCancellationAndValidation", "TestActivateCompressionNativeComparisons", "TestActivateCompressionCancellationAndReadFailures", "TestCaptureCompressionMetadataBounded", "TestCaptureCompressionMetadataFailures", "TestCaptureCompressionMetadataAbsent", "TestCompressionMetadataInvalidArguments", "TestCompressionLifecycleProvenance"} {
		required[name] = true
	}
	if runtime.GOOS == "darwin" {
		for _, name := range []string{"TestCompressionResourceForkOpeningNative", "TestCompressionResourceForkVersionRouting", "TestCompressionResourceForkLegacyFailures", "TestCompressionResourceForkLegacyIdentity", "TestPathResourceForkNative", "TestRecompressNativeFiles", "TestNativeCompressionAcquisitionErrors", "TestNativeCompressionAcquisitionDecompresses", "TestInstallHeldCompressionNativeReadback", "TestCommitHeldCompressionNativeReadback", "TestCommitHeldCompressionNativeErrors", "TestQueryCompressionHeldNativeCorpus", "TestCompressionMetadataHeldLargeFork", "TestCompressionMetadataNativeErrors"} {
			required[name] = true
		}
	} else {
		required["TestNativeCompressionAcquisitionRequiresDarwinContext"] = true
		required["TestCompressionNativeMetadataRequiresDarwinContext"] = true
		required["TestCommitHeldCompressionRequiresNativeDarwinView"] = true
		required["TestInstallHeldCompressionRequiresNativeDarwinView"] = true
	}
	passed := 0
	for _, line := range bytes.Split(transcript.Bytes(), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var event struct{ Action, Test string }
		if e = json.Unmarshal(line, &event); e != nil {
			return e
		}
		if event.Action == "skip" || event.Action == "fail" {
			return fmt.Errorf("compression lifecycle case skipped: %s", event.Test)
		}
		if event.Action == "pass" && event.Test != "" {
			delete(required, event.Test)
			passed++
		}
	}
	if len(required) != 0 {
		return fmt.Errorf("missing compression lifecycle suites: %v", required)
	}
	coverageFiles := map[string][2]int{"pkg/hostdata/compression_operation.go": {}, "pkg/hostdata/compression_operation_native.go": {}, "pkg/hostdata/compression_install.go": {}, "pkg/hostdata/compression_install_held.go": {}, "pkg/hostdata/compression_fork_install.go": {}, "pkg/hostdata/compression_commit_held.go": {}, "pkg/hostdata/compression_commit.go": {}, "pkg/hostdata/compression_flags.go": {}, "pkg/hostdata/compression_metadata.go": {}}
	if runtime.GOOS == "darwin" {
		coverageFiles["pkg/hostdata/compression_operation_darwin.go"] = [2]int{}
		coverageFiles["pkg/hostdata/resource_fork_darwin.go"] = [2]int{}
		coverageFiles["pkg/hostdata/resource_fork_legacy_darwin.go"] = [2]int{}
		coverageFiles["pkg/hostdata/appledouble_path_fork_darwin.go"] = [2]int{}
		coverageFiles["pkg/hostdata/compression_metadata_darwin.go"] = [2]int{}
		coverageFiles["pkg/hostdata/compression_commit_held_darwin.go"] = [2]int{}
	} else {
		coverageFiles["pkg/hostdata/compression_operation_other.go"] = [2]int{}
		coverageFiles["pkg/hostdata/compression_metadata_other.go"] = [2]int{}
		coverageFiles["pkg/hostdata/compression_commit_held_other.go"] = [2]int{}
	}
	data, e := os.ReadFile(profile)
	if e != nil {
		return e
	}
	covered, total := 0, 0
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		name := strings.TrimPrefix(strings.SplitN(f[0], ":", 2)[0], "github.com/deploymenttheory/go-apfs-v2/")
		n, e := strconv.Atoi(f[1])
		if e != nil {
			return e
		}
		hits, e := strconv.Atoi(f[2])
		if e != nil {
			return e
		}
		if count, ok := coverageFiles[name]; ok {
			count[1] += n
			if hits > 0 {
				count[0] += n
			}
			coverageFiles[name] = count
		}
	}
	for name, count := range coverageFiles {
		if count[1] == 0 || count[0]*100 <= count[1]*95 {
			return fmt.Errorf("%s coverage must exceed 95%%: %d/%d", name, count[0], count[1])
		}
		covered += count[0]
		total += count[1]
	}
	// Keep the complete package suite independent of the focused, non-skippable
	// evidence. Existing platform qualifications remain in the package suite.
	packageLog, e := os.Create(filepath.Join(dir, "package-tests.jsonl"))
	if e != nil {
		return e
	}
	packageProfile := filepath.Join(dir, "package-coverage.out")
	packageCmd := exec.Command("go", "test", "-count=1", "-json", "-covermode=atomic", "-coverprofile="+packageProfile, "./pkg/hostdata")
	packageCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	packageCmd.Stdout = io.MultiWriter(os.Stdout, packageLog)
	packageCmd.Stderr = os.Stderr
	runErr := packageCmd.Run()
	closeErr := packageLog.Close()
	if runErr != nil {
		return runErr
	}
	if closeErr != nil {
		return closeErr
	}
	packageData, e := os.ReadFile(packageProfile)
	if e != nil {
		return e
	}
	packageCovered, packageTotal := 0, 0
	for _, line := range strings.Split(string(packageData), "\n") {
		if line == "" || line == "mode: atomic" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return fmt.Errorf("invalid package coverage block: %q", line)
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n < 0 {
			return fmt.Errorf("invalid package statement count: %q", line)
		}
		hits, err := strconv.Atoi(fields[2])
		if err != nil || hits < 0 {
			return fmt.Errorf("invalid package coverage hits: %q", line)
		}
		packageTotal += n
		if hits > 0 {
			packageCovered += n
		}
	}
	if packageTotal == 0 || packageCovered*100 <= packageTotal*95 {
		return fmt.Errorf("complete hostdata package coverage must exceed 95%%: %d/%d", packageCovered, packageTotal)
	}
	hashes, e := evidenceaudit.SourceHashes(os.DirFS("."), []string{"pkg/hostdata/compression_*.go", "pkg/hostdata/resource_fork*.go", "pkg/hostdata/appledouble_path_fork*.go", "internal/darwinabi/*.go", "internal/darwinabi/*.s", "pkg/osversion/*.go", "scripts/verify-compression-lifecycle.go", "scripts/capture-compression-lifecycle.go", "testdata/appledouble/native/compression-lifecycle*", "testdata/appledouble/native/compression-operation*", "testdata/appledouble/native/resource-fork-open*", "scripts/capture-resource-fork-open.go", "scripts/capture-compression-operation*.go", "testdata/appledouble/native/compression-policy.c", "testdata/appledouble/native/compression-query.json.gz", "go.mod", "go.sum"})
	if e != nil {
		return e
	}
	revision, e := exec.Command("git", "rev-parse", "HEAD").Output()
	if e != nil {
		return e
	}
	report := map[string]any{"coverage_files": coverageFiles, "covered": covered, "statements": total, "passed_tests": passed, "source_sha256": hashes, "revision": strings.TrimSpace(string(revision)), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "go": runtime.Version()}
	report["complete_package_coverage"] = map[string]int{"covered": packageCovered, "statements": packageTotal}
	data, e = json.MarshalIndent(report, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "coverage.json"), append(data, '\n'), 0600); e != nil {
		return e
	}
	if e = evidenceaudit.Coverage(os.DirFS("."), os.DirFS(filepath.Dir(dir)), filepath.Base(dir), strings.TrimSpace(string(revision)), runtime.GOOS); e != nil {
		return e
	}
	fmt.Printf("Compression lifecycle: complete hostdata coverage %d/%d; %d focused passing records; every new production file above 95%%\n", packageCovered, packageTotal, passed)
	return nil
}

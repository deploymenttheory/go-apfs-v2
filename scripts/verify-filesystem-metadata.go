//go:build ignore

// Qualify the filesystem view without waiting for fresh native producer jobs.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func main() {
	if err := verify(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func verify() error {
	const dir = "artifacts/filesystem-metadata-coverage"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	// Bind every instrumented package source, not just the files this focused
	// suite qualifies. Existing whole-package coverage gates remain mandatory.
	hashes, err := evidenceaudit.HarnessSourceHashes(os.DirFS("."), []string{"pkg/hostdata/*.go", "pkg/appledouble/*.go", "pkg/appledouble/testdata/fuzz/FuzzFilesystemRemoval/*", "scripts/verify-filesystem-metadata.go", "testdata/appledouble/native/metadata-filesystem*.json.gz", "go.mod", "go.sum"})
	if err != nil {
		return err
	}
	packageJSON, err := cirunner.Command("go", "list", "-json", "./pkg/hostdata", "./pkg/appledouble").Output()
	if err != nil {
		return err
	}
	all := map[string][2]int{}
	focused := map[string][2]int{}
	decoder := json.NewDecoder(bytes.NewReader(packageJSON))
	for {
		var pkg struct {
			ImportPath string
			GoFiles    []string
		}
		if err = decoder.Decode(&pkg); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
		prefix := strings.TrimPrefix(pkg.ImportPath, "github.com/deploymenttheory/go-apfs-v2/")
		for _, base := range pkg.GoFiles {
			name := prefix + "/" + base
			if _, ok := hashes[name]; !ok {
				return fmt.Errorf("untracked package source: %s", name)
			}
			all[name] = [2]int{}
			if strings.HasPrefix(base, "filesystem_metadata") || base == "filesystem_remove.go" {
				focused[name] = [2]int{}
			}
		}
	}
	if len(focused) < 3 {
		return errors.New("incomplete filesystem metadata source inventory")
	}
	log, err := os.Create(filepath.Join(dir, "tests.jsonl"))
	if err != nil {
		return err
	}
	var transcript bytes.Buffer
	profile := filepath.Join(dir, "coverage.out")
	cmd := cirunner.Command("go", "test", "-timeout", "3m", "-count=1", "-json", "-run", "^(TestFilesystemMetadata|TestMetadataValue|TestFilesystemRemoval|FuzzFilesystemRemoval)", "-covermode=atomic", "-coverprofile="+profile, "./pkg/hostdata", "./pkg/appledouble")
	cmd.Stdout = io.MultiWriter(os.Stdout, log, &transcript)
	cmd.Stderr = os.Stderr
	if err = errors.Join(cmd.Run(), log.Close()); err != nil {
		return err
	}
	required := map[string]bool{"TestFilesystemRemovalPackedEmpty": true, "TestFilesystemMetadataCorpusInventory": true, "TestFilesystemRemovalNativeBytes": true, "TestFilesystemRemovalStreaming": true, "TestFilesystemRemovalFailures": true, "TestFilesystemMetadataNativeFATRemoval": true, "TestFilesystemMetadataBorrowedLifetime": true, "TestFilesystemMetadataHeldFailures": true, "TestFilesystemMetadataRemovalFailures": true, "TestFilesystemMetadataRemovalLastAttribute": true, "TestFilesystemMetadataNativeRemoval": true, "TestFilesystemMetadataNativeFATReadback": true, "TestFilesystemMetadataLargeFork": true, "TestFilesystemMetadataScope": true, "TestFilesystemMetadataIdentityAndSelection": true, "TestFilesystemMetadataNativeProviderFailures": true, "TestFilesystemMetadataSidecarFailures": true, "TestFilesystemMetadataBlankForkBoundaries": true, "TestFilesystemMetadataAcquisitionBoundaries": true, "TestMetadataValueCancellation": true}
	if runtime.GOOS == "darwin" {
		required["TestFilesystemMetadataNativeForkStreaming"] = true
		required["TestFilesystemMetadataForkWrapperFailures"] = true
	} else {
		required["TestFilesystemMetadataNativeVolumeQuery"] = true
	}
	if runtime.GOOS == "windows" {
		required["TestFilesystemMetadataFATNames"] = true
	}
	passed := 0
	for _, line := range bytes.Split(transcript.Bytes(), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var event struct{ Action, Test string }
		if err = json.Unmarshal(line, &event); err != nil {
			return err
		}
		if event.Action == "skip" || event.Action == "fail" {
			return fmt.Errorf("unqualified filesystem metadata test %s: %s", event.Test, event.Action)
		}
		if event.Action == "pass" && event.Test != "" {
			delete(required, event.Test)
			passed++
		}
	}
	if len(required) != 0 {
		return fmt.Errorf("missing filesystem metadata suites: %v", required)
	}
	data, err := os.ReadFile(profile)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(data, []byte("mode: atomic\n")) {
		return errors.New("invalid coverage mode")
	}
	observed := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || line == "mode: atomic" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return fmt.Errorf("invalid coverage block: %q", line)
		}
		name := strings.TrimPrefix(strings.SplitN(fields[0], ":", 2)[0], "github.com/deploymenttheory/go-apfs-v2/")
		counts, ok := all[name]
		if !ok {
			return fmt.Errorf("untracked coverage source: %s", name)
		}
		statements, e := strconv.Atoi(fields[1])
		if e != nil || statements < 0 {
			return errors.New("invalid coverage statement count")
		}
		hits, e := strconv.Atoi(fields[2])
		if e != nil || hits < 0 {
			return errors.New("invalid coverage hit count")
		}
		counts[1] += statements
		if hits > 0 {
			counts[0] += statements
		}
		all[name] = counts
		observed[name] = true
	}
	covered, total := 0, 0
	for name := range focused {
		counts := all[name]
		if !observed[name] || counts[1] == 0 || counts[0]*100 <= counts[1]*95 {
			return fmt.Errorf("%s coverage must exceed 95 percent: %d/%d", name, counts[0], counts[1])
		}
		focused[name] = counts
		covered += counts[0]
		total += counts[1]
	}
	revision, err := cirunner.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	report := map[string]any{"coverage_files": focused, "instrumented_package_files": all, "covered": covered, "statements": total, "passed_tests": passed, "source_sha256": hashes, "revision": strings.TrimSpace(string(revision)), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "go": runtime.Version()}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "coverage.json"), append(encoded, '\n'), 0600); err != nil {
		return err
	}
	if err = evidenceaudit.Coverage(os.DirFS("."), os.DirFS("artifacts"), "filesystem-metadata-coverage", strings.TrimSpace(string(revision)), runtime.GOOS); err != nil {
		return err
	}
	fmt.Printf("Filesystem metadata reads and removals: %d/%d statements; %d passing records on %s/%s\n", covered, total, passed, runtime.GOOS, runtime.GOARCH)
	return nil
}

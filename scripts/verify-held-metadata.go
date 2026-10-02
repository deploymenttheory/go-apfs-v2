//go:build ignore

// Verify held native and portable logical metadata providers.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

func main() {
	if e := verify(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func verify() error {
	const dir = "artifacts/held-metadata"
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
	cmd := exec.Command("go", "test", "-count=1", "-json", "-run", "^Test(HeldMetadata|HeldLifecycle|LogicalMetadata|MetadataArgument|DarwinSecurity|OpenMetadata|MetadataOpen|MetadataStat|DarwinMetadata)", "-covermode=atomic", "-coverprofile="+profile, "-coverpkg=./pkg/hostdata/...", "./pkg/hostdata")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Stdout = io.MultiWriter(os.Stdout, log, &transcript)
	cmd.Stderr = io.MultiWriter(os.Stderr, log)
	if e := cmd.Run(); e != nil {
		return e
	}
	passed := 0
	for _, line := range bytes.Split(transcript.Bytes(), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var event struct{ Action, Test string }
		if e := json.Unmarshal(line, &event); e != nil {
			return e
		}
		if event.Action == "skip" {
			return fmt.Errorf("metadata provider test skipped: %s", event.Test)
		}
		if event.Action == "pass" && event.Test != "" {
			passed++
		}
	}
	b, e := os.ReadFile(profile)
	if e != nil {
		return e
	}
	covered, total := 0, 0
	coverageFiles := map[string][2]int{"pkg/hostdata/held_metadata.go": {}, "pkg/hostdata/metadata_open.go": {}}
	coverageFiles["pkg/hostdata/held_lifecycle.go"] = [2]int{}
	coverageFiles["pkg/hostdata/metadata_stat.go"] = [2]int{}
	if runtime.GOOS == "windows" {
		coverageFiles["pkg/hostdata/metadata_stat_windows.go"] = [2]int{}
	} else {
		coverageFiles["pkg/hostdata/metadata_stat_other.go"] = [2]int{}
	}
	switch runtime.GOOS {
	case "darwin":
		coverageFiles["pkg/hostdata/held_metadata_darwin.go"] = [2]int{}
		coverageFiles["pkg/hostdata/libsystem_security_darwin.go"] = [2]int{}
		coverageFiles["pkg/hostdata/metadata_open_darwin.go"] = [2]int{}
	case "linux", "windows":
		coverageFiles["pkg/hostdata/held_metadata_other.go"] = [2]int{}
		coverageFiles["pkg/hostdata/metadata_open_"+runtime.GOOS+".go"] = [2]int{}
	default:
		return fmt.Errorf("unsupported qualification host: %s", runtime.GOOS)
	}
	blocks := map[string][2]int{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		file := strings.TrimPrefix(strings.SplitN(fields[0], ":", 2)[0], "github.com/deploymenttheory/go-apfs-v2/")
		_, tracked := coverageFiles[file]
		if !tracked {
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
		return fmt.Errorf("metadata provider coverage must exceed 95%%: %d/%d", covered, total)
	}
	if passed < 1150 {
		return fmt.Errorf("incomplete metadata provider tests: %d", passed)
	}
	files := []string{"pkg/hostdata/held_metadata.go", "pkg/hostdata/held_metadata_test.go", "pkg/hostdata/held_metadata_darwin.go", "pkg/hostdata/held_metadata_darwin_test.go", "pkg/hostdata/held_metadata_other.go", "pkg/hostdata/held_metadata_other_test.go", "pkg/hostdata/libsystem_security_darwin.go", "pkg/hostdata/metadata_open.go", "pkg/hostdata/metadata_open_test.go", "pkg/hostdata/metadata_open_darwin.go", "pkg/hostdata/metadata_open_darwin_test.go", "pkg/hostdata/metadata_open_linux.go", "pkg/hostdata/metadata_open_windows.go", "scripts/verify-held-metadata.go", "scripts/verify-held-metadata-native.go", "testdata/appledouble/native/held-metadata.c", "go.mod", "go.sum"}
	files = append(files, "pkg/hostdata/metadata_stat.go", "pkg/hostdata/metadata_stat_other.go", "pkg/hostdata/metadata_stat_windows.go", "pkg/hostdata/metadata_stat_test.go", "pkg/hostdata/metadata_stat_windows_test.go")
	hashes := map[string]string{}
	files = append(files, "pkg/hostdata/held_metadata_fixture_test.go", "pkg/hostdata/metadata_open_windows_test.go", "testdata/appledouble/native/held-metadata.json.gz")
	files = append(files, "pkg/hostdata/held_lifecycle.go", "pkg/hostdata/held_lifecycle_test.go", "pkg/hostdata/held_lifecycle_native_test.go", "internal/testutil/heldlifecycle/oracle.go", "testdata/appledouble/native/held-lifecycle.c", "testdata/appledouble/native/held-lifecycle.json.gz", "scripts/verify-held-lifecycle.go")
	for _, path := range files {
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		h := sha256.Sum256(b)
		hashes[path] = hex.EncodeToString(h[:])
	}
	revision, e := exec.Command("git", "rev-parse", "HEAD").Output()
	if e != nil {
		return e
	}
	report := map[string]any{"coverage_files": coverageFiles, "covered": covered, "statements": total, "passed_tests": passed, "source_sha256": hashes, "revision": strings.TrimSpace(string(revision)), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "go": runtime.Version()}
	b, e = json.MarshalIndent(report, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "coverage.json"), append(b, '\n'), 0600); e != nil {
		return e
	}
	fmt.Printf("Held metadata providers: %d/%d covered statements; %d passing test records on %s/%s\n", covered, total, passed, runtime.GOOS, runtime.GOARCH)
	return nil
}

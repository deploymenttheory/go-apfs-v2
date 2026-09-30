//go:build ignore

// Verify the complete path lifecycle and its native/portable operation providers.
package main

import (
	"bytes"
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

	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"
)

func main() {
	if e := verify(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func verify() error {
	const dir = "artifacts/path-lifecycle-coverage"
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
	cmd := exec.Command("go", "test", "-count=1", "-json", "-run", "^(TestPath|TestAppleDoublePath|TestPreparePathSecurity|TestResetPathSecurity|TestDarwinCall)", "-covermode=atomic", "-coverprofile="+profile, "-coverpkg=./pkg/hostmeta,./internal/testutil/pathnative,./internal/testutil/pathsecurity", "./pkg/hostmeta", "./internal/testutil/pathnative", "./internal/testutil/pathsecurity")
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
			return fmt.Errorf("Path lifecycle test skipped: %s", event.Test)
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
	coverageFiles := map[string][2]int{}
	coverageFiles["internal/testutil/pathnative/oracle.go"] = [2]int{}
	coverageFiles["internal/testutil/pathsecurity/oracle.go"] = [2]int{}
	for _, file := range []string{"appledouble_path.go", "appledouble_path_backing.go", "appledouble_path_fork.go", "appledouble_path_open.go", "path_lifecycle.go", "path_security.go"} {
		coverageFiles["pkg/hostmeta/"+file] = [2]int{}
	}
	suffix := "other"
	if runtime.GOOS == "darwin" {
		suffix = "darwin"
		coverageFiles["pkg/hostmeta/libsystem_call_darwin.go"] = [2]int{}
	}
	coverageFiles["pkg/hostmeta/appledouble_path_io_"+suffix+".go"] = [2]int{}
	coverageFiles["pkg/hostmeta/appledouble_path_fork_"+suffix+".go"] = [2]int{}
	coverageFiles["pkg/hostmeta/path_native_"+suffix+".go"] = [2]int{}
	handleSuffix := "unix"
	if runtime.GOOS == "windows" {
		handleSuffix = "windows"
	}
	coverageFiles["pkg/hostmeta/appledouble_path_handle_"+handleSuffix+".go"] = [2]int{}
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
	var deficits error
	for file, counts := range coverageFiles {
		if counts[1] == 0 || counts[0]*100 <= counts[1]*95 {
			deficits = errors.Join(deficits, fmt.Errorf("%s coverage must exceed 95%%: %d/%d", file, counts[0], counts[1]))
		}
	}
	if deficits != nil {
		return deficits
	}
	if total == 0 || covered*100 <= total*95 {
		return fmt.Errorf("Path lifecycle coverage must exceed 95%%: %d/%d", covered, total)
	}
	if passed < 50 {
		return fmt.Errorf("incomplete path lifecycle tests: %d", passed)
	}
	files := []string{"scripts/verify-path-lifecycle-coverage.go", "go.mod", "go.sum", "pkg/hostmeta/*.go", "internal/evidenceaudit/*.go", "internal/testutil/pathnative/*.go", "internal/testutil/pathsecurity/*.go", "testdata/appledouble/native/path-*.c", "testdata/appledouble/native/path-*.json.gz", "testdata/appledouble/native/xattr-provider-context.h", "testdata/appledouble/native/xattr-remove-effects*"}
	hashes, e := evidenceaudit.SourceHashes(os.DirFS("."), files)
	if e != nil {
		return e
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
	fmt.Printf("Path lifecycle: %d/%d covered statements; %d passing test records on %s/%s\n", covered, total, passed, runtime.GOOS, runtime.GOARCH)
	return nil
}

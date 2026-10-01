//go:build ignore

// Qualify the typed Darwin extension in addition to the existing portable gates.
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
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("typed Darwin qualification requires macOS")
	}
	if out, err := exec.Command("go", "run", "scripts/generate-darwin-wrappers.go", "-check").CombinedOutput(); err != nil {
		return fmt.Errorf("generated wrappers: %w: %s", err, out)
	}
	const dir = "artifacts/darwin-wrappers"
	if e := os.MkdirAll(dir, 0755); e != nil {
		return e
	}
	sdk, err := exec.Command("xcrun", "--show-sdk-path").Output()
	if err != nil {
		return err
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		cmd := exec.Command("xcrun", "clang", "-arch", arch, "-isysroot", strings.TrimSpace(string(sdk)), "-Wall", "-Wextra", "-Werror", "-DDARWIN_WRAPPERS_ORACLE", "-fsyntax-only", "-Xclang", "-ast-dump=json", "testdata/appledouble/native/darwin-wrappers.c")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		ast, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("%s SDK signatures: %w: %s", arch, err, stderr.String())
		}
		if err := os.WriteFile(filepath.Join(dir, "ast-"+arch+".json"), ast, 0600); err != nil {
			return err
		}
	}
	for _, arch := range []string{"amd64", "arm64"} {
		cmd := exec.Command("go", "test", "-c", "-o", filepath.Join(dir, "wrappers-"+arch+".test"), "./internal/darwinabi")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=darwin", "GOARCH="+arch)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s wrapper link: %w: %s", arch, err, out)
		}
	}
	oracle, err := filepath.Abs(filepath.Join(dir, "native-observer"))
	if err != nil {
		return err
	}
	if out, err := exec.Command("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-DDARWIN_WRAPPERS_ORACLE", "testdata/appledouble/native/darwin-wrappers.c", "-o", oracle).CombinedOutput(); err != nil {
		return fmt.Errorf("native observer: %w: %s", err, out)
	}
	log, e := os.Create(filepath.Join(dir, "tests.jsonl"))
	if e != nil {
		return e
	}
	defer log.Close()
	var transcript bytes.Buffer
	profile := filepath.Join(dir, "coverage.out")
	cmd := exec.Command("go", "test", "-count=1", "-json", "-run", "^Test(Typed|Darwin|Held|Path|Quarantine|ACLIdentity|LibSystem|SandboxCapture|CaptureXattrs|XattrCapture|XattrValues|Metadata|OpenMetadata)", "-covermode=atomic", "-coverprofile="+profile, "-coverpkg=./internal/darwinabi", "./pkg/hostdata", "./pkg/hostdata/acl", "./pkg/hostdata/sandbox", "./internal/darwinabi")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "APFS_DARWIN_WRAPPERS_ORACLE="+oracle)
	cmd.Stdout = io.MultiWriter(os.Stdout, log, &transcript)
	cmd.Stderr = io.MultiWriter(os.Stderr, log)
	if e := cmd.Run(); e != nil {
		return e
	}
	functions, err := exec.Command("go", "tool", "cover", "-func="+profile).CombinedOutput()
	if err != nil {
		return fmt.Errorf("coverage diagnostics: %w: %s", err, functions)
	}
	if err := os.WriteFile(filepath.Join(dir, "functions.txt"), functions, 0600); err != nil {
		return err
	}
	fmt.Print(string(functions))
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
	coverageFiles := map[string][2]int{"internal/darwinabi/zsyscall_darwin_" + runtime.GOARCH + ".go": {}}
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
	files := []string{"scripts/verify-darwin-wrappers.go", "scripts/generate-darwin-wrappers.go", "scripts/audit-native-bindings.go", "testdata/appledouble/native/darwin-wrappers.c", "go.mod", "go.sum"}
	for _, pattern := range []string{"internal/darwinabi/*", "pkg/hostdata/*.go", "pkg/hostdata/acl/*.go", "pkg/hostdata/sandbox/*.go"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return err
		}
		if len(matches) == 0 {
			return fmt.Errorf("unmatched source %s", pattern)
		}
		files = append(files, matches...)
	}
	hashes := map[string]string{}
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
	report := map[string]any{"coverage_files": coverageFiles, "covered": covered, "statements": total, "passed_tests": passed, "source_sha256": hashes, "revision": strings.TrimSpace(string(revision)), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "go": runtime.Version(), "sdk": strings.TrimSpace(string(sdk))}
	b, e = json.MarshalIndent(report, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "coverage.json"), append(b, '\n'), 0600); e != nil {
		return e
	}
	fmt.Printf("Typed Darwin wrappers: %d/%d covered statements; %d passing test records on %s/%s\n", covered, total, passed, runtime.GOOS, runtime.GOARCH)
	return nil
}

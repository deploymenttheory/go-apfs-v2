//go:build ignore

// Verify the strict xattr API with portable and real-host tests and retain evidence.
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
	if err := verify(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func verify() error {
	dir := filepath.Join("artifacts", "strict-xattrs")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	log, err := os.Create(filepath.Join(dir, "tests.jsonl"))
	if err != nil {
		return err
	}
	defer log.Close()
	profile := filepath.Join(dir, "coverage.out")
	cmd := exec.Command("go", "test", "-count=1", "-json", "-covermode=atomic", "-coverprofile="+profile, "-run", "^TestStrictXattr", "./pkg/hostmeta")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	var transcript bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, log, &transcript)
	cmd.Stderr = io.MultiWriter(os.Stderr, log)
	if err := cmd.Run(); err != nil {
		return err
	}
	passed, listed := 0, 0
	for _, line := range bytes.Split(transcript.Bytes(), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var event struct{ Action, Test string }
		if e := json.Unmarshal(line, &event); e != nil {
			return e
		}
		if event.Action == "skip" {
			return fmt.Errorf("strict xattr test skipped: %s", event.Test)
		}
		if event.Action == "pass" && event.Test != "" {
			passed++
			if strings.HasPrefix(event.Test, "TestStrictXattrList") {
				listed++
			}
		}
	}
	if passed < 70 || listed < 36 {
		return fmt.Errorf("incomplete strict xattr suite: %d", passed)
	}
	data, err := os.ReadFile(profile)
	if err != nil {
		return err
	}
	type coverage struct{ Covered, Statements int }
	files := map[string]coverage{}
	total := coverage{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		location := fields[0]
		colon := strings.LastIndexByte(location, ':')
		if colon < 0 {
			return fmt.Errorf("invalid coverage location %q", location)
		}
		name := filepath.Base(location[:colon])
		if !strings.HasPrefix(name, "xattr_strict") || !strings.HasSuffix(name, ".go") {
			continue
		}
		statements, err := strconv.Atoi(fields[1])
		if err != nil {
			return err
		}
		hits, err := strconv.Atoi(fields[2])
		if err != nil {
			return err
		}
		v := files[name]
		v.Statements += statements
		total.Statements += statements
		if hits > 0 {
			v.Covered += statements
			total.Covered += statements
		}
		files[name] = v
	}
	if len(files) == 0 || total.Statements == 0 {
		return fmt.Errorf("no strict xattr coverage")
	}
	for name, coverage := range files {
		if (strings.HasPrefix(name, "xattr_strict_list") || name == "xattr_strict_ea.go") && (coverage.Statements == 0 || coverage.Covered*100 <= coverage.Statements*95) {
			return fmt.Errorf("%s coverage must exceed 95%%", name)
		}
	}
	sources := map[string]string{}
	names, err := filepath.Glob("pkg/hostmeta/xattr_strict*.go")
	if err != nil {
		return err
	}
	names = append(names, "scripts/verify-xattrs.go", "go.mod", "go.sum")
	for _, name := range names {
		b, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		h := sha256.Sum256(b)
		sources[filepath.ToSlash(name)] = hex.EncodeToString(h[:])
	}
	revision, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	report := map[string]any{"goos": runtime.GOOS, "goarch": runtime.GOARCH, "go": runtime.Version(), "revision": strings.TrimSpace(string(revision)), "passed_tests": passed, "listing_tests": listed, "files": files, "total": total, "source_sha256": sources}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "coverage.json"), append(b, '\n'), 0644); err != nil {
		return err
	}
	fmt.Printf("Strict xattr API: %d/%d statements (%.2f%%) on %s/%s\n", total.Covered, total.Statements, 100*float64(total.Covered)/float64(total.Statements), runtime.GOOS, runtime.GOARCH)
	if total.Covered*100 <= total.Statements*95 {
		return fmt.Errorf("strict xattr API coverage must exceed 95%%")
	}
	return nil
}

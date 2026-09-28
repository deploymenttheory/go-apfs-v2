//go:build ignore

// Retain real unit coverage and provenance for the shared AppleDouble codec.
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
	dir := "artifacts/appledouble"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	log, err := os.Create(filepath.Join(dir, "tests.jsonl"))
	if err != nil {
		return err
	}
	defer log.Close()
	var transcript bytes.Buffer
	profile := filepath.Join(dir, "coverage.out")
	cmd := exec.Command("go", "test", "-count=1", "-json", "-covermode=atomic", "-coverprofile="+profile, "./pkg/appledouble")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Stdout = io.MultiWriter(os.Stdout, log, &transcript)
	cmd.Stderr = io.MultiWriter(os.Stderr, log)
	if err := cmd.Run(); err != nil {
		return err
	}
	passed := 0
	for _, line := range bytes.Split(transcript.Bytes(), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var event struct{ Action, Test string }
		if err := json.Unmarshal(line, &event); err != nil {
			return err
		}
		if event.Action == "skip" {
			return fmt.Errorf("AppleDouble test skipped: %s", event.Test)
		}
		if event.Action == "pass" && event.Test != "" {
			passed++
		}
	}
	data, err := os.ReadFile(profile)
	if err != nil {
		return err
	}
	covered, total := 0, 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		if !strings.HasPrefix(fields[0], "github.com/deploymenttheory/go-apfs-v2/pkg/appledouble/") {
			return fmt.Errorf("unexpected coverage block %s", fields[0])
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil {
			return err
		}
		hits, err := strconv.Atoi(fields[2])
		if err != nil {
			return err
		}
		total += n
		if hits > 0 {
			covered += n
		}
	}
	files, err := filepath.Glob("pkg/appledouble/*")
	if err != nil {
		return err
	}
	files = append(files, "testdata/cli/component-links.probe.json", "scripts/verify-appledouble.go", "go.mod", "go.sum")
	files = append(files, "testdata/appledouble/native/large.ad.gz", "testdata/appledouble/native/probe.c", "scripts/verify-appledouble-native.go")
	files = append(files, "testdata/appledouble/native/names.json")
	files = append(files, "testdata/appledouble/native/records.json", "testdata/appledouble/native/list.c")
	files = append(files, "testdata/appledouble/native/quarantine-macos26.json", "testdata/appledouble/native/quarantine-application.json", "testdata/appledouble/native/quarantine.json", "testdata/appledouble/native/quarantine.c", "scripts/verify-appledouble-quarantine.go", "testdata/appledouble/native/acl-update.json", "testdata/appledouble/native/acl-external.c", "testdata/appledouble/native/acl-external.json", "testdata/appledouble/native/special.json", "testdata/appledouble/native/acl.json", "testdata/appledouble/native/acl.c", "scripts/verify-appledouble-acl.go")
	sources := map[string]string{}
	for _, name := range files {
		b, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		sources[filepath.ToSlash(name)] = hex.EncodeToString(sum[:])
	}
	if sources["testdata/cli/component-links.probe.json"] != "450b5a23661072a6de625c55e37de0af2602253f1ab71b063e889fbb71985865" {
		return fmt.Errorf("native pkgbuild fixture provenance mismatch")
	}
	revision, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	report := map[string]any{"goos": runtime.GOOS, "goarch": runtime.GOARCH, "go": runtime.Version(), "revision": strings.TrimSpace(string(revision)), "covered": covered, "statements": total, "passed_tests": passed, "source_sha256": sources}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "coverage.json"), append(b, '\n'), 0644); err != nil {
		return err
	}
	fmt.Printf("AppleDouble: %d/%d covered statements; %d passing test records on %s/%s\n", covered, total, passed, runtime.GOOS, runtime.GOARCH)
	if total == 0 || covered*100 <= total*95 || passed == 0 {
		return fmt.Errorf("AppleDouble unit coverage must exceed 95%% without skipped tests")
	}
	return nil
}

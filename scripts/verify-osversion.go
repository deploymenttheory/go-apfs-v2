//go:build ignore

// Verify explicit target selection and native detection above 95% on every host.
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
	const dir = "artifacts/osversion-coverage"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	log, err := os.Create(filepath.Join(dir, "tests.jsonl"))
	if err != nil {
		return err
	}
	var transcript bytes.Buffer
	profile := filepath.Join(dir, "coverage.out")
	cmd := cirunner.Command("go", "test", "-count=1", "-json", "-covermode=atomic", "-coverprofile="+profile, "./pkg/osversion")
	cmd.Stdout = io.MultiWriter(os.Stdout, log, &transcript)
	cmd.Stderr = os.Stderr
	if err = errors.Join(cmd.Run(), log.Close()); err != nil {
		return err
	}
	required := map[string]bool{"TestVersion": true, "TestProductCapture": true, "TestExplicitMacOSProfiles": true, "TestDetectProvider": true, "FuzzVersion": true}
	files := map[string][2]int{"pkg/osversion/version.go": {}, "pkg/osversion/macos.go": {}, "pkg/osversion/host.go": {}}
	if runtime.GOOS == "darwin" {
		required["TestDetectNative"] = true
		files["pkg/osversion/host_darwin.go"] = [2]int{}
	} else {
		required["TestDetectForeignHost"] = true
		files["pkg/osversion/host_other.go"] = [2]int{}
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
			return fmt.Errorf("unqualified osversion test %s: %s", event.Action, event.Test)
		}
		if event.Action == "pass" && event.Test != "" {
			delete(required, event.Test)
			passed++
		}
	}
	if len(required) != 0 {
		return fmt.Errorf("missing osversion suites: %v", required)
	}
	data, err := os.ReadFile(profile)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(data, []byte("mode: atomic\n")) {
		return errors.New("invalid coverage mode")
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || line == "mode: atomic" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return fmt.Errorf("invalid coverage block %q", line)
		}
		name := strings.TrimPrefix(strings.SplitN(fields[0], ":", 2)[0], "github.com/deploymenttheory/go-apfs-v2/")
		counts, exists := files[name]
		if !exists {
			return fmt.Errorf("untracked osversion source: %s", name)
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n < 0 {
			return fmt.Errorf("invalid statement count: %q", line)
		}
		hits, err := strconv.Atoi(fields[2])
		if err != nil || hits < 0 {
			return fmt.Errorf("invalid hit count: %q", line)
		}
		counts[1] += n
		if hits > 0 {
			counts[0] += n
		}
		files[name] = counts
	}
	covered, total := 0, 0
	for name, counts := range files {
		if counts[1] == 0 || counts[0]*100 <= counts[1]*95 {
			return fmt.Errorf("%s coverage must exceed 95%%: %d/%d", name, counts[0], counts[1])
		}
		covered += counts[0]
		total += counts[1]
	}
	hashes, err := evidenceaudit.HarnessSourceHashes(os.DirFS("."), []string{"pkg/osversion/*.go", "scripts/verify-osversion.go", "go.mod", "go.sum"})
	if err != nil {
		return err
	}
	revision, err := cirunner.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	report := map[string]any{"coverage_files": files, "covered": covered, "statements": total, "passed_tests": passed, "source_sha256": hashes, "revision": strings.TrimSpace(string(revision)), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "go": runtime.Version()}
	data, err = json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "coverage.json"), append(data, '\n'), 0600); err != nil {
		return err
	}
	if err = evidenceaudit.Coverage(os.DirFS("."), os.DirFS("artifacts"), "osversion-coverage", strings.TrimSpace(string(revision)), runtime.GOOS); err != nil {
		return err
	}
	fmt.Printf("OS version profiles: %d/%d statements; %d passing test records on %s/%s\n", covered, total, passed, runtime.GOOS, runtime.GOARCH)
	return nil
}

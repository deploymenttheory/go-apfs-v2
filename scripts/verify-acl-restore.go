//go:build ignore

// Verify portable ACL restoration separately from unrelated host-specific code.
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
	const dir = "artifacts/acl-restore"
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
	cmd := exec.Command("go", "test", "-count=1", "-json", "-run", "^(Test.*RestoreACL|Test.*ACLAttributes|FuzzRestoreACL|FuzzACLAttributes|Test.*Chmod|FuzzDarwinChmod|TestWriteSecurityFlags)", "-covermode=atomic", "-coverprofile="+profile, "./pkg/hostmeta", "./pkg/hfsplus")
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
			return fmt.Errorf("ACL restoration test skipped: %s", event.Test)
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
	coverageFiles := map[string][2]int{"pkg/hostmeta/acl_restore.go": {}, "pkg/hostmeta/acl_attributes.go": {}, "pkg/hostmeta/acl_chmod.go": {}, "pkg/hostmeta/acl_chmod_properties.go": {}, "pkg/hfsplus/writer_attribute_flags.go": {}}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		file := strings.TrimPrefix(strings.SplitN(fields[0], ":", 2)[0], "github.com/deploymenttheory/go-apfs-v2/")
		counts, tracked := coverageFiles[file]
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
		return fmt.Errorf("ACL restoration coverage must exceed 95%%: %d/%d", covered, total)
	}
	files := []string{"pkg/hostmeta/acl_chmod_properties.go", "pkg/hostmeta/acl_chmod_properties_test.go", "testdata/appledouble/native/acl-chmod-properties.c", "testdata/appledouble/native/acl-chmod-properties.json.gz", "pkg/hostmeta/acl_restore_nonowner_test.go", "testdata/appledouble/native/acl-nonowner.c", "testdata/appledouble/native/acl-nonowner.json.gz", "pkg/hfsplus/writer.go", "pkg/hfsplus/writer_attribute_flags.go", "pkg/hfsplus/writer_security_test.go", "pkg/hfsplus/writer_test.go", "pkg/hfsplus/writer_hardlink_test.go", "pkg/hostmeta/acl_chmod.go", "pkg/hostmeta/acl_chmod_test.go", "testdata/appledouble/native/acl-chmod.c", "testdata/appledouble/native/acl-chmod.json.gz", "pkg/hostmeta/acl_attributes.go", "pkg/hostmeta/acl_attributes_test.go", "testdata/appledouble/native/acl-attributes.c", "testdata/appledouble/native/acl-attributes.json.gz", "go.mod", "go.sum", "pkg/hostmeta/acl_restore.go", "pkg/hostmeta/acl_restore_test.go", "pkg/hostmeta/acl_restore_native_test.go", "pkg/appledouble/acl.go", "pkg/appledouble/acl_external.go", "pkg/appledouble/acl_update.go", "pkg/appledouble/filesec.go", "testdata/appledouble/native/acl-restore.c", "testdata/appledouble/native/filesec.c", "testdata/appledouble/native/acl-restore.json.gz", "scripts/verify-acl-restore.go", "scripts/verify-appledouble-filesec.go"}
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
	report := map[string]any{"coverage_files": coverageFiles, "covered": covered, "statements": total, "passed_tests": passed, "source_sha256": hashes, "revision": strings.TrimSpace(string(revision)), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "go": runtime.Version()}
	b, e = json.MarshalIndent(report, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "coverage.json"), append(b, '\n'), 0600); e != nil {
		return e
	}
	fmt.Printf("ACL restoration: %d/%d covered statements; %d passing test records on %s/%s\n", covered, total, passed, runtime.GOOS, runtime.GOARCH)
	return nil
}

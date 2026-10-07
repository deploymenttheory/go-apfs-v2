//go:build ignore

// Verify image ACL restoration independently of unrelated image code.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func main() {
	if e := verify(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func verify() error {
	const dir = "artifacts/image-acl-coverage"
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
	cmd := cirunner.Command("go", "test", "-count=1", "-json", "-run", "^TestImageACLRestore", "-covermode=atomic", "-coverprofile="+profile, "-coverpkg=./internal/imageacl,./pkg/apfswrite,./pkg/hfsplus", "./internal/imageacl", "./pkg/apfswrite", "./pkg/hfsplus", "./internal/testutil/imagerestore")
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
			return fmt.Errorf("Image ACL restoration test skipped: %s", event.Test)
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
	coverageFiles := map[string][2]int{"internal/imageacl/tree.go": {}, "internal/imageacl/restore.go": {}, "pkg/apfswrite/acl_restore.go": {}, "pkg/hfsplus/writer_acl_restore.go": {}}
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
		return fmt.Errorf("Image ACL restoration coverage must exceed 95%%: %d/%d", covered, total)
	}
	if passed < 2336 {
		return fmt.Errorf("incomplete mode tests: %d", passed)
	}
	files := []string{"internal/imageacl/tree.go", "internal/imageacl/restore.go", "internal/imageacl/restore_test.go", "pkg/apfswrite/acl_restore.go", "pkg/apfswrite/acl_restore_test.go", "pkg/apfswrite/file.go", "pkg/apfswrite/writer.go", "pkg/apfswrite/mode.go", "pkg/apfswrite/root.go", "pkg/apfswrite/xattr_streams.go", "pkg/hfsplus/writer_acl_restore.go", "pkg/hfsplus/writer_acl_restore_test.go", "pkg/hfsplus/writer.go", "pkg/hfsplus/writer_mode.go", "pkg/hfsplus/writer_attribute_flags.go", "pkg/hfsplus/hardlink_writer.go", "internal/unixmode/mode.go", "pkg/hostdata/acl/acl_restore.go", "pkg/hostdata/image_security.go", "pkg/appledouble/acl_update.go", "pkg/appledouble/filesec.go", "pkg/appledouble/acl.go", "pkg/appledouble/acl_external.go", "internal/testutil/imagerestore/fixtures.go", "internal/testutil/imagerestore/restore_test.go", "internal/testutil/imagesecurity/fixtures.go", "scripts/verify-image-acl-restore.go", "scripts/verify-image-acl-coverage.go", "testdata/appledouble/native/image-acl-restore.c", "testdata/appledouble/native/filesec.c", "testdata/appledouble/native/image-acl-restore.json.gz", "go.mod", "go.sum"}
	hashes := map[string]string{}
	for _, path := range files {
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		h := sha256.Sum256(b)
		hashes[path] = hex.EncodeToString(h[:])
	}
	revision, e := cirunner.Command("git", "rev-parse", "HEAD").Output()
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
	fmt.Printf("Image ACL restoration: %d/%d covered statements; %d passing test records on %s/%s\n", covered, total, passed, runtime.GOOS, runtime.GOARCH)
	return nil
}

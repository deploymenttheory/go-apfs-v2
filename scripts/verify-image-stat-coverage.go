//go:build ignore

// Verify image stat restoration independently of unrelated host code.
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
	const dir = "artifacts/image-stat-coverage"
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
	cmd := cirunner.Command("go", "test", "-count=1", "-json", "-run", "^(TestImageStat|TestImageMetadata)", "-covermode=atomic", "-coverprofile="+profile, "-coverpkg=./internal/imageacl,./pkg/apfswrite,./pkg/apfs,./pkg/hfsplus", "./internal/imageacl", "./internal/testutil/imagestat", "./pkg/apfs", "./pkg/hfsplus", "./pkg/apfswrite")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Stdout = io.MultiWriter(os.Stdout, log, &transcript)
	if e := cmd.RunWithDiagnostics(log.Name() + ".stderr.log"); e != nil {
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
			return fmt.Errorf("Image stat restoration test skipped: %s", event.Test)
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
	coverageFiles := map[string][2]int{"internal/imageacl/stat.go": {}, "pkg/apfswrite/stat_copy.go": {}, "pkg/hfsplus/writer_stat_copy.go": {}, "pkg/apfs/metadata.go": {}, "pkg/hfsplus/metadata.go": {}}
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
		return fmt.Errorf("Image stat restoration coverage must exceed 95%%: %d/%d", covered, total)
	}
	if passed < 618 {
		return fmt.Errorf("incomplete image stat restoration tests: %d", passed)
	}
	files := []string{"pkg/apfs/volume.go", "pkg/apfswrite/lookup_case_test.go", "pkg/hostdata/image_metadata.go", "pkg/apfs/metadata.go", "pkg/apfs/metadata_test.go", "pkg/hfsplus/metadata.go", "pkg/hfsplus/metadata_test.go", "internal/testutil/imagestat/metadata_test.go", "internal/imageacl/stat.go", "pkg/apfswrite/stat_copy.go", "pkg/hfsplus/writer_stat_copy.go", "internal/imageacl/stat_test.go", "internal/imageacl/tree.go", "pkg/apfswrite/acl_restore.go", "pkg/hfsplus/writer_acl_restore.go", "pkg/hostdata/image_stat.go", "pkg/hostdata/stat_copy.go", "pkg/hostdata/stat_flags.go", "internal/bsdflags/flags.go", "internal/inodetime/time.go", "pkg/apfswrite/file.go", "pkg/apfswrite/writer.go", "pkg/hfsplus/writer.go", "internal/testutil/imagestat/fixtures.go", "internal/testutil/imagestat/fixtures_test.go", "internal/testutil/imagesecurity/fixtures.go", "internal/testutil/statcopy/oracle.go", "scripts/verify-image-security.go", "scripts/verify-image-stat-coverage.go", "testdata/appledouble/native/image-stat.c", "testdata/appledouble/native/stat-copy.c", "testdata/appledouble/native/image-security.c", "testdata/appledouble/native/security-copy.c", "testdata/appledouble/native/image-stat.json.gz", "go.mod", "go.sum"}
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
	fmt.Printf("Image stat restoration: %d/%d covered statements; %d passing test records on %s/%s\n", covered, total, passed, runtime.GOOS, runtime.GOARCH)
	return nil
}

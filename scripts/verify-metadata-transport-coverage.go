//go:build ignore

// Verify production carrier, capture, extraction and repacking integration.
package main

import (
	"bytes"
	"encoding/json"
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
	const dir = "artifacts/metadata-transport-coverage"
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
	cmd := exec.Command("go", "test", "-count=1", "-json", "-run", "^(TestCarrier|TestCaptureXattrs|TestLibSystem|TestRecordAttribute|TestNativeBaseline|TestOpenWalk|TestLazyCarrier|TestNodeAndValue|TestValue|TestXattrValue|TestVolumeXattrValues|TestStreamedValues|TestOpenEntryTree|TestHFSValues|TestProjection|TestQuarantineCapture|TestQuarantineFile|TestACLIdentityCapture)", "-covermode=atomic", "-coverprofile="+profile, "-coverpkg=./pkg/metatransport,./pkg/hostmeta,./internal/hostwalk,./internal/tools,./pkg/apfs,./pkg/apfswrite,./pkg/hfsplus,./internal/decmpfs", "./pkg/metatransport", "./pkg/hostmeta", "./internal/hostwalk", "./internal/tools", "./pkg/apfs", "./pkg/apfswrite", "./pkg/hfsplus", "./internal/decmpfs")
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
			return fmt.Errorf("Metadata transport test skipped: %s", event.Test)
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
	coverageFiles := map[string][2]int{"pkg/metatransport/carrier.go": {}, "pkg/metatransport/attributes.go": {}, "pkg/metatransport/values.go": {}, "internal/hostwalk/open.go": {}, "pkg/apfs/xattr_values.go": {}, "pkg/apfswrite/values.go": {}, "pkg/hostmeta/xattr_capture.go": {}, "internal/hostwalk/carrier.go": {}, "internal/tools/extract_carrier.go": {}, "internal/tools/extract_projection.go": {}}
	coverageFiles["pkg/hostmeta/xattr_capture_path_"+runtime.GOOS+".go"] = [2]int{}
	coverageFiles["pkg/hfsplus/writer_values.go"] = [2]int{}
	coverageFiles["pkg/hfsplus/attribute_values.go"] = [2]int{}
	coverageFiles["pkg/hostmeta/filetime.go"] = [2]int{}
	coverageFiles["pkg/hostmeta/file_times.go"] = [2]int{}
	coverageFiles["internal/decmpfs/carrier_storage.go"] = [2]int{}
	coverageFiles["internal/tools/extract_projection_readback.go"] = [2]int{}
	coverageFiles["pkg/hostmeta/quarantine_capture.go"] = [2]int{}
	for _, file := range []string{"pkg/hostmeta/acl_identity_capture.go", "pkg/hostmeta/quarantine_file.go", "pkg/hostmeta/resource_fork.go", "pkg/hostmeta/xattr_values.go", "pkg/metatransport/native_values.go", "internal/hostwalk/native_values.go"} {
		coverageFiles[file] = [2]int{}
	}
	if runtime.GOOS == "darwin" {
		coverageFiles["pkg/hostmeta/quarantine_capture_darwin.go"] = [2]int{}
		coverageFiles["pkg/hostmeta/acl_identity_capture_darwin.go"] = [2]int{}
		coverageFiles["pkg/hostmeta/quarantine_file_darwin.go"] = [2]int{}
		coverageFiles["pkg/hostmeta/resource_fork_darwin.go"] = [2]int{}
	} else {
		coverageFiles["pkg/hostmeta/quarantine_capture_other.go"] = [2]int{}
		coverageFiles["pkg/hostmeta/acl_identity_capture_other.go"] = [2]int{}
		coverageFiles["pkg/hostmeta/quarantine_file_other.go"] = [2]int{}
		coverageFiles["pkg/hostmeta/resource_fork_other.go"] = [2]int{}
	}
	if runtime.GOOS == "linux" {
		coverageFiles["pkg/hostmeta/access_time_linux.go"] = [2]int{}
		coverageFiles["pkg/hostmeta/xattr_values_bound_linux.go"] = [2]int{}
	} else {
		coverageFiles["pkg/hostmeta/xattr_values_bound_other.go"] = [2]int{}
	}
	if runtime.GOOS == "windows" {
		coverageFiles["pkg/hostmeta/creation_time_windows.go"] = [2]int{}
		coverageFiles["pkg/hostmeta/access_time_windows.go"] = [2]int{}
	}
	if runtime.GOOS == "darwin" {
		coverageFiles["pkg/hostmeta/libsystem_xattr_darwin.go"] = [2]int{}
	} else {
		coverageFiles["pkg/hostmeta/xattr_capture_other.go"] = [2]int{}
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
		return fmt.Errorf("Metadata transport coverage must exceed 95%%: %d/%d", covered, total)
	}
	if passed < 80 {
		return fmt.Errorf("incomplete image stat restoration tests: %d", passed)
	}
	files := []string{"scripts/verify-metadata-transport-coverage.go", "scripts/verify-metadata-transport.go", "go.mod", "go.sum"}
	for _, pattern := range []string{"pkg/hostmeta/acl_identity_capture*.go", "pkg/hostmeta/quarantine_file*.go", "pkg/hostmeta/resource_fork*.go", "pkg/hostmeta/xattr_values*.go", "internal/hostwalk/native_values*.go", "pkg/hfsplus/root_values_test.go", "testdata/appledouble/native/acl-identity*.c", "testdata/appledouble/native/acl-identity-capture.json.gz", "scripts/verify-acl-identity-capture-native.go"} {
		files = append(files, pattern)
	}
	for _, pattern := range []string{"pkg/metatransport/*.go", "pkg/hostmeta/xattr_capture*.go", "pkg/hostmeta/libsystem_xattr*.go", "internal/hostwalk/carrier*.go", "internal/hostwalk/open*.go", "pkg/apfs/xattr_values*.go", "pkg/apfswrite/values*.go", "pkg/hfsplus/*values*.go", "pkg/hfsplus/values_test.go", "pkg/hfsplus/writer.go", "pkg/hfsplus/validate.go", "pkg/hostmeta/filetime*.go", "pkg/hostmeta/quarantine_capture*.go", "internal/decmpfs/*.go", "pkg/hostmeta/file_times*.go", "pkg/hostmeta/access_time*.go", "pkg/hostmeta/creation_time*.go", "internal/tools/extract_carrier*.go", "internal/tools/extract_projection*.go"} {
		files = append(files, pattern)
	}
	files = append(files, "internal/evidenceaudit/*.go")
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
	fmt.Printf("Metadata transport: %d/%d covered statements; %d passing test records on %s/%s\n", covered, total, passed, runtime.GOOS, runtime.GOARCH)
	return nil
}

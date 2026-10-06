//go:build ignore

// Qualify the complete portable carrier package and produce every non-fault
// regular-file operation case from each retained macOS profile for native readback.
package main

import (
	"bufio"
	"bytes"
	"context"
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
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"
)

const artifact = "artifacts/carrier-recompression-portable"

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	out, e := filepath.Abs(artifact)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(out, 0755); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	log, e := os.Create(filepath.Join(out, "tests.jsonl"))
	if e != nil {
		return e
	}
	var transcript bytes.Buffer
	commands := [][]string{{"test", "-count=1", "-json", "-covermode=atomic", "-coverprofile=" + filepath.Join(out, "coverage.out"), "./pkg/metatransport", "./pkg/recompression"}, {"test", "-count=1", "-json", "-run=^TestCarrierRecompressionNativeProfiles$", "./acceptance"}}
	for _, args := range commands {
		cmd := exec.CommandContext(ctx, "go", args...)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "APFS_CARRIER_RECOMPRESSION_OUTPUT="+out)
		cmd.Stdout = io.MultiWriter(log, &transcript)
		cmd.Stderr = os.Stderr
		if e = cmd.Run(); e != nil {
			return errors.Join(e, log.Close())
		}
	}
	if e = log.Close(); e != nil {
		return e
	}
	passed, cases, packages := 0, 0, 0
	top := false
	scanner := bufio.NewScanner(&transcript)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var event struct{ Action, Test string }
		if e = json.Unmarshal(scanner.Bytes(), &event); e != nil {
			return e
		}
		if event.Action == "skip" || event.Action == "fail" {
			return fmt.Errorf("qualification %s: %s", event.Action, event.Test)
		}
		if event.Action == "pass" {
			if event.Test == "" {
				packages++
			} else {
				passed++
			}
			if event.Test == "TestCarrierRecompressionNativeProfiles" {
				top = true
			}
			if strings.HasPrefix(event.Test, "TestCarrierRecompressionNativeProfiles/") && strings.Contains(event.Test, "/case-") {
				cases++
			}
		}
	}
	if e = scanner.Err(); e != nil {
		return e
	}
	if !top || cases != 648 || packages != 3 {
		return fmt.Errorf("incomplete carrier qualification: top=%v native cases=%d packages=%d", top, cases, packages)
	}
	b, e := os.ReadFile(filepath.Join(out, "coverage.out"))
	if e != nil {
		return e
	}
	files := map[string][2]int{}
	packageCounts := map[string][2]int{}
	allCovered, allStatements := 0, 0
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		location, _, ok := strings.Cut(fields[0], ":")
		if !ok {
			return errors.New("malformed profile")
		}
		name := strings.TrimPrefix(location, "github.com/deploymenttheory/go-apfs-v2/")
		n, e := strconv.Atoi(fields[1])
		if e != nil {
			return e
		}
		hits, e := strconv.Atoi(fields[2])
		if e != nil {
			return e
		}
		allStatements += n
		if hits > 0 {
			allCovered += n
		}
		if strings.HasPrefix(name, "pkg/metatransport/") || strings.HasPrefix(name, "pkg/recompression/") {
			v := files[name]
			v[1] += n
			if hits > 0 {
				v[0] += n
			}
			files[name] = v
			packageName := strings.TrimSuffix(name, "/"+filepath.Base(name))
			p := packageCounts[packageName]
			p[1] += n
			if hits > 0 {
				p[0] += n
			}
			packageCounts[packageName] = p

		}
	}
	mandatory := 0
	covered, total := 0, 0
	for _, packageName := range []string{"pkg/metatransport", "pkg/recompression"} {
		expected, e := filepath.Glob(packageName + "/*.go")
		if e != nil {
			return e
		}
		for _, path := range expected {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			mandatory++
			path = filepath.ToSlash(path)
			v, ok := files[path]
			if !ok || v[1] == 0 || v[0]*100 <= v[1]*95 {
				return fmt.Errorf("%s coverage must exceed 95%%: %d/%d", path, v[0], v[1])
			}
			covered += v[0]
			total += v[1]
		}
		v := packageCounts[packageName]
		if v[1] == 0 || v[0]*100 <= v[1]*95 {
			return fmt.Errorf("complete %s package coverage must exceed 95%%: %d/%d", packageName, v[0], v[1])
		}
	}
	if mandatory < 6 || len(files) != mandatory {
		return errors.New("incomplete recompression and transport production coverage inventory")
	}
	if covered != allCovered || total != allStatements {
		return errors.New("incomplete package coverage totals")
	}
	hashes, e := evidenceaudit.SourceHashes(os.DirFS("."), []string{"pkg/metatransport/*.go", "pkg/recompression/*.go", "pkg/compression/decmpfs/*.go", "internal/decmpfs/*.go", "pkg/hostdata/compression*.go", "pkg/osversion/*.go", "pkg/apfswrite/*.go", "pkg/hfsplus/*.go", "internal/hostwalk/*.go", "acceptance/carrier_recompression_test.go", "scripts/verify-carrier-recompression*.go", "testdata/appledouble/native/carrier-recompression-readback.c", "testdata/appledouble/native/compression-operation*.json.gz", "scripts/capture-recompression-access.go", "testdata/appledouble/native/recompression-access*.json.gz", "testdata/appledouble/native/recompression-access.c", "testdata/appledouble/native/recompression-open.c", "testdata/appledouble/native/recompression-access-source/*", ".github/workflows/carrier-recompression.yml", "go.mod", "go.sum"})
	if e != nil {
		return e
	}
	revision, e := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	if e != nil {
		return e
	}
	report := map[string]any{"revision": strings.TrimSpace(string(revision)), "source_sha256": hashes, "go": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "native_cases": cases, "image_count": 9, "image_entries": 666, "passed_tests": passed, "covered": covered, "statements": total, "coverage_files": files, "package_coverage": packageCounts, "package_covered": allCovered, "package_statements": allStatements}
	b, e = json.MarshalIndent(report, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(out, "coverage.json"), b, 0644); e != nil {
		return e
	}
	if e = evidenceaudit.Coverage(os.DirFS("."), os.DirFS("artifacts"), "carrier-recompression-portable", strings.TrimSpace(string(revision)), runtime.GOOS); e != nil {
		return e
	}
	fmt.Printf("648 native operation cases; 9 images with 666 entries; per-file and both complete packages %d/%d; combined coverage %d/%d\n", covered, total, allCovered, allStatements)
	return nil
}

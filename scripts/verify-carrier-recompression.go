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

	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
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
	commands := [][]string{{"test", "-count=1", "-json", "-covermode=atomic", "-coverprofile=" + filepath.Join(out, "coverage.out"), "./pkg/metatransport", "./pkg/recompression", "./pkg/authorization"}, {"test", "-count=1", "-json", "-run=^TestCarrierRecompressionNativeProfiles$", "./acceptance"}}
	for _, args := range commands {
		cmd := cirunner.CommandContext(ctx, "go", args...)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "APFS_CARRIER_RECOMPRESSION_OUTPUT="+out)
		cmd.Stdout = io.MultiWriter(log, &transcript)
		cmd.Stderr = os.Stderr
		if e = cmd.Run(); e != nil {
			reportCommandFailure(args, transcript.Bytes())
			return errors.Join(e, log.Close())
		}
	}
	if e = log.Close(); e != nil {
		return e
	}
	passed, cases, compositions, packages := 0, 0, 0, 0
	unitCompositions := make(map[string]bool)
	for _, count := range []int{2, 3} {
		for _, linked := range []bool{false, true} {
			for _, outcome := range []string{"recompress", "admission-denied", "cancel-publication", "stale-generation", "failure-after-rename", "cancel-after-rename", "cancel-after-publication"} {
				unitCompositions[fmt.Sprintf("TestCarrierReplacementRecompressionComposition/names-%d/linked-%t/%s", count, linked, outcome)] = false
			}
			unitCompositions[fmt.Sprintf("TestCarrierInPlaceEditedAliases/names-%d/linked-%t", count, linked)] = false
		}
	}
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
			if seen, required := unitCompositions[event.Test]; required {
				if seen {
					return fmt.Errorf("duplicate carrier composition: %s", event.Test)
				}
				unitCompositions[event.Test] = true
			}
			if event.Test == "" {
				packages++
			} else {
				passed++
			}
			if event.Test == "TestCarrierRecompressionNativeProfiles" {
				top = true
			}
			if strings.HasPrefix(event.Test, "TestCarrierRecompressionNativeProfiles/") && strings.Contains(event.Test, "/composition-") {
				compositions++
			}
			if strings.HasPrefix(event.Test, "TestCarrierRecompressionNativeProfiles/") && strings.Contains(event.Test, "/case-") {
				cases++
			}
		}
	}
	if e = scanner.Err(); e != nil {
		return e
	}
	for name, seen := range unitCompositions {
		if !seen {
			return fmt.Errorf("required carrier composition missing: %s", name)
		}
	}
	if !top || cases != 648 || compositions != 72 || packages != 4 {
		return fmt.Errorf("incomplete carrier qualification: top=%v native cases=%d compositions=%d packages=%d", top, cases, compositions, packages)
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
		if strings.HasPrefix(name, "pkg/metatransport/") || strings.HasPrefix(name, "pkg/recompression/") || strings.HasPrefix(name, "pkg/authorization/") {
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
	for _, packageName := range []string{"pkg/metatransport", "pkg/recompression", "pkg/authorization"} {
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
		return errors.New("incomplete recompression, transport and authorization production coverage inventory")
	}
	if covered != allCovered || total != allStatements {
		return errors.New("incomplete package coverage totals")
	}
	hashes, e := evidenceaudit.HarnessSourceHashes(os.DirFS("."), []string{"pkg/metatransport/*.go", "pkg/recompression/*.go", "pkg/authorization/*.go", "pkg/compression/decmpfs/*.go", "internal/decmpfs/*.go", "pkg/hostdata/*.go", "pkg/osversion/*.go", "pkg/apfswrite/*.go", "pkg/hfsplus/*.go", "internal/hostwalk/*.go", "acceptance/carrier_recompression_test.go", "acceptance/carrier_replacement_test.go", "scripts/verify-carrier-recompression*.go", "testdata/appledouble/native/carrier-recompression-readback.c", "testdata/appledouble/native/compression-operation*.json.gz", "scripts/capture-recompression-access.go", "testdata/appledouble/native/recompression-access*.json.gz", "testdata/appledouble/native/recompression-access.c", "testdata/appledouble/native/recompression-open.c", "testdata/appledouble/native/recompression-access-source/*", ".github/workflows/carrier-recompression.yml", "go.mod", "go.sum"})
	if e != nil {
		return e
	}
	revision, e := cirunner.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	if e != nil {
		return e
	}
	report := map[string]any{"revision": strings.TrimSpace(string(revision)), "source_sha256": hashes, "go": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "native_cases": cases, "replacement_compositions": compositions, "image_count": 9, "image_entries": 846, "passed_tests": passed, "covered": covered, "statements": total, "coverage_files": files, "package_coverage": packageCounts, "package_covered": allCovered, "package_statements": allStatements}
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
	fmt.Printf("648 native operation cases; 9 images with 846 entries; per-file and all three complete packages %d/%d; combined coverage %d/%d\n", covered, total, allCovered, allStatements)
	return nil
}

// Keep full JSON evidence on disk while putting a bounded, useful diagnostic in
// the job log. In particular, go test -json normally sends assertion messages
// only to stdout, so returning its exit status alone hides the failing cases.
func reportCommandFailure(args []string, transcript []byte) {
	fmt.Fprintf(os.Stderr, "qualification command failed: go %s\ncomplete test transcript: %s/tests.jsonl\n", strings.Join(args, " "), artifact)
	type event struct{ Action, Package, Test, Output, OutputType string }
	failed := map[string]bool{}
	lines := bytes.Split(transcript, []byte{'\n'})
	for _, line := range lines {
		var v event
		if json.Unmarshal(line, &v) == nil && v.Action == "fail" {
			failed[v.Package+"/"+v.Test] = true
		}
	}
	count, remaining := 0, 32<<10
	for _, line := range lines {
		var v event
		if json.Unmarshal(line, &v) != nil || v.Output == "" || v.OutputType == "frame" {
			continue
		}
		if v.Action != "build-output" && (v.Action != "output" || (!failed[v.Package+"/"+v.Test] && v.Test != "")) {
			continue
		}
		if count == 80 || remaining == 0 {
			fmt.Fprintln(os.Stderr, "additional diagnostics retained in the complete test transcript")
			return
		}
		message := v.Package
		if v.Test != "" {
			message += "/" + v.Test
		}
		message += ": " + v.Output
		if len(message) > remaining {
			message = message[:remaining]
		}
		fmt.Fprint(os.Stderr, message)
		if !strings.HasSuffix(message, "\n") {
			fmt.Fprintln(os.Stderr)
		}
		remaining -= len(message)
		count++
	}
	if count == 0 {
		fmt.Fprintln(os.Stderr, "no assertion output was produced; inspect command diagnostics and the complete transcript")
	}
}

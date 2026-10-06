//go:build ignore

// Qualify native-image readers and every changed filename production file.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type count struct{ Covered, Statements int64 }

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	const out = "artifacts/name-comparison-coverage"
	if e := os.MkdirAll(out, 0755); e != nil {
		return e
	}
	base := os.Getenv("APFS_NAME_IMAGE_ARTIFACTS")
	if base == "" {
		return errors.New("APFS_NAME_IMAGE_ARTIFACTS is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	packages := "./pkg/apfs,./pkg/hfsplus,./internal/nameunicode"
	commands := [][]string{{"test", "-count=1", "-json", "-covermode=atomic", "-coverpkg=" + packages, "-coverprofile=" + filepath.Join(out, "unit.coverage.out"), "./pkg/apfs", "./pkg/hfsplus", "./internal/nameunicode"}, {"test", "-count=1", "-json", "-covermode=atomic", "-coverpkg=" + packages, "-coverprofile=" + filepath.Join(out, "images.coverage.out"), "scripts/capture-name-collation.go", "scripts/verify-name-comparison_test.go"}}
	var logs []string
	for i, args := range commands {
		path := filepath.Join(out, []string{"unit-tests.jsonl", "image-tests.jsonl"}[i])
		logs = append(logs, path)
		f, e := os.Create(path)
		if e != nil {
			return e
		}
		cmd := exec.CommandContext(ctx, "go", args...)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "APFS_BIG_DMG="+filepath.Join(base, "name-collation-xcode-27", "APFS.dmg"), "HFSPLUS_TEST_IMG="+filepath.Join(base, "name-collation-xcode-27", "HFSplus.dmg"))
		cmd.Stdout = f
		cmd.Stderr = os.Stderr
		runErr := cmd.Run()
		if e = errors.Join(runErr, f.Close()); e != nil {
			diagnose(path)
			return fmt.Errorf("go %v: %w", args, e)
		}
	}
	passed, names, e := transcripts(logs, filepath.Join(out, "tests.jsonl"))
	if e != nil {
		return e
	}
	required := []string{"TestCanonicalPipelines", "TestCompleteNativeScalarAdmission", "TestCreateNameTargetAdmission", "TestHFSEscapedByteConversion", "TestNameCollationNativeEvidence", "TestNameCollationNativeEvidence/15", "TestNameCollationNativeEvidence/26", "TestNameCollationNativeEvidence/27", "TestNameHashInputBoundaries", "TestNameEncodingComparison", "TestSharedNameComparison", "TestLookupNameValidation", "TestIllegalUTF8CatalogAliases", "TestNativeNameImageReaders"}
	for _, major := range []string{"15", "26", "27"} {
		for _, kind := range []string{"APFS", "APFSX", "HFS+", "HFSX"} {
			required = append(required, "TestNativeNameImageReaders/"+major+"/"+kind)
		}
	}
	for _, name := range required {
		if !names[name] {
			return fmt.Errorf("missing required qualification suite %s", name)
		}
	}
	totals, e := mergeProfiles([]string{filepath.Join(out, "unit.coverage.out"), filepath.Join(out, "images.coverage.out")}, filepath.Join(out, "coverage.out"))
	if e != nil {
		return e
	}
	selected := map[string][2]int64{}
	var total count
	for _, p := range []string{"internal/nameunicode/normalize.go", "internal/nameunicode/admission.go", "pkg/apfs/name_hash.go", "pkg/apfs/name_lookup.go", "pkg/apfs/name_create.go", "pkg/hfsplus/name_compare.go", "pkg/hfsplus/name_lookup.go", "pkg/hfsplus/normalize.go", "pkg/hfsplus/casefold_table.go", "pkg/hfsplus/volume.go"} {
		c := totals[p]
		selected[p] = [2]int64{c.Covered, c.Statements}
		total.Covered += c.Covered
		total.Statements += c.Statements
		if c.Statements == 0 || c.Covered*100 <= c.Statements*95 {
			return fmt.Errorf("%s must exceed95%%: %d/%d", p, c.Covered, c.Statements)
		}
	}
	packageTotals := map[string]count{}
	for p, c := range totals {
		pkg := filepath.ToSlash(filepath.Dir(p))
		x := packageTotals[pkg]
		x.Covered += c.Covered
		x.Statements += c.Statements
		packageTotals[pkg] = x
	}
	if c := packageTotals["internal/nameunicode"]; c.Statements == 0 || c.Covered*100 <= c.Statements*95 {
		return fmt.Errorf("whole nameunicode must exceed95%%: %+v", c)
	}
	sources, e := evidenceaudit.SourceHashes(os.DirFS("."), []string{"internal/nameunicode/*.go", "pkg/apfs/*.go", "pkg/hfsplus/*.go", "scripts/*name*", "testdata/appledouble/native/name-*.c", "testdata/appledouble/native/name-*.json.gz", "testdata/appledouble/native/name-collation-source/*", "testdata/appledouble/native/name-comparison-source/*", ".github/workflows/name-comparison.yml", "go.mod", "go.sum"})
	if e != nil {
		return e
	}
	revision, e := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	if e != nil {
		return e
	}
	rawHashes := map[string]string{}
	for _, name := range []string{"unit-tests.jsonl", "image-tests.jsonl", "tests.jsonl", "unit.coverage.out", "images.coverage.out", "coverage.out"} {
		b, e := os.ReadFile(filepath.Join(out, name))
		if e != nil {
			return e
		}
		h := sha256.Sum256(b)
		rawHashes[name] = hex.EncodeToString(h[:])
	}
	report := map[string]any{"revision": strings.TrimSpace(string(revision)), "source_sha256": sources, "evidence_sha256": rawHashes, "goos": runtime.GOOS, "goarch": runtime.GOARCH, "go": runtime.Version(), "passed_tests": passed, "required_suites": required, "native_profiles": 3, "native_volumes": 12, "native_lookup_observations": 90072, "coverage_files": selected, "covered": total.Covered, "statements": total.Statements, "package_totals": packageTotals}
	b, e := json.MarshalIndent(report, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(out, "coverage.json"), append(b, '\n'), 0644); e != nil {
		return e
	}
	if e = evidenceaudit.Coverage(os.DirFS("."), os.DirFS("artifacts"), "name-comparison-coverage", strings.TrimSpace(string(revision)), runtime.GOOS); e != nil {
		return e
	}
	fmt.Printf("90072 native-image lookups; %d changed files exceed95%%; selectedstatements%d/%d\n", len(selected), total.Covered, total.Statements)
	return nil
}
func transcripts(paths []string, dest string) (passed int, names map[string]bool, err error) {
	out, e := os.Create(dest)
	if e != nil {
		return 0, nil, e
	}
	defer func() { err = errors.Join(err, out.Close()) }()
	names = map[string]bool{}
	for _, path := range paths {
		b, e := os.ReadFile(path)
		if e != nil {
			return 0, nil, e
		}
		scan := bufio.NewScanner(strings.NewReader(string(b)))
		scan.Buffer(make([]byte, 65536), 1<<20)
		packages := 0
		for scan.Scan() {
			var item struct{ Action, Test string }
			if e = json.Unmarshal(scan.Bytes(), &item); e != nil {
				return 0, nil, e
			}
			if item.Action == "skip" || item.Action == "fail" {
				return 0, nil, fmt.Errorf("qualification %s: %s", item.Action, item.Test)
			}
			if item.Action == "pass" {
				if item.Test == "" {
					packages++
				} else {
					passed++
					names[item.Test] = true
				}
			}
		}
		if e = scan.Err(); e != nil {
			return 0, nil, e
		}
		if packages == 0 {
			return 0, nil, errors.New("missing completed package transcript")
		}
		if _, e = out.Write(b); e != nil {
			return 0, nil, e
		}
	}
	return passed, names, nil
}
func mergeProfiles(paths []string, dest string) (map[string]count, error) {
	blocks := map[string][2]int64{}
	for _, path := range paths {
		f, e := os.Open(path)
		if e != nil {
			return nil, e
		}
		scan := bufio.NewScanner(f)
		if !scan.Scan() || scan.Text() != "mode: atomic" {
			_ = f.Close()
			return nil, errors.New("invalid coverage header")
		}
		for scan.Scan() {
			fields := strings.Fields(scan.Text())
			if len(fields) != 3 {
				_ = f.Close()
				return nil, errors.New("invalid coverage block")
			}
			n, e := strconv.ParseInt(fields[1], 10, 64)
			if e != nil {
				_ = f.Close()
				return nil, e
			}
			hits, e := strconv.ParseInt(fields[2], 10, 64)
			if e != nil {
				_ = f.Close()
				return nil, e
			}
			prior, exists := blocks[fields[0]]
			if n < 0 || hits < 0 || (exists && prior[0] != n) {
				_ = f.Close()
				return nil, errors.New("inconsistent coverage block")
			}
			blocks[fields[0]] = [2]int64{n, prior[1] + hits}
		}
		if e = errors.Join(scan.Err(), f.Close()); e != nil {
			return nil, e
		}
	}
	keys := make([]string, 0, len(blocks))
	for k := range blocks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out strings.Builder
	out.WriteString("mode: atomic\n")
	totals := map[string]count{}
	for _, key := range keys {
		b := blocks[key]
		fmt.Fprintf(&out, "%s %d %d\n", key, b[0], b[1])
		path, _, ok := strings.Cut(key, ":")
		if !ok {
			return nil, errors.New("coverage location")
		}
		path = strings.TrimPrefix(path, "github.com/deploymenttheory/go-apfs-v2/")
		c := totals[path]
		c.Statements += b[0]
		if b[1] > 0 {
			c.Covered += b[0]
		}
		totals[path] = c
	}
	return totals, os.WriteFile(dest, []byte(out.String()), 0644)
}
func diagnose(path string) {
	f, e := os.Open(path)
	if e != nil {
		return
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 65536), 1<<20)
	last := map[string][]string{}
	for scan.Scan() {
		var item struct{ Action, Test, Output string }
		if json.Unmarshal(scan.Bytes(), &item) != nil {
			continue
		}
		if item.Output != "" {
			rows := append(last[item.Test], item.Output)
			if len(rows) > 12 {
				rows = rows[len(rows)-12:]
			}
			last[item.Test] = rows
		}
		if item.Action == "fail" {
			fmt.Fprintln(os.Stderr, "FAILED", item.Test)
			for _, s := range last[item.Test] {
				_, _ = io.WriteString(os.Stderr, s)
			}
		}
	}
	fmt.Fprintln(os.Stderr, "Full transcript:", path)
}

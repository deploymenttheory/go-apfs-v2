//go:build ignore

// Qualify shared CI reporting and provenance without native tools or networks.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/build"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

const reportingModule = "github.com/deploymenttheory/go-apfs-v2/"

var reportingPackages = []string{"internal/testutil/cirunner", "internal/testutil/captureprovenance", "internal/testutil/nativeevidence", "internal/evidenceaudit"}

// Keep this reviewed obligation inventory separate from the workflow itself.
// A deleted YAML call must fail qualification rather than shrink its scope.
var qualificationFamilies = []string{
	".github/workflows/carrier-recompression.yml",
	".github/workflows/compression-native.yml",
	".github/workflows/compression-owned.yml",
	".github/workflows/compression-state.yml",
	".github/workflows/hfs-special-names.yml",
	".github/workflows/large-resource-fork.yml",
	".github/workflows/metadata-transport.yml",
	".github/workflows/name-admission.yml",
	".github/workflows/name-cache-ast.yml",
	".github/workflows/name-collation.yml",
	".github/workflows/replacement.yml",
	".github/workflows/fuzz.yml",
	".github/workflows/ci-reporting.yml",
	".github/workflows/name-comparison.yml",
	".github/workflows/name-writer.yml",
	".github/workflows/pathname-authorization.yml",
	".github/workflows/pathname-limits.yml",
	".github/workflows/name-lookup.yml",
}

type reportingCount struct{ Covered, Statements int64 }

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := runReportingGate(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runReportingGate(ctx context.Context) error {
	if err := evidenceaudit.QualificationGraph(os.DirFS("."), ".github/workflows/ci.yml", "qualification-complete", qualificationFamilies); err != nil {
		return err
	}
	const out = "artifacts/ci-reporting-coverage"
	if err := os.MkdirAll(out, 0755); err != nil {
		return err
	}
	profile := filepath.Join(out, "coverage.out")
	args := []string{"test", "-count=1", "-json", "-covermode=atomic", "-coverprofile=" + profile}
	for _, pkg := range reportingPackages {
		args = append(args, "./"+pkg)
	}
	transcript := filepath.Join(out, "tests.jsonl")
	file, err := os.Create(transcript)
	if err != nil {
		return err
	}
	cmd := cirunner.CommandContext(ctx, "go", args...)
	cmd.Stdout = file
	cmd.Stderr = os.Stderr
	if err = errors.Join(cmd.Run(), file.Close()); err != nil {
		return fmt.Errorf("CI reporting qualification; raw evidence retained at %s: %w", out, err)
	}
	raw, err := os.ReadFile(transcript)
	if err != nil {
		return err
	}
	passed, err := validateReportingTranscript(raw, reportingPackages)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(profile)
	if err != nil {
		return err
	}
	files, packages, err := validateReportingCoverage(os.DirFS("."), data, reportingPackages)
	if err != nil {
		return err
	}
	patterns := []string{"scripts/verify-ci-reporting.go", "scripts/verify-ci-reporting_test.go", "go.mod", "go.sum"}
	for _, pkg := range reportingPackages {
		patterns = append(patterns, pkg+"/*.go")
	}
	sources, err := evidenceaudit.HarnessSourceHashes(os.DirFS("."), patterns)
	if err != nil {
		return err
	}
	revision, err := cirunner.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	total := reportingCount{}
	selected := map[string][2]int64{}
	for name, c := range files {
		selected[name] = [2]int64{c.Covered, c.Statements}
		total.Covered += c.Covered
		total.Statements += c.Statements
	}
	hashes := map[string]string{}
	for name, b := range map[string][]byte{"tests.jsonl": raw, "coverage.out": data} {
		digest := sha256.Sum256(b)
		hashes[name] = hex.EncodeToString(digest[:])
	}
	report := map[string]any{"revision": strings.TrimSpace(string(revision)), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "go": runtime.Version(), "source_sha256": sources, "evidence_sha256": hashes, "passed_tests": passed, "coverage_files": selected, "package_totals": packages, "required_packages": reportingPackages, "covered": total.Covered, "statements": total.Statements}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(out, "coverage.json"), append(b, '\n'), 0644); err != nil {
		return err
	}
	if err = evidenceaudit.Coverage(os.DirFS("."), os.DirFS("artifacts"), "ci-reporting-coverage", strings.TrimSpace(string(revision)), runtime.GOOS); err != nil {
		return err
	}
	fmt.Printf("CI reporting: %d passed tests; %d production files and %d packages exceed 95%% coverage\n", passed, len(files), len(packages))
	return nil
}

func validateReportingTranscript(raw []byte, required []string) (int, error) {
	type state struct {
		started, finished bool
		passed            int
		running           map[string]bool
		seen              map[string]bool
	}
	packages := map[string]*state{}
	for _, pkg := range required {
		key := reportingModule + pkg
		if _, exists := packages[key]; exists {
			return 0, errors.New("duplicate required package")
		}
		packages[key] = &state{running: map[string]bool{}, seen: map[string]bool{}}
	}
	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 64<<10), 1<<20)
	passed := 0
	for scan.Scan() {
		var event struct{ Action, Package, Test string }
		if err := json.Unmarshal(scan.Bytes(), &event); err != nil {
			return 0, err
		}
		pkg, exists := packages[event.Package]
		if !exists {
			return 0, fmt.Errorf("unexpected test package %q", event.Package)
		}
		if pkg.finished {
			return 0, fmt.Errorf("event after package completion: %s", event.Package)
		}
		switch event.Action {
		case "skip", "fail", "build-fail":
			return 0, fmt.Errorf("qualification %s: %s/%s", event.Action, event.Package, event.Test)
		case "start":
			if pkg.started || event.Test != "" {
				return 0, errors.New("invalid duplicate package start")
			}
			pkg.started = true
		case "run":
			if !pkg.started || event.Test == "" || pkg.seen[event.Test] {
				return 0, errors.New("invalid or duplicate test run")
			}
			pkg.seen[event.Test] = true
			pkg.running[event.Test] = true
		case "pass":
			if !pkg.started {
				return 0, errors.New("completion without package start")
			}
			if event.Test == "" {
				if len(pkg.running) != 0 || pkg.passed == 0 {
					return 0, errors.New("unfinished or empty package")
				}
				pkg.finished = true
			} else {
				if !pkg.running[event.Test] {
					return 0, errors.New("test completion without matching run")
				}
				delete(pkg.running, event.Test)
				pkg.passed++
				passed++
			}
		case "pause", "cont":
			if !pkg.running[event.Test] {
				return 0, errors.New("test transition without matching run")
			}
		case "output":
			if !pkg.started {
				return 0, errors.New("output before package start")
			}
		default:
			return 0, fmt.Errorf("unknown test action %q", event.Action)
		}
	}
	if err := scan.Err(); err != nil {
		return 0, err
	}
	if len(packages) == 0 {
		return 0, errors.New("empty required package inventory")
	}
	for name, pkg := range packages {
		if !pkg.finished {
			return 0, fmt.Errorf("incomplete package transcript: %s", name)
		}
	}
	return passed, nil
}

var reportingLocation = regexp.MustCompile(`^([^:]+):[1-9][0-9]*\.[1-9][0-9]*,[1-9][0-9]*\.[1-9][0-9]*$`)

func validateReportingCoverage(source fs.FS, raw []byte, required []string) (map[string]reportingCount, map[string]reportingCount, error) {
	buildContext := build.Default
	buildContext.OpenFile = func(name string) (io.ReadCloser, error) { return source.Open(filepath.ToSlash(name)) }
	files := map[string]reportingCount{}
	packages := map[string]reportingCount{}
	for _, pkg := range required {
		if _, ok := packages[pkg]; ok {
			return nil, nil, errors.New("duplicate coverage package")
		}
		packages[pkg] = reportingCount{}
		names, err := fs.Glob(source, pkg+"/*.go")
		if err != nil {
			return nil, nil, err
		}
		found := false
		for _, name := range names {
			if !strings.HasSuffix(name, "_test.go") {
				active, err := buildContext.MatchFile(pkg, path.Base(name))
				if err != nil {
					return nil, nil, err
				}
				if !active {
					continue
				}
				files[name] = reportingCount{}
				found = true
			}
		}
		if !found {
			return nil, nil, fmt.Errorf("missing production source inventory: %s", pkg)
		}
	}
	scan := bufio.NewScanner(bytes.NewReader(raw))
	if !scan.Scan() || scan.Text() != "mode: atomic" {
		return nil, nil, errors.New("invalid coverage mode")
	}
	seen := map[string]bool{}
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) != 3 {
			return nil, nil, errors.New("invalid coverage block")
		}
		match := reportingLocation.FindStringSubmatch(fields[0])
		if match == nil || !strings.HasPrefix(match[1], reportingModule) {
			return nil, nil, errors.New("invalid coverage location")
		}
		name := strings.TrimPrefix(match[1], reportingModule)
		c, ok := files[name]
		if !ok || !fs.ValidPath(name) {
			return nil, nil, fmt.Errorf("unexpected coverage source %s", name)
		}
		if seen[fields[0]] {
			return nil, nil, errors.New("duplicate coverage block")
		}
		seen[fields[0]] = true
		n, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || n < 0 || n > 1<<30 {
			return nil, nil, errors.New("invalid coverage statement count")
		}
		hits, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || hits < 0 {
			return nil, nil, errors.New("invalid coverage hit count")
		}
		c.Statements += n
		if hits > 0 {
			c.Covered += n
		}
		files[name] = c
	}
	if err := scan.Err(); err != nil {
		return nil, nil, err
	}
	for name, c := range files {
		if c.Statements == 0 || c.Covered*100 <= c.Statements*95 {
			return nil, nil, fmt.Errorf("%s must exceed 95%% coverage: %d/%d", name, c.Covered, c.Statements)
		}
		pkg := path.Dir(name)
		total := packages[pkg]
		total.Covered += c.Covered
		total.Statements += c.Statements
		packages[pkg] = total
	}
	if len(files) == 0 {
		return nil, nil, errors.New("empty coverage inventory")
	}
	for pkg, c := range packages {
		if c.Statements == 0 || c.Covered*100 <= c.Statements*95 {
			return nil, nil, fmt.Errorf("%s package must exceed 95%% coverage", pkg)
		}
	}
	return files, packages, nil
}

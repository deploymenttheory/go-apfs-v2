//go:build ignore

// Capture native replacement metadata and replay every captured case on each OS.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

type evidence struct {
	Schema    int               `json:"schema"`
	Cases     int               `json:"cases"`
	Versions  map[string]string `json:"versions"`
	Sources   map[string]string `json:"sources"`
	Artifacts map[string]string `json:"artifacts"`
}

func main() {
	replay := flag.Bool("replay", false, "verify and replay a native evidence directory")
	dir := flag.String("dir", "artifacts/replacement-filesystem", "evidence directory")
	flag.Parse()
	var err error
	if *replay {
		err = replayEvidence(*dir)
	} else {
		err = captureEvidence(*dir)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func digest(path string) (string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}
func saveJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}
func gzipFile(path string, b []byte) error {
	f, e := os.Create(path)
	if e != nil {
		return e
	}
	z := gzip.NewWriter(f)
	_, e = z.Write(b)
	return errors.Join(e, z.Close(), f.Close())
}
func captureEvidence(dir string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("capture requires macOS native filesystems")
	}
	if e := os.MkdirAll(dir, 0755); e != nil {
		return e
	}
	report := evidence{Schema: 1, Cases: 220, Versions: map[string]string{}, Sources: map[string]string{}, Artifacts: map[string]string{}}
	for name, args := range map[string][]string{"host": {"sw_vers"}, "compiler": {"xcrun", "clang", "--version"}, "sdk": {"xcrun", "--show-sdk-path"}} {
		b, e := cirunner.Command(args[0], args[1:]...).Output()
		if e != nil {
			return e
		}
		report.Versions[name] = string(b)
	}
	const source = "testdata/appledouble/native/replacement-filesystem.c"
	for _, name := range nativeInputs() {
		sum, e := digest(name)
		if e != nil {
			return e
		}
		report.Sources[name] = sum
		b, e := os.ReadFile(name)
		if e != nil {
			return e
		}
		target := filepath.Join(dir, name)
		if e = os.MkdirAll(filepath.Dir(target), 0755); e != nil {
			return e
		}
		if e = os.WriteFile(target, b, 0644); e != nil {
			return e
		}
	}
	if e := captureprovenance.Bind(os.DirFS("."), dir, report.Sources); e != nil {
		return e
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		b, e := cirunner.Command("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-arch", arch, "-Xclang", "-ast-dump=json", "-fsyntax-only", source).Output()
		if e != nil {
			return e
		}
		if !json.Valid(b) || !bytes.Contains(b, []byte("fsetxattr")) || !bytes.Contains(b, []byte("copyfile")) {
			return fmt.Errorf("incomplete %s native AST", arch)
		}
		name := arch + ".ast.json.gz"
		if e = gzipFile(filepath.Join(dir, name), b); e != nil {
			return e
		}
		report.Artifacts[name], e = digest(filepath.Join(dir, name))
		if e != nil {
			return e
		}
	}
	corpus, err := filepath.Abs(filepath.Join(dir, "cases.json"))
	if err != nil {
		return err
	}
	if e := runTests(dir, "native", []string{"./pkg/hostdata"}, "^TestReplacementFilesystemNativeEncoding$", "APFS_REPLACEMENT_FILESYSTEM_CAPTURE="+corpus); e != nil {
		return e
	}
	b, e := os.ReadFile(corpus)
	if e != nil {
		return e
	}
	if e = validateCases(b); e != nil {
		return e
	}
	if e = gzipFile(filepath.Join(dir, "cases.json.gz"), b); e != nil {
		return e
	}
	if e = os.Remove(corpus); e != nil {
		return e
	}
	for _, name := range []string{"cases.json.gz", "native.jsonl"} {
		report.Artifacts[name], e = digest(filepath.Join(dir, name))
		if e != nil {
			return e
		}
	}
	return saveJSON(filepath.Join(dir, "report.json"), report)
}
func validateCases(b []byte) error {
	var cases []struct {
		Filesystem, Profile string
		Input, Native       []byte
		Errno               int
	}
	if e := json.Unmarshal(b, &cases); e != nil {
		return e
	}
	seen := map[string]bool{}
	failed := 0
	for _, c := range cases {
		key := c.Filesystem + "/" + c.Profile
		if seen[key] || len(c.Input) == 0 || len(c.Native) == 0 {
			return fmt.Errorf("invalid duplicate/empty case %s", key)
		}
		seen[key] = true
		if c.Errno != 0 {
			if c.Errno != 22 {
				return fmt.Errorf("unexpected native errno %d", c.Errno)
			}
			failed++
		}
	}
	for _, fs := range []string{"MS-DOS FAT32", "ExFAT"} {
		for _, size := range []int{0, 1, 3650, 3651, 3652, 4096, 65100, 65400, 65536, 131072} {
			for _, fork := range []int{0, 1, 4, 255, 256, 285, 286, 287, 65535, 65536, 65537} {
				key := fmt.Sprintf("%s/value-%d-fork-%d", fs, size, fork)
				if !seen[key] {
					return fmt.Errorf("missing case %s", key)
				}
			}
		}
	}
	if len(cases) != 220 || failed != 100 {
		return fmt.Errorf("incomplete native corpus: %d cases %d failures", len(cases), failed)
	}
	return nil
}
func replayEvidence(dir string) error {
	b, e := os.ReadFile(filepath.Join(dir, "report.json"))
	if e != nil {
		return e
	}
	var report evidence
	if e = json.Unmarshal(b, &report); e != nil {
		return e
	}
	if report.Schema != 1 || report.Cases != 220 || len(report.Versions) != 3 {
		return errors.New("incomplete evidence report")
	}
	if e = captureprovenance.Verify(os.DirFS("."), report.Sources); e != nil {
		return e
	}
	for _, name := range nativeInputs() {
		if report.Sources[name] == "" {
			return fmt.Errorf("missing native source %s", name)
		}
	}
	for name, want := range report.Sources {
		if !filepath.IsLocal(name) {
			return errors.New("nonlocal evidence source")
		}
		for _, path := range []string{name, filepath.Join(dir, name)} {
			sum, e := digest(path)
			if e != nil {
				return e
			}
			if sum != want {
				return fmt.Errorf("source mismatch %s", path)
			}
		}
	}
	for _, name := range []string{"arm64.ast.json.gz", "x86_64.ast.json.gz", "cases.json.gz", "native.jsonl"} {
		want := report.Artifacts[name]
		sum, e := digest(filepath.Join(dir, name))
		if e != nil {
			return e
		}
		if want == "" || sum != want {
			return fmt.Errorf("artifact mismatch %s", name)
		}
	}
	f, e := os.Open(filepath.Join(dir, "cases.json.gz"))
	if e != nil {
		return e
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	b, e = io.ReadAll(z)
	if e = errors.Join(e, z.Close()); e != nil {
		return e
	}
	if e = validateCases(b); e != nil {
		return e
	}
	absolute, e := filepath.Abs(filepath.Join(dir, "cases.json.gz"))
	if e != nil {
		return e
	}
	return runTests(dir, "replay", []string{"./pkg/appledouble", "./pkg/hostdata"}, "^Test(FilesystemEncodingNativeCopy|ReplacementFilesystemNativeCorpus)$", "APFS_REPLACEMENT_FILESYSTEM_CORPUS="+absolute)
}
func runTests(dir, label string, packages []string, pattern, env string) error {
	args := append([]string{"test", "-count=1", "-json", "-run", pattern}, packages...)
	cmd := cirunner.Command("go", args...)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", env)
	log, e := os.Create(filepath.Join(dir, label+".jsonl"))
	if e != nil {
		return e
	}
	var transcript bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, log, &transcript)
	cmd.Stderr = io.MultiWriter(os.Stderr, log)
	if e = errors.Join(cmd.Run(), log.Close()); e != nil {
		return e
	}
	decoder := json.NewDecoder(&transcript)
	passed := map[string]bool{}
	for {
		var event struct{ Action, Test, Package string }
		e = decoder.Decode(&event)
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return e
		}
		if event.Action == "fail" || event.Action == "skip" {
			return fmt.Errorf("incomplete %s test: %+v", label, event)
		}
		if event.Action == "pass" {
			passed[event.Package+"/"+event.Test] = true
		}
	}
	for _, pkg := range packages {
		name := "github.com/deploymenttheory/go-apfs-v2/" + strings.TrimPrefix(pkg, "./")
		if !passed[name+"/"] {
			return fmt.Errorf("missing package pass %s", name)
		}
	}
	expected := []string{"TestReplacementFilesystemNativeEncoding"}
	if label == "replay" {
		expected = []string{"TestFilesystemEncodingNativeCopy", "TestReplacementFilesystemNativeCorpus"}
	}
	for _, test := range expected {
		found := false
		for name := range passed {
			if strings.HasSuffix(name, "/"+test) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("missing required suite %s", test)
		}
	}
	return nil
}

func nativeInputs() []string {
	return []string{
		"testdata/appledouble/native/replacement-filesystem.c",
		"scripts/verify-replacement-filesystem.go", ".github/workflows/replacement.yml",
		"pkg/hostdata/replacement_filesystem_darwin_test.go", "pkg/hostdata/replacement_volume_darwin_test.go",
		"pkg/hostdata/replacement_filesystem_test.go", "pkg/appledouble/filesystem_encode_test.go",
		"pkg/hostdata/replacement_filesystem.go", "pkg/hostdata/replacement_filesystem_darwin.go",
		"pkg/hostdata/replacement_copy_darwin.go", "pkg/appledouble/filesystem_encode.go",
		"scripts/generate-darwin-wrappers.go", "internal/darwinabi/zsyscall_darwin_arm64.go", "internal/darwinabi/zsyscall_darwin_arm64.s",
		"internal/darwinabi/zsyscall_darwin_amd64.go", "internal/darwinabi/zsyscall_darwin_amd64.s", "go.mod", "go.sum",
	}
}

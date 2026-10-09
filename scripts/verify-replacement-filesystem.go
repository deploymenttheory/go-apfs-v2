//go:build ignore

// Capture native replacement metadata and replay every captured case on each OS.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
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
	"sort"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

type evidence struct {
	Profile   osversion.MacOSProfile `json:"native_profile"`
	Schema    int                    `json:"schema"`
	Cases     int                    `json:"cases"`
	Versions  map[string]string      `json:"versions"`
	Sources   map[string]string      `json:"sources"`
	Artifacts map[string]string      `json:"artifacts"`
}

func main() {
	replay := flag.Bool("replay", false, "verify and replay a native evidence directory")
	baseline := flag.Bool("baseline", false, "check native policy separately from collection and Go parity")
	live := flag.Bool("live", false, "qualify held native Go copies against the C oracle")
	major := flag.Uint("major", 0, "required native macOS profile")
	output := flag.String("out", "artifacts/replacement-filesystem-replay", "consumer evidence directory")
	dir := flag.String("dir", "artifacts/replacement-filesystem", "evidence directory")
	flag.Parse()
	var err error
	if *replay {
		err = replayEvidence(*dir, osversion.MacOSProfile(*major), *live, *output, *baseline)
	} else {
		err = captureEvidence(*dir, osversion.MacOSProfile(*major))
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
func captureEvidence(dir string, expected osversion.MacOSProfile) error {
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
	version, err := osversion.ParseProductVersion(report.Versions["host"])
	if err != nil {
		return err
	}
	report.Profile, err = osversion.ProfileForMacOS(version)
	if err != nil {
		return err
	}
	if expected != 0 && report.Profile != expected {
		return errors.New("native producer profile mismatch")
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
	if e := runTests(dir, "native", []string{"./pkg/hostdata"}, "^TestReplacementFilesystemNativeCapture$", "APFS_REPLACEMENT_FILESYSTEM_CAPTURE="+corpus); e != nil {
		return e
	}
	b, e := os.ReadFile(corpus)
	if e != nil {
		return e
	}
	if e = validateCases(b, report.Profile); e != nil {
		return e
	}
	if e = gzipFile(filepath.Join(dir, "cases.json.gz"), b); e != nil {
		return e
	}
	if e = os.Remove(corpus); e != nil {
		return e
	}
	for _, name := range []string{"cases.json.gz", "native.jsonl", "native.stderr.log"} {
		report.Artifacts[name], e = digest(filepath.Join(dir, name))
		if e != nil {
			return e
		}
	}
	if err := archiveSources(dir, report.Sources); err != nil {
		return err
	}
	report.Artifacts["sources.json.gz"], e = digest(filepath.Join(dir, "sources.json.gz"))
	if e != nil {
		return e
	}
	if err := saveJSON(filepath.Join(dir, "report.json"), report); err != nil {
		return err
	}
	return captureprovenance.SealExecution(context.Background(), dir)

}
func validateCases(b []byte, profile osversion.MacOSProfile) error {
	if profile != osversion.MacOS15 && profile != osversion.MacOS26 && profile != osversion.MacOS27 {
		return osversion.ErrMacOSProfile
	}
	var cases []struct {
		Filesystem, Profile string
		Input, Native       []byte
		Errno               int
	}
	if e := json.Unmarshal(b, &cases); e != nil {
		return e
	}
	seen := map[string]bool{}
	for _, c := range cases {
		key := c.Filesystem + "/" + c.Profile
		if seen[key] || len(c.Input) == 0 || len(c.Native) == 0 {
			return fmt.Errorf("invalid duplicate/empty case %s", key)
		}
		seen[key] = true
		if c.Errno < 0 {
			return fmt.Errorf("invalid native errno %d", c.Errno)
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
	if len(cases) != 220 {
		return fmt.Errorf("incomplete native corpus: %d cases", len(cases))
	}
	return nil
}

// Behavioral baseline checking is separate from independent collection.
func validateNativePolicy(b []byte, profile osversion.MacOSProfile) error {
	if err := validateCases(b, profile); err != nil {
		return err
	}
	var records []struct {
		Profile string
		Errno   int
	}
	if err := json.Unmarshal(b, &records); err != nil {
		return err
	}
	for _, record := range records {
		var size, fork int
		if _, err := fmt.Sscanf(record.Profile, "value-%d-fork-%d", &size, &fork); err != nil {
			return err
		}
		expectedErrno := 0
		if profile != osversion.MacOS15 && fork > 0 && fork < 286 {
			expectedErrno = 22
		}
		if record.Errno != expectedErrno {
			return fmt.Errorf("native baseline changed for macOS %d/%s: errno %d expected %d", profile, record.Profile, record.Errno, expectedErrno)
		}
	}
	return nil
}

func replayEvidence(dir string, expected osversion.MacOSProfile, live bool, output string, baseline bool) error {
	if err := captureprovenance.VerifyExecution(context.Background(), dir); err != nil {
		return err
	}
	b, e := os.ReadFile(filepath.Join(dir, "report.json"))
	if e != nil {
		return e
	}
	var report evidence
	if e = json.Unmarshal(b, &report); e != nil {
		return e
	}
	version, err := osversion.ParseProductVersion(report.Versions["host"])
	if err != nil {
		return err
	}
	profile, err := osversion.ProfileForMacOS(version)
	if err != nil {
		return err
	}
	if expected == 0 || profile != expected || report.Profile != expected {
		return errors.New("native consumer profile mismatch")
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
	archived, err := readArchivedSources(filepath.Join(dir, "sources.json.gz"))
	if err != nil {
		return err
	}
	if len(archived) != len(report.Sources) {
		return errors.New("incomplete archived source inventory")
	}
	for name, want := range report.Sources {
		if !filepath.IsLocal(name) {
			return errors.New("nonlocal evidence source")
		}
		sum, e := digest(name)
		if e != nil {
			return e
		}
		if sum != want {
			return fmt.Errorf("current source mismatch %s", name)
		}
		b, ok := archived[name]
		h := sha256.Sum256(b)
		if !ok || hex.EncodeToString(h[:]) != want {
			return fmt.Errorf("archived source mismatch %s", name)
		}
	}

	for _, name := range []string{"arm64.ast.json.gz", "x86_64.ast.json.gz", "cases.json.gz", "native.jsonl", "native.stderr.log", "sources.json.gz"} {
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
	if e = validateCases(b, report.Profile); e != nil {
		return e
	}
	if baseline {
		return validateNativePolicy(b, report.Profile)
	}
	absolute, e := filepath.Abs(filepath.Join(dir, "cases.json.gz"))
	if e != nil {
		return e
	}
	consumer := filepath.Join(output, fmt.Sprintf("macos%d", report.Profile))
	if err := os.MkdirAll(consumer, 0700); err != nil {
		return err
	}
	if live {
		current, err := osversion.Detect(context.Background())
		if err != nil {
			return err
		}
		actual, err := osversion.ProfileForMacOS(current)
		if err != nil || actual != expected {
			return errors.New("live native receiver profile mismatch")
		}
		return runTests(consumer, "live", []string{"./pkg/hostdata"}, "^TestReplacementFilesystemNativeEncoding$")
	}
	return runTests(consumer, "replay", []string{"./pkg/appledouble", "./pkg/hostdata"}, "^Test(FilesystemEncodingNativeCopy|ReplacementFilesystemNativeCorpus)$", "APFS_REPLACEMENT_FILESYSTEM_CORPUS="+absolute, fmt.Sprintf("APFS_REPLACEMENT_FILESYSTEM_PROFILE=%d", report.Profile))
}
func runTests(dir, label string, packages []string, pattern string, env ...string) error {
	args := append([]string{"test", "-count=1", "-json", "-run", pattern}, packages...)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := cirunner.CommandContext(ctx, "go", args...)
	cmd.Env = append(append(os.Environ(), "CGO_ENABLED=0"), env...)
	transcriptPath := filepath.Join(dir, label+".jsonl")
	diagnosticPath := filepath.Join(dir, label+".stderr.log")
	if err := cmd.Capture(transcriptPath, diagnosticPath); err != nil {
		return fmt.Errorf("%s qualification failed; stdout %s stderr %s: %w", label, transcriptPath, diagnosticPath, err)
	}
	transcript, e := os.ReadFile(transcriptPath)
	if e != nil {
		return e
	}
	return validateTestTranscript(transcript, packages, label)
}

func validateTestTranscript(transcript []byte, packages []string, label string) error {
	decoder := json.NewDecoder(bytes.NewReader(transcript))
	passed := map[string]bool{}
	started, completed := map[string]bool{}, map[string]bool{}
	running := map[string]bool{}
	allowedPackages := map[string]bool{}
	for _, pkg := range packages {
		allowedPackages["github.com/deploymenttheory/go-apfs-v2/"+strings.TrimPrefix(pkg, "./")] = true
	}
	for {
		var event struct{ Action, Test, Package string }
		e := decoder.Decode(&event)
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return e
		}
		if !allowedPackages[event.Package] {
			return fmt.Errorf("unexpected test package %s", event.Package)
		}
		key := event.Package + "/" + event.Test
		switch event.Action {
		case "start":
			if event.Test != "" || started[event.Package] {
				return errors.New("invalid package start")
			}
			started[event.Package] = true
		case "run":
			if event.Test == "" || !started[event.Package] || completed[event.Package] || running[key] || passed[key] {
				return errors.New("invalid test start")
			}
			running[key] = true
		case "pass":
			if !started[event.Package] || completed[event.Package] {
				return errors.New("invalid package completion")
			}
			if event.Test == "" {
				for name := range running {
					if strings.HasPrefix(name, event.Package+"/") {
						return errors.New("package closed with unfinished tests")
					}
				}
				completed[event.Package] = true
			} else {
				if !running[key] {
					return errors.New("test completed without start")
				}
				delete(running, key)
			}
		case "output", "pause", "cont":
		case "fail", "skip":
		default:
			return fmt.Errorf("invalid test event %q", event.Action)
		}
		if event.Action == "fail" || event.Action == "skip" {
			return fmt.Errorf("incomplete %s test: %+v", label, event)
		}
		if event.Action == "pass" {
			if passed[event.Package+"/"+event.Test] {
				return errors.New("duplicate completion event")
			}
			passed[event.Package+"/"+event.Test] = true
		}
	}
	known := map[string]bool{}
	for _, pkg := range packages {
		name := "github.com/deploymenttheory/go-apfs-v2/" + strings.TrimPrefix(pkg, "./")
		known[name+"/"] = true
		if !passed[name+"/"] {
			return fmt.Errorf("missing package pass %s", name)
		}
	}
	expected := []string{"TestReplacementFilesystemNativeCapture"}
	if label == "live" {
		expected = []string{"TestReplacementFilesystemNativeEncoding"}
	}
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
	for _, test := range expected {
		packageName := "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
		if test == "TestFilesystemEncodingNativeCopy" {
			packageName = "github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
		}
		known[packageName+"/"+test] = true
		if !passed[packageName+"/"+test] {
			return fmt.Errorf("missing required suite %s", test)
		}
		for _, filesystem := range []string{"MS-DOS FAT32", "ExFAT"} {
			filesystemTest := strings.ReplaceAll(filesystem, " ", "_")
			if test != "TestFilesystemEncodingNativeCopy" && test != "TestReplacementFilesystemNativeCorpus" {
				known[packageName+"/"+test+"/"+filesystemTest] = true
			}
			if test != "TestFilesystemEncodingNativeCopy" && test != "TestReplacementFilesystemNativeCorpus" && !passed[packageName+"/"+test+"/"+filesystemTest] {
				return fmt.Errorf("missing filesystem completion %s", filesystem)
			}
			for _, size := range []int{0, 1, 3650, 3651, 3652, 4096, 65100, 65400, 65536, 131072} {
				for _, fork := range []int{0, 1, 4, 255, 256, 285, 286, 287, 65535, 65536, 65537} {
					key := fmt.Sprintf("%s/%s/%s/value-%d-fork-%d", packageName, test, filesystemTest, size, fork)
					known[key] = true
					if !passed[key] {
						return fmt.Errorf("missing native case completion %s", key)
					}
				}
			}
		}
	}
	for key := range passed {
		if !known[key] {
			return fmt.Errorf("unexpected completion %s", key)
		}
	}
	return nil
}

func nativeInputs() []string {
	return []string{
		"testdata/appledouble/native/replacement-filesystem.c",
		"scripts/verify-replacement-filesystem.go", "scripts/verify-replacement-filesystem_test.go", ".github/workflows/replacement.yml",
		"pkg/hostdata/replacement_filesystem_darwin_test.go", "pkg/hostdata/replacement_volume_darwin_test.go",
		"pkg/hostdata/replacement_filesystem_test.go", "pkg/appledouble/filesystem_encode_test.go",
		"pkg/hostdata/replacement_options.go", "pkg/osversion/macos.go", "pkg/osversion/version.go",
		"pkg/hostdata/replacement_filesystem.go", "pkg/hostdata/replacement_filesystem_darwin.go",
		"pkg/hostdata/replacement_copy_darwin.go", "pkg/appledouble/filesystem_encode.go",
		"scripts/generate-darwin-wrappers.go", "internal/darwinabi/zsyscall_darwin_arm64.go", "internal/darwinabi/zsyscall_darwin_arm64.s",
		"internal/darwinabi/zsyscall_darwin_amd64.go", "internal/darwinabi/zsyscall_darwin_amd64.s", "go.mod", "go.sum",
	}
}

// Frozen source bytes are evidence data, not runnable copies of the CI harness.
// Preserve and verify every byte in an archive; never exempt live source paths
// from the repository's process reporting audit.
func archiveSources(dir string, hashes map[string]string) error {
	sources := map[string][]byte{}
	for name, want := range hashes {
		path := filepath.Join(dir, name)
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != want {
			return fmt.Errorf("capture source changed: %s", name)
		}
		sources[name] = b
	}
	b, e := json.Marshal(sources)
	if e != nil {
		return e
	}
	if e = gzipFile(filepath.Join(dir, "sources.json.gz"), b); e != nil {
		return e
	}
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if e = os.Remove(filepath.Join(dir, name)); e != nil {
			return e
		}
	}
	return nil
}
func readArchivedSources(path string) (map[string][]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		return nil, e
	}
	defer z.Close()
	var sources map[string][]byte
	if e = json.NewDecoder(z).Decode(&sources); e != nil {
		return nil, e
	}
	return sources, nil
}

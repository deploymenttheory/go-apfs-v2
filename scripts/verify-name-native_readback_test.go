//go:build ignore

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

var nativeNameHarnessSources = []string{
	"testdata/appledouble/native/name-readback.c",
	"testdata/appledouble/native/name-receiver.c",
	"scripts/verify-name-native_readback_test.go",
	"scripts/verify-name-native_matrix_test.go",
	"scripts/verify-name-native_commands_test.go",
	"scripts/verify-name-comparison_test.go",
	"scripts/capture-name-collation.go",
	".github/workflows/name-comparison.yml",
	"go.mod", "go.sum",
}

type nativeNameCell struct {
	Producer   int    `json:"producer"`
	Receiver   int    `json:"receiver"`
	Filesystem string `json:"filesystem"`
}

func nativeNameSelection(producer, receiver, filesystem string) (nativeNameCell, error) {
	if producer == "" && receiver == "" && filesystem == "" {
		return nativeNameCell{}, nil // The original complete local 12-image run.
	}
	versions := map[string]int{"15": 15, "26": 26, "27": 27}
	p, r := versions[producer], versions[receiver]
	if p == 0 || r == 0 {
		return nativeNameCell{}, errors.New("matrix requires explicit producer and receiver 15, 26 or 27")
	}
	switch filesystem {
	case "APFS", "APFSX", "HFS+", "HFSX":
		return nativeNameCell{p, r, filesystem}, nil
	default:
		return nativeNameCell{}, errors.New("matrix requires explicit APFS, APFSX, HFS+ or HFSX")
	}
}

func TestCaptureNativeNameReceiver(t *testing.T) {
	runNativeNameImages(t, true, false)
}

func TestNativeCrossVersionNameImages(t *testing.T) {
	runNativeNameImages(t, false, false)
}

func TestPrepareNativeNameReceiver(t *testing.T) {
	runNativeNameImages(t, true, true)
}

func runNativeNameImages(t *testing.T, reference, prepare bool) {

	selection, e := nativeNameSelection(os.Getenv("APFS_NAME_PRODUCER"), os.Getenv("APFS_NAME_RECEIVER"), os.Getenv("APFS_NAME_FILESYSTEM"))
	if e != nil {
		t.Fatal(e)
	}
	if runtime.GOOS != "darwin" {
		t.Fatal("native cross-version qualification requires Darwin")
	}
	original, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Error(err)
		}
	})
	root, e := filepath.Abs("..")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chdir(root); e != nil {
		t.Fatal(e)
	}
	base := os.Getenv("APFS_NAME_IMAGE_ARTIFACTS")
	if base == "" {
		t.Fatal("missing allthree native image producers")
	}
	outputName := "name-native-readback"
	if reference {
		outputName = "name-native-reference"
	}
	if prepare {
		outputName = "name-native-preparation"
	}
	outputRoot := os.Getenv("APFS_NAME_OUTPUT_ROOT")
	if outputRoot == "" {
		outputRoot = "artifacts"
	}
	out, e := filepath.Abs(filepath.Join(outputRoot, outputName))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll(filepath.Dir(out), 0755); e != nil {
		t.Fatal(e)
	}
	// Refuse stale evidence from a prior invocation, including an earlier cell.
	if e = os.Mkdir(out, 0755); e != nil {
		t.Fatal(e)
	}
	limit := 25 * time.Minute
	if selection.Producer != 0 {
		limit = 4 * time.Minute
		if reference {
			limit = 2 * time.Minute
		}
	}
	if prepare {
		limit = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(t.Context(), limit)
	defer cancel()
	commands := &nativeCommandRunner{Directory: filepath.Join(out, "commands")}
	host, e := commands.run(ctx, "sw_vers")
	if e != nil {
		t.Fatal(e)
	}
	version, e := osversion.ParseProductVersion(string(host))
	if e != nil || (selection.Receiver != 0 && int(version.Major) != selection.Receiver) {
		t.Fatalf("receiver version does not match requested matrix cell: %s: %v", host, e)
	}
	source := "testdata/appledouble/native/name-readback.c"
	if reference {
		source = "testdata/appledouble/native/name-receiver.c"
	}
	binary := filepath.Join(out, "probe")
	if _, e = commands.run(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", source, "-o", binary); e != nil {
		t.Fatal(e)
	}
	sdk, e := commands.run(ctx, "xcrun", "--show-sdk-path")
	if e != nil {
		t.Fatal(e)
	}
	hashes := map[string]string{}
	for _, p := range nativeNameHarnessSources {
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		hashes[p] = sum(b)
	}
	if e = captureprovenance.Bind(os.DirFS(root), out, hashes); e != nil {
		t.Fatal(e)
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		ast, e := commands.run(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-target", arch+"-apple-macos15.0", "-isysroot", strings.TrimSpace(string(sdk)), "-Xclang", "-ast-dump=json", "-fsyntax-only", source)
		if e != nil {
			t.Fatal(e)
		}
		name := arch + ".ast.json"
		hashes[name] = sum(ast)
		if e = os.WriteFile(filepath.Join(out, name), ast, 0644); e != nil {
			t.Fatal(e)
		}
	}
	for _, h := range []string{"sys/stat.h", "sys/fcntl.h", "unistd.h", "sys/errno.h"} {
		b, e := os.ReadFile(filepath.Join(strings.TrimSpace(string(sdk)), "usr/include", h))
		if e != nil {
			t.Fatal(e)
		}
		name := "SDK/" + h
		hashes[name] = sum(b)
		dest := filepath.Join(out, name)
		if e = os.MkdirAll(filepath.Dir(dest), 0755); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(dest, b, 0644); e != nil {
			t.Fatal(e)
		}
	}
	b, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	hashes["native-binary"] = sum(b)
	inputs := map[string]string{}
	checked := 0
	volumes := 0
	profiles := 0
	for _, p := range []struct {
		major    int
		artifact string
	}{{15, "name-collation-macos-15"}, {26, "name-collation-macos-latest"}, {27, "name-collation-xcode-27"}} {
		if selection.Producer != 0 && selection.Producer != p.major {
			continue
		}
		profiles++
		dir := filepath.Join(base, p.artifact)
		capturePath := filepath.Join(dir, "native.json.gz")
		input, err := os.ReadFile(capturePath)
		if err != nil {
			t.Fatal(err)
		}
		inputs[p.artifact+"/native.json.gz"] = sum(input)
		tsv, err := os.ReadFile(filepath.Join(dir, "cases.tsv"))
		if err != nil {
			t.Fatal(err)
		}
		inputs[p.artifact+"/cases.tsv"] = sum(tsv)
		fresh := readComparisonCapture(t, capturePath, p.major)
		prior := readComparisonCapture(t, fmt.Sprintf("testdata/appledouble/native/name-collation-macos%d.json.gz", p.major))
		if e = compareStable(prior, fresh); e != nil {
			t.Fatal(e)
		}
		for _, v := range fresh.Volumes {
			if selection.Filesystem != "" && selection.Filesystem != v.Kind {
				continue
			}
			volumes++
			inputs[p.artifact+"/"+strings.ReplaceAll(v.Kind, "+", "plus")+".dmg"] = v.ImageSHA256
			if prepare {
				b, err := os.ReadFile(filepath.Join(dir, strings.ReplaceAll(v.Kind, "+", "plus")+".dmg"))
				if err != nil || sum(b) != v.ImageSHA256 {
					t.Fatal("preparation image hash", err)
				}
				continue
			}
			t.Run(fmt.Sprintf("%d/%s", p.major, v.Kind), func(t *testing.T) {
				nativeImageReadback(t, ctx, commands, out, dir, binary, string(host), p.major, v, reference, false)
				checked += len(v.Native.Cases) * 2
			})
		}
	}
	wantProfiles, wantVolumes, wantChecked := 3, 12, 90072
	if selection.Producer != 0 {
		wantProfiles, wantVolumes, wantChecked = 1, 1, 7506
	}
	if (!prepare && checked != wantChecked) || profiles != wantProfiles || volumes != wantVolumes || t.Failed() {
		t.Fatalf("incomplete native qualification: observations %d/%d profiles %d/%d volumes %d/%d", checked, wantChecked, profiles, wantProfiles, volumes, wantVolumes)
	}
	compiler, e := commands.run(ctx, "xcrun", "clang", "--version")
	if e != nil {
		t.Fatal(e)
	}
	revision, e := commands.run(ctx, "git", "rev-parse", "HEAD")
	if e != nil {
		t.Fatal(e)
	}
	if !reference {
		if err := os.CopyFS(filepath.Join(out, "reference"), os.DirFS(filepath.Join(filepath.Dir(out), "name-native-reference"))); err != nil {
			t.Fatal(err)
		}
	}
	rawEvidence := map[string]string{}
	err := filepath.WalkDir(out, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || path == filepath.Join(out, "report.json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(out, path)
		if err != nil {
			return err
		}
		rawEvidence[filepath.ToSlash(relative)] = sum(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	report := map[string]any{"schema": 3, "reference": reference, "preparation": prepare, "selection": selection, "host": string(host), "compiler": string(compiler), "sdk": string(sdk), "revision": strings.TrimSpace(string(revision)), "source_sha256": hashes, "input_sha256": inputs, "evidence_sha256": rawEvidence, "observations": checked, "producer_profiles": profiles, "volumes": volumes}
	b, e = json.MarshalIndent(report, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(out, "report.json"), b, 0644); e != nil {
		t.Fatal(e)
	}
}
func nativeImageReadback(t *testing.T, ctx context.Context, commands *nativeCommandRunner, out, dir, binary, host string, major int, v volumeCapture, reference, diagnostic bool) {
	t.Helper()
	stem := fmt.Sprintf("%d-%s", major, strings.ReplaceAll(v.Kind, "+", "plus"))
	image := filepath.Join(dir, strings.ReplaceAll(v.Kind, "+", "plus")+".dmg")
	b, e := os.ReadFile(image)
	if e != nil || sum(b) != v.ImageSHA256 {
		t.Fatal("native image hash", e)
	}
	var want []byte
	if !reference && !diagnostic {
		cell := nativeNameCell{Producer: major, Filesystem: v.Kind}
		version, err := osversion.ParseProductVersion(host)
		if err != nil {
			t.Fatal(err)
		}
		cell.Receiver = int(version.Major)
		refDir := filepath.Join(filepath.Dir(out), "name-native-reference")
		want, err = loadNativeReceiverReference(refDir, cell, host, v, dir)
		if err != nil {
			t.Fatal(err)
		}
	}
	// Never place a live mount under an uploaded artifact directory: an upload
	// must not traverse an unresponsive mounted filesystem after a failed probe.
	mount := filepath.Join(filepath.Dir(out), "name-native-mounts", stem)
	if e = os.MkdirAll(mount, 0700); e != nil {
		t.Fatal(e)
	}
	var raw []byte
	e = withNativeReadbackMount(ctx, commands.run, image, mount, filepath.Join(out, stem+"-detach.json"), func(attached []byte) error {
		if err := os.WriteFile(filepath.Join(out, stem+"-attach.plist"), attached, 0644); err != nil {
			return err
		}
		var err error
		probeContext, cancelProbe := context.WithTimeout(ctx, 2*time.Minute)
		defer cancelProbe()
		commands.liveStderr = true
		defer func() { commands.liveStderr = false }()
		raw, err = commands.run(probeContext, binary, mount, filepath.Join(dir, "cases.tsv"))
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(out, stem+"-readback.json"), raw, 0644)
	})
	if e != nil {
		t.Fatal(e)
	}
	if reference {
		normalized, err := parseNativeReceiver(raw, v.Native.Cases)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(out, stem+"-observations.json"), normalized, 0644); err != nil {
			t.Fatal(err)
		}
	} else if diagnostic {
		validateNativeNameResults(t, raw, v.Native.Cases, len(v.Native.Cases))
	} else {
		if err := compareNativeReceiver(raw, want, v.Native.Cases); err != nil {
			t.Fatal(err)
		}
	}
	after, e := os.ReadFile(image)
	if e != nil || sum(after) != v.ImageSHA256 {
		t.Fatal("read-only verification changed native image", e)
	}
}

// Receiver results are separate from producer creation observations. The latter
// establishes image identity, not whether an older kernel can resolve a name.
type nativeNameResult struct {
	Errno int    `json:"errno"`
	Inode uint64 `json:"inode"`
	Size  int64  `json:"size"`
	Read  int64  `json:"read"`
}

// Zero is a real native result, so absent/null fields must not silently decode
// into zero and turn truncated evidence into successful lookup or cleanup.
func (r *nativeNameResult) UnmarshalJSON(raw []byte) error {
	var value struct {
		Errno *int    `json:"errno"`
		Inode *uint64 `json:"inode"`
		Size  *int64  `json:"size"`
		Read  *int64  `json:"read"`
	}
	if err := decodeNativeJSON(raw, &value); err != nil {
		return err
	}
	if value.Errno == nil || value.Inode == nil || value.Size == nil || value.Read == nil {
		return errors.New("missing native result field")
	}
	*r = nativeNameResult{*value.Errno, *value.Inode, *value.Size, *value.Read}
	return nil
}

type nativeNameObservation struct {
	ID      string             `json:"id"`
	Results []nativeNameResult `json:"results"`
}
type nativeNameReadback struct {
	Count int                     `json:"count"`
	Cases []nativeNameObservation `json:"cases"`
}
type nativeNameMatrixReport struct {
	Schema       int               `json:"schema"`
	Reference    bool              `json:"reference"`
	Preparation  bool              `json:"preparation"`
	Selection    nativeNameCell    `json:"selection"`
	Host         string            `json:"host"`
	Compiler     string            `json:"compiler"`
	SDK          string            `json:"sdk"`
	Revision     string            `json:"revision"`
	Sources      map[string]string `json:"source_sha256"`
	Inputs       map[string]string `json:"input_sha256"`
	Evidence     map[string]string `json:"evidence_sha256"`
	Observations int               `json:"observations"`
	Profiles     int               `json:"producer_profiles"`
	Volumes      int               `json:"volumes"`
}

func decodeNativeJSON(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("trailing native JSON")
	}
	return nil
}

func validateNativeObservations(raw []byte, expected []nativeCase, required int) (nativeNameReadback, error) {
	var got nativeNameReadback
	if required <= 0 || len(expected) != required {
		return got, errors.New("invalid explicit native inventory")
	}
	if err := decodeNativeJSON(raw, &got); err != nil {
		return got, err
	}
	if got.Count != required || len(got.Cases) != required {
		return got, errors.New("incomplete native readback")
	}
	seen := make(map[string]bool, required)
	for i, c := range got.Cases {
		want := expected[i]
		if c.ID == "" || seen[c.ID] || c.ID != want.ID || len(c.Results) != 2 {
			return got, errors.New("native case inventory mismatch")
		}
		seen[c.ID] = true
		for j, r := range c.Results {
			if r.Errno < 0 {
				return got, errors.New("negative native errno")
			}
			if r.Errno != 0 {
				if r.Inode != 0 || r.Size != 0 || r.Read != -1 {
					return got, errors.New("failed lookup has identity or content")
				}
				continue
			}
			// These fixtures have at most one empty regular file per case. A
			// successful lookup must resolve that exact producer object. Do not
			// infer whether either spelling should resolve on this receiver.
			if want.CreateErrno != 0 || want.Inode == 0 || r.Inode != want.Inode || r.Size != 0 || r.Read != 0 {
				return got, fmt.Errorf("%s candidate%d identity/content changed", c.ID, j)
			}
		}
	}
	return got, nil
}

func compareNativeReceiver(raw, reference []byte, expected []nativeCase) error {
	want, err := validateNativeObservations(reference, expected, len(expected))
	if err != nil {
		return fmt.Errorf("receiver reference: %w", err)
	}
	got, err := validateNativeObservations(raw, expected, len(expected))
	if err != nil {
		return err
	}
	for i, c := range got.Cases {
		for j, r := range c.Results {
			if r != want.Cases[i].Results[j] {
				return fmt.Errorf("%s candidate%d receiver result %+v want %+v", c.ID, j, r, want.Cases[i].Results[j])
			}
		}
	}
	return nil
}

// The reference C probe emits one complete TSV record per spelling, followed by
// an explicit completion record only after all descriptors have closed.
func parseNativeReceiver(raw []byte, expected []nativeCase) ([]byte, error) {
	lines := strings.Split(string(raw), "\n")
	if len(expected) == 0 || len(lines) != len(expected)*2+2 || lines[len(lines)-1] != "" || lines[len(lines)-2] != fmt.Sprintf("complete\t%d", len(expected)) {
		return nil, errors.New("incomplete receiver reference stream")
	}
	got := nativeNameReadback{Count: len(expected)}
	for i, want := range expected {
		c := nativeNameObservation{ID: want.ID}
		for j := 0; j < 2; j++ {
			fields := strings.Split(lines[i*2+j], "\t")
			if len(fields) != 7 || fields[0] != want.ID || fields[1] != strconv.Itoa(j) {
				return nil, errors.New("receiver reference record identity")
			}
			errno, e1 := strconv.ParseInt(fields[2], 10, 32)
			inode, e2 := strconv.ParseUint(fields[3], 10, 64)
			size, e3 := strconv.ParseInt(fields[4], 10, 64)
			read, e4 := strconv.ParseInt(fields[5], 10, 64)
			if err := errors.Join(e1, e2, e3, e4); err != nil {
				return nil, err
			}
			if fields[6] != "closed" {
				return nil, errors.New("receiver descriptor cleanup incomplete")
			}
			c.Results = append(c.Results, nativeNameResult{int(errno), inode, size, read})
		}
		got.Cases = append(got.Cases, c)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		return nil, err
	}
	_, err = validateNativeObservations(encoded, expected, len(expected))
	return encoded, err
}

// Supplemental diagnostics validate shape and identity without pretending that
// producer lookup errno qualifies a receiving kernel. The full gate additionally
// requires a separate, complete receiver reference and successful replay.
func validateNativeNameResults(t *testing.T, raw []byte, expected []nativeCase, required int) {
	t.Helper()
	if _, err := validateNativeObservations(raw, expected, required); err != nil {
		t.Fatal(err)
	}
}

func loadNativeReceiverReference(out string, cell nativeNameCell, host string, v volumeCapture, input string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		return nil, err
	}
	var report nativeNameMatrixReport
	// Reports also retain compiler/SDK strings; decode through their full shape.
	if err = decodeNativeJSON(raw, &report); err != nil {
		return nil, err
	}
	if report.Schema != 3 || report.Preparation || !report.Reference || report.Host != host || (!((report.Selection == cell && report.Observations == 7506 && report.Profiles == 1 && report.Volumes == 1) || (report.Selection == (nativeNameCell{}) && report.Observations == 90072 && report.Profiles == 3 && report.Volumes == 12))) || len(v.Native.Cases) != 3753 {
		return nil, errors.New("receiver reference context/inventory mismatch")
	}
	if err = verifyNativeNameEvidence(out, report.Evidence); err != nil {
		return nil, err
	}
	sources, err := nativeNameSourceInventory(out)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(sources, report.Sources) {
		return nil, errors.New("receiver reference sources changed")
	}
	for _, name := range []string{"native.json.gz", "cases.tsv", strings.ReplaceAll(v.Kind, "+", "plus") + ".dmg"} {
		b, err := os.ReadFile(filepath.Join(input, name))
		if err != nil {
			return nil, err
		}
		if report.Inputs[filepath.Base(input)+"/"+name] != sum(b) {
			return nil, errors.New("receiver reference input changed")
		}
	}
	if len(report.Inputs) != report.Profiles*2+report.Volumes {
		return nil, errors.New("receiver reference input inventory")
	}
	producer := readReceiverProducerRevision(input)
	if len(report.Revision) != 40 || report.Revision != producer {
		return nil, errors.New("receiver reference revision mismatch")
	}
	stem := fmt.Sprintf("%d-%s", cell.Producer, strings.ReplaceAll(cell.Filesystem, "+", "plus"))
	attached, err := os.ReadFile(filepath.Join(out, stem+"-attach.plist"))
	if err != nil {
		return nil, err
	}
	detached, err := os.ReadFile(filepath.Join(out, stem+"-detach.json"))
	if err != nil {
		return nil, err
	}
	if err = validateNativeReceiverLifecycle(attached, detached); err != nil {
		return nil, err
	}
	stream, err := os.ReadFile(filepath.Join(out, stem+"-readback.json"))
	if err != nil {
		return nil, err
	}
	normalized, err := parseNativeReceiver(stream, v.Native.Cases)
	if err != nil {
		return nil, err
	}
	stored, err := os.ReadFile(filepath.Join(out, stem+"-observations.json"))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(normalized, stored) {
		return nil, errors.New("receiver observations differ from raw stream")
	}
	return stored, nil
}

func readReceiverProducerRevision(input string) string {
	// Decode only the revision here; callers already validate the complete
	// compressed producer capture and its current source provenance.
	f, err := os.Open(filepath.Join(input, "native.json.gz"))
	if err != nil {
		return ""
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		return ""
	}
	defer z.Close()
	var c struct{ Revision string }
	if json.NewDecoder(z).Decode(&c) != nil {
		return ""
	}
	return c.Revision
}

func nativeNameSourceInventory(out string) (map[string]string, error) {
	sources, err := captureprovenance.Inventory(os.DirFS("."))
	if err != nil {
		return nil, err
	}
	for _, path := range nativeNameHarnessSources {
		b, err := os.ReadFile(filepath.FromSlash(path))
		if err != nil {
			return nil, err
		}
		sources[path] = sum(b)
	}
	for _, path := range []string{"arm64.ast.json", "x86_64.ast.json", "SDK/sys/stat.h", "SDK/sys/fcntl.h", "SDK/unistd.h", "SDK/sys/errno.h"} {
		b, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(path)))
		if err != nil {
			return nil, err
		}
		sources[path] = sum(b)
	}
	b, err := os.ReadFile(filepath.Join(out, "probe"))
	if err != nil {
		return nil, err
	}
	sources["native-binary"] = sum(b)
	return sources, nil
}
func verifyNativeNameEvidence(dir string, hashes map[string]string) error {
	if len(hashes) == 0 {
		return errors.New("missing raw native evidence")
	}
	for name, hash := range hashes {
		if !fs.ValidPath(name) || strings.Contains(name, "\\") || name == "report.json" {
			return fmt.Errorf("invalid evidence path %q", name)
		}
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			return err
		}
		if sum(data) != hash {
			return fmt.Errorf("native evidence hash mismatch: %s", name)
		}
	}
	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink in native evidence")
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if relative == "report.json" {
			return nil
		}
		if _, ok := hashes[filepath.ToSlash(relative)]; !ok {
			return fmt.Errorf("unhashed native evidence: %s", relative)
		}
		return nil
	})
}

func validateNativeReceiverLifecycle(attached, detached []byte) error {
	device, err := diskimage.AttachmentDevice(attached)
	if err != nil || device == "" {
		return errors.Join(err, errors.New("missing attachment identity"))
	}
	var attempts []struct {
		Device   string `json:"device"`
		ExitCode *int   `json:"exit_code"`
		Output   string `json:"output"`
	}
	if err = decodeNativeJSON(detached, &attempts); err != nil {
		return err
	}
	if len(attempts) == 0 || attempts[len(attempts)-1].ExitCode == nil || *attempts[len(attempts)-1].ExitCode != 0 {
		return errors.New("receiver detach incomplete")
	}
	for i, a := range attempts {
		if a.Device != device || a.ExitCode == nil || (i < len(attempts)-1 && *a.ExitCode == 0) {
			return errors.New("receiver detach ownership/sequence changed")
		}
	}
	return nil
}

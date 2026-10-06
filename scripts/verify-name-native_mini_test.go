//go:build ignore

// Minimal native layout controls are supplemental and cannot qualify the full
// 3753-case producer/receiver gate. Existing native C oracles remain unchanged.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

type miniMetadata struct {
	Schema                        int
	Host, Revision, Compiler, SDK string
	Sources                       map[string]string
}
type miniImage struct {
	Schema                               int
	DiagnosticOnly                       bool
	Mode, Kind, MetadataHash, CorpusHash string
	Cases                                []nameCase
	Volume                               volumeCapture
}
type miniPlan struct {
	Schema                                                    int
	DiagnosticOnly                                            bool
	Mode, Kind, ProducerMetadataHash, ManifestHash, ImageHash string
	Consumer                                                  miniMetadata
}

func miniRoot(t *testing.T) string {
	t.Helper()
	original, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	root, e := filepath.Abs("..")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chdir(root); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := os.Chdir(original); e != nil {
			t.Error(e)
		}
	})
	return root
}
func miniCases(t *testing.T, mode string) []nameCase {
	t.Helper()
	if mode != "ascii" && mode != "ascii-a7ce" {
		t.Fatal("explicit minimal mode required")
	}
	reference := readComparisonCapture(t, "testdata/appledouble/native/name-collation-macos26.json.gz", 26)
	want := []string{"ascii"}
	if mode == "ascii-a7ce" {
		want = append(want, "fold-A7CE")
	}
	var selected []nameCase
	for _, id := range want {
		found := 0
		for _, c := range reference.Cases {
			if c.ID == id {
				selected = append(selected, c)
				found++
			}
		}
		if found != 1 {
			t.Fatal("minimal source inventory", id)
		}
	}
	return selected
}
func miniSourceNames() []string {
	names := []string{
		"testdata/appledouble/native/name-collation.c",
		"testdata/appledouble/native/name-raw-readback.c",
		"testdata/appledouble/native/name-collation-macos26.json.gz",
		"scripts/verify-name-native_mini_test.go",
		"scripts/capture-name-collation.go",
		"scripts/verify-name-comparison_test.go",
		"scripts/verify-name-native_commands_test.go",
		"scripts/verify-name-native_boundary_test.go",
		"scripts/verify-name-native_diagnostic_test.go",
		"scripts/verify-name-native_syscall_test.go",
		"scripts/verify-name-native_raw_test.go",
		".github/workflows/name-mini-diagnostic.yml",
		"go.mod",
		"go.sum",
		"native-creator",
		"syscall-probe",
		"apfs-driver.plist",
		"sdk-settings.plist",
		"uname.txt",
		"resources.txt",
		"host.txt",
		"compiler.txt",
		"sdk.txt",
	}
	for _, role := range []string{"creator", "reader"} {
		for _, arch := range []string{"arm64", "x86_64"} {
			names = append(names, role+"-"+arch+".ast.json")
		}
	}
	for _, h := range append(rawHeaders(), "dirent.h") {
		names = append(names, "SDK/"+h)
	}
	return names
}
func miniCheckSources(meta miniMetadata, out string) error {
	names := miniSourceNames()
	if meta.Schema != 1 || len(meta.Sources) != len(names) {
		return errors.New("minimal source inventory changed")
	}
	for _, name := range names {
		want, ok := meta.Sources[name]
		if !ok {
			return fmt.Errorf("missing source %s", name)
		}
		path := filepath.Join(out, name)
		if strings.HasPrefix(name, "testdata/") || strings.HasPrefix(name, "scripts/") || strings.HasPrefix(name, ".github/") || name == "go.mod" || name == "go.sum" {
			path = name
		}
		b, e := os.ReadFile(path)
		if e != nil || sum(b) != want {
			return fmt.Errorf("minimal source changed %s: %w", name, e)
		}
	}
	for name, want := range map[string]string{"host.txt": meta.Host, "compiler.txt": meta.Compiler, "sdk.txt": meta.SDK} {
		b, e := os.ReadFile(filepath.Join(out, name))
		if e != nil {
			return e
		}
		got := string(b)
		if name == "sdk.txt" {
			got = strings.TrimSpace(got)
		}
		if got != want {
			return fmt.Errorf("minimal observation field changed: %s", name)
		}
	}
	return nil
}
func miniBuild(t *testing.T, out string, major int) miniMetadata {
	t.Helper()
	if e := os.MkdirAll(out, 0700); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	commands := &nativeCommandRunner{Directory: filepath.Join(out, "build-commands")}
	meta := miniMetadata{Schema: 1, Sources: map[string]string{}}
	for _, observation := range []struct {
		name, command string
		args          []string
	}{
		{"host.txt", "sw_vers", nil},
		{"compiler.txt", "xcrun", []string{"clang", "--version"}},
		{"sdk.txt", "xcrun", []string{"--show-sdk-path"}},
		{"uname.txt", "uname", []string{"-a"}},
		{"resources.txt", "sysctl", []string{"hw.memsize", "hw.ncpu"}},
	} {
		b, e := commands.run(ctx, observation.command, observation.args...)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(out, observation.name), b, 0600); e != nil {
			t.Fatal(e)
		}
		switch observation.name {
		case "host.txt":
			meta.Host = string(b)
		case "compiler.txt":
			meta.Compiler = string(b)
		case "sdk.txt":
			meta.SDK = strings.TrimSpace(string(b))
		}
	}
	if e := validateComparisonProfile(capture{Host: meta.Host}, major); e != nil {
		t.Fatal(e)
	}
	revision, e := commands.run(ctx, "git", "rev-parse", "HEAD")
	if e != nil {
		t.Fatal(e)
	}
	meta.Revision = strings.TrimSpace(string(revision))
	for name, path := range map[string]string{"apfs-driver.plist": "/System/Library/Extensions/apfs.kext/Contents/Info.plist", "sdk-settings.plist": filepath.Join(meta.SDK, "SDKSettings.plist")} {
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(out, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, h := range append(rawHeaders(), "dirent.h") {
		b, e := os.ReadFile(filepath.Join(meta.SDK, "usr/include", h))
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(out, "SDK", h)
		if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, program := range []struct{ role, source, binary string }{{"creator", "testdata/appledouble/native/name-collation.c", "native-creator"}, {"reader", "testdata/appledouble/native/name-raw-readback.c", "syscall-probe"}} {
		if _, e = commands.run(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", program.source, "-o", filepath.Join(out, program.binary)); e != nil {
			t.Fatal(e)
		}
		for _, arch := range []string{"arm64", "x86_64"} {
			b, e := commands.run(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-target", arch+"-apple-macos15.0", "-isysroot", meta.SDK, "-Xclang", "-ast-dump=json", "-fsyntax-only", program.source)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(out, program.role+"-"+arch+".ast.json"), b, 0600); e != nil {
				t.Fatal(e)
			}
		}
	}
	for _, name := range miniSourceNames() {
		path := filepath.Join(out, name)
		if strings.HasPrefix(name, "testdata/") || strings.HasPrefix(name, "scripts/") || strings.HasPrefix(name, ".github/") || name == "go.mod" || name == "go.sum" {
			path = name
		}
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		meta.Sources[name] = sum(b)
	}
	if e = traceWriteJSON(filepath.Join(out, "metadata.json"), meta); e != nil {
		t.Fatal(e)
	}
	return meta
}
func miniValidateNative(n nativeCapture, kind string, cases []nameCase) error {
	if kind != "APFS" && kind != "APFSX" {
		return errors.New("invalid minimal filesystem")
	}
	sensitive := kind == "APFSX"
	if len(cases) < 1 || len(cases) > 2 || n.Filesystem != "apfs" || n.Sensitive != sensitive || n.Valid[0]&0x100 == 0 || (n.Capabilities[0]&0x100 != 0) != sensitive || !n.Retained || n.Count != len(cases) || len(n.Cases) != len(cases) {
		return errors.New("minimal native volume/inventory changed")
	}
	want := 0
	if sensitive {
		want = 2
	}
	for i, c := range n.Cases {
		if c.ID != cases[i].ID || c.Created != cases[i].Created || c.Queried != cases[i].Queried || c.CreateErrno != 0 || c.LookupErrno != want || c.Parent == 0 || c.Inode == 0 || c.StoredInode != c.Inode || c.Stored != c.Created || c.Same == sensitive {
			return errors.New("minimal native positive control failed")
		}
		if !sensitive && c.QueriedInode != c.Inode || sensitive && c.QueriedInode != 0 {
			return errors.New("minimal query identity changed")
		}
	}
	return nil
}
func miniRecords(t *testing.T, image string, v *volumeCapture) {
	t.Helper()
	container, closer, e := apfs.OpenImage(image, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := closer.Close(); e != nil {
			t.Error(e)
		}
	}()
	volumes, e := container.Volumes()
	if e != nil || len(volumes) != 1 {
		t.Fatal("minimal volume inventory", e)
	}
	volume := volumes[0]
	if volume.FileSystemBTree.UseCaseFolding == v.Native.Sensitive {
		t.Fatal("native mode/image flags differ")
	}
	for _, c := range v.Native.Cases {
		records, e := volume.FileSystemBTree.AllRecordsForOID(volume.Reader, c.Parent)
		if e != nil {
			t.Fatal(e)
		}
		for _, raw := range records {
			kind, e := apfs.ExtractDataTypeFromKey(raw.KeyData)
			if e != nil {
				t.Fatal(e)
			}
			if kind != apfs.FileSystemRecordTypeDirectoryEntry {
				continue
			}
			entry := apfs.NewDirectoryEntryRecord()
			if e = entry.ReadKeyData(raw.KeyData); e != nil {
				t.Fatal(e)
			}
			if e = entry.ReadValueData(raw.ValueData); e != nil {
				t.Fatal(e)
			}
			v.Records = append(v.Records, diskRecord{
				ID:    c.ID,
				Name:  hex.EncodeToString([]byte(strings.TrimSuffix(string(entry.Name), "\x00"))),
				Key:   hex.EncodeToString(raw.KeyData),
				Value: hex.EncodeToString(raw.ValueData),
				Hash:  entry.NameHash,
				Inode: entry.Identifier,
			})
		}
	}
	if e = validateRecords(*v); e != nil {
		t.Fatal(e)
	}
}
func miniDetach(t *testing.T, out, mount, device string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 45*time.Second)
	defer cancel()
	commands := &nativeCommandRunner{Directory: filepath.Join(out, "detach-commands")}
	e := diskimage.RetryDetach(ctx, func() (int, error) {
		_, err := commands.run(ctx, "hdiutil", "detach", device)
		if err == nil {
			return 0, nil
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), err
		}
		return -1, err
	})
	e = errors.Join(e, os.Remove(mount))
	if writeErr := traceWriteJSON(filepath.Join(out, "detach.json"), map[string]any{"device": device, "mount": mount, "error": fmt.Sprint(e)}); writeErr != nil {
		t.Error(writeErr)
	}
	if e != nil {
		t.Error(e)
	}
}
func TestProduceMinimalNativeImages(t *testing.T) {
	root := miniRoot(t)
	out := filepath.Join(root, "artifacts/name-mini-producer")
	major := 26
	if value := os.Getenv("APFS_NAME_MINI_PRODUCER_HOST"); value != "" {
		n, e := strconv.Atoi(value)
		if e != nil || (n != 26 && n != 27) {
			t.Fatal("producer target", e)
		}
		major = n
	}
	meta := miniBuild(t, out, major)
	metaBytes, e := os.ReadFile(filepath.Join(out, "metadata.json"))
	if e != nil {
		t.Fatal(e)
	}
	corpus, e := os.ReadFile("testdata/appledouble/native/name-collation-macos26.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"ascii", "ascii-a7ce"} {
		for _, kind := range []string{"APFS", "APFSX"} {
			t.Run(mode+"-"+kind, func(t *testing.T) {
				cases := miniCases(t, mode)
				dir := filepath.Join(out, mode+"-"+kind)
				if e := os.Mkdir(dir, 0700); e != nil {
					t.Fatal(e)
				}
				var tsv strings.Builder
				for _, c := range cases {
					fmt.Fprintf(&tsv, "%s\t%s\t%s\n", c.ID, c.Created, c.Queried)
				}
				casePath := filepath.Join(dir, "cases.tsv")
				if e := os.WriteFile(casePath, []byte(tsv.String()), 0600); e != nil {
					t.Fatal(e)
				}
				mount := filepath.Join(filepath.Dir(out), "name-mini-producer-mounts", mode+"-"+kind)
				if e := os.MkdirAll(mount, 0700); e != nil {
					t.Fatal(e)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
				defer cancel()
				commands := &nativeCommandRunner{Directory: filepath.Join(dir, "commands")}
				image := filepath.Join(dir, kind+".dmg")
				formatter := kind
				if kind == "APFSX" {
					formatter = "Case-sensitive APFS"
				}
				if _, e := commands.run(ctx, "hdiutil", "create", "-size", "128m", "-fs", formatter, "-volname", "Collation", image); e != nil {
					t.Fatal(e)
				}
				attached, e := commands.run(ctx, "hdiutil", "attach", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", mount, image)
				// Own any attachment before a fallible evidence write or parse.
				device := mount
				detached := false
				defer func() {
					if !detached {
						miniDetach(t, dir, mount, device)
					}
				}()
				parsedDevice, parseErr := diskimage.AttachmentDevice(attached)
				if parsedDevice != "" {
					device = parsedDevice
				}
				writeErr := os.WriteFile(filepath.Join(dir, "attach.plist"), attached, 0600)
				if e = errors.Join(e, parseErr, writeErr); e != nil {
					t.Fatal(e)
				}
				raw, e := commands.run(ctx, filepath.Join(out, "native-creator"), mount, casePath)
				if writeErr := os.WriteFile(filepath.Join(dir, "native.json"), raw, 0600); writeErr != nil {
					t.Fatal(writeErr)
				}
				if e != nil {
					t.Fatal(e)
				}
				v := volumeCapture{Kind: kind}
				if e = json.Unmarshal(raw, &v.Native); e != nil {
					t.Fatal(e)
				}
				if e = miniValidateNative(v.Native, kind, cases); e != nil {
					t.Fatal(e)
				}
				miniDetach(t, dir, mount, device)
				detached = true
				if t.Failed() {
					return
				}
				miniRecords(t, image, &v)
				b, e := os.ReadFile(image)
				if e != nil {
					t.Fatal(e)
				}
				v.ImageSHA256 = sum(b)
				report := miniImage{
					Schema:         1,
					DiagnosticOnly: true,
					Mode:           mode,
					Kind:           kind,
					MetadataHash:   sum(metaBytes),
					CorpusHash:     sum(corpus),
					Cases:          cases,
					Volume:         v,
				}
				if e = traceWriteJSON(filepath.Join(dir, "manifest.json"), report); e != nil {
					t.Fatal(e)
				}
				if e = miniCheckSources(meta, out); e != nil {
					t.Fatal(e)
				}
			})
		}
	}
}
func miniSelection(t *testing.T) (string, string) {
	t.Helper()
	mode, kind := os.Getenv("APFS_NAME_MINI_MODE"), os.Getenv("APFS_NAME_DIAGNOSTIC_FILESYSTEM")
	if mode != "ascii" && mode != "ascii-a7ce" {
		t.Fatal("explicit minimal mode required")
	}
	if kind != "APFS" && kind != "APFSX" {
		t.Fatal("explicit minimal filesystem required")
	}
	return mode, kind
}
func miniInput(t *testing.T) (string, miniImage, miniMetadata) {
	t.Helper()
	mode, kind := miniSelection(t)
	base := os.Getenv("APFS_NAME_MINI_IMAGES")
	if base == "" {
		t.Fatal("missing genuine minimal producer images")
	}
	b, e := os.ReadFile(filepath.Join(base, "metadata.json"))
	if e != nil {
		t.Fatal(e)
	}
	metaHash := sum(b)
	var meta miniMetadata
	if e = json.Unmarshal(b, &meta); e != nil {
		t.Fatal(e)
	}
	producerMajor := 26
	if value := os.Getenv("APFS_NAME_MINI_PRODUCER_HOST"); value != "" {
		producerMajor, e = strconv.Atoi(value)
		if e != nil {
			t.Fatal(e)
		}
	}
	if e = validateComparisonProfile(capture{Host: meta.Host}, producerMajor); e != nil {
		t.Fatal(e)
	}
	if e = miniCheckSources(meta, base); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(base, mode+"-"+kind)
	b, e = os.ReadFile(filepath.Join(dir, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	var report miniImage
	if e = json.Unmarshal(b, &report); e != nil {
		t.Fatal(e)
	}
	corpus, e := os.ReadFile("testdata/appledouble/native/name-collation-macos26.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	if report.Schema != 1 || !report.DiagnosticOnly || report.Mode != mode || report.Kind != kind || report.Volume.Kind != kind || report.MetadataHash != metaHash || report.CorpusHash != sum(corpus) {
		t.Fatal("minimal image manifest identity")
	}
	cases := miniCases(t, mode)
	if len(report.Cases) != len(cases) {
		t.Fatal("minimal case count")
	}
	var tsv strings.Builder
	for i, c := range cases {
		if report.Cases[i] != c {
			t.Fatal("minimal case bytes changed")
		}
		fmt.Fprintf(&tsv, "%s\t%s\t%s\n", c.ID, c.Created, c.Queried)
	}
	b, e = os.ReadFile(filepath.Join(dir, "cases.tsv"))
	if e != nil || string(b) != tsv.String() {
		t.Fatal("minimal TSV/source mismatch", e)
	}
	if e = miniValidateNative(report.Volume.Native, kind, cases); e != nil {
		t.Fatal(e)
	}
	if e = validateRecords(report.Volume); e != nil {
		t.Fatal(e)
	}
	b, e = os.ReadFile(filepath.Join(dir, kind+".dmg"))
	if e != nil || sum(b) != report.Volume.ImageSHA256 {
		t.Fatal("minimal image bytes changed", e)
	}
	return dir, report, meta
}
func TestPrepareMinimalNativeReceiver(t *testing.T) {
	root := miniRoot(t)
	dir, report, producer := miniInput(t)
	out := filepath.Join(root, "artifacts/name-native-diagnostic")
	major := 15
	if value := os.Getenv("APFS_NAME_DIAGNOSTIC_HOST"); value != "" {
		n, e := strconv.Atoi(value)
		if e != nil {
			t.Fatal(e)
		}
		major = n
	}
	consumer := miniBuild(t, out, major)
	if consumer.Revision != producer.Revision {
		t.Fatal("producer/receiver source revisions differ")
	}
	manifest, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	plan := miniPlan{
		Schema:               1,
		DiagnosticOnly:       true,
		Mode:                 report.Mode,
		Kind:                 report.Kind,
		ProducerMetadataHash: report.MetadataHash,
		ManifestHash:         sum(manifest),
		ImageHash:            report.Volume.ImageSHA256,
		Consumer:             consumer,
	}
	if e = traceWriteJSON(filepath.Join(out, "pre-execution.json"), plan); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(out, "syscall-control"), 0700); e != nil {
		t.Fatal(e)
	}
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		t.Fatal(e)
	}
	checkpointBytes, e := os.ReadFile(filepath.Join(out, "pre-execution.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = traceWriteJSON(filepath.Join(out, "syscall-plan.json"), syscallTracePlan{
		Schema:         1,
		DiagnosticOnly: true,
		Nonce:          hex.EncodeToString(nonce),
		Checkpoint:     sum(checkpointBytes),
	}); e != nil {
		t.Fatal(e)
	}
}
func miniReceiver(t *testing.T) (string, string, miniImage, miniPlan) {
	t.Helper()
	root := miniRoot(t)
	dir, report, _ := miniInput(t)
	out := filepath.Join(root, "artifacts/name-native-diagnostic")
	b, e := os.ReadFile(filepath.Join(out, "pre-execution.json"))
	if e != nil {
		t.Fatal(e)
	}
	var plan miniPlan
	if e = json.Unmarshal(b, &plan); e != nil {
		t.Fatal(e)
	}
	manifest, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	if plan.Schema != 1 || !plan.DiagnosticOnly || plan.Mode != report.Mode || plan.Kind != report.Kind || plan.ProducerMetadataHash != report.MetadataHash || plan.ManifestHash != sum(manifest) || plan.ImageHash != report.Volume.ImageSHA256 {
		t.Fatal("minimal receiver checkpoint changed")
	}
	if e = miniCheckSources(plan.Consumer, out); e != nil {
		t.Fatal(e)
	}
	return out, dir, report, plan
}
func TestAttachMinimalNativeReceiver(t *testing.T) {
	out, dir, report, _ := miniReceiver(t)
	mount := boundaryMount(out, singleNameCheckpoint{Profile: 26, Filesystem: report.Kind})
	if e := os.MkdirAll(filepath.Dir(mount), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(mount, 0700); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(out, "pre-execution.json"))
	if e != nil {
		t.Fatal(e)
	}
	boundaryResult(t, out, "attach-intent", struct{ Mount, Checkpoint string }{mount, sum(b)})
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	commands := &nativeCommandRunner{Directory: filepath.Join(out, "boundary-attach-commands")}
	raw, e := commands.run(ctx, "hdiutil", "attach", "-readonly", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", mount, filepath.Join(dir, report.Kind+".dmg"))
	writeErr := os.WriteFile(filepath.Join(out, "boundary-attach.plist"), raw, 0600)
	if e = errors.Join(e, writeErr); e != nil {
		t.Fatal(e)
	}
	boundaryAttached(t, out, mount)
}
func TestReadMinimalNativeReceiver(t *testing.T) {
	out, dir, report, _ := miniReceiver(t)
	mount := boundaryMount(out, singleNameCheckpoint{Profile: 26, Filesystem: report.Kind})
	boundaryAttached(t, out, mount)
	control := filepath.Join(out, "syscall-control")
	b, e := os.ReadFile(filepath.Join(out, "syscall-plan.json"))
	if e != nil {
		t.Fatal(e)
	}
	checkpointBytes, e := os.ReadFile(filepath.Join(out, "pre-execution.json"))
	if e != nil {
		t.Fatal(e)
	}
	var identity syscallTracePlan
	if e = json.Unmarshal(b, &identity); e != nil || identity.Schema != 1 || !identity.DiagnosticOnly || len(identity.Nonce) != 32 || identity.Checkpoint != sum(checkpointBytes) {
		t.Fatal("minimal process identity", e)
	}
	stdout, e := os.Create(filepath.Join(out, "raw-native.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	stderr, e := os.Create(filepath.Join(out, "raw-native.stderr"))
	if e != nil {
		t.Fatal(errors.Join(e, stdout.Close()))
	}
	cmd := exec.Command(filepath.Join(out, "syscall-probe"), mount, filepath.Join(dir, "cases.tsv"), control, identity.Nonce)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	startErr := cmd.Start()
	e = errors.Join(startErr, stdout.Close(), stderr.Close())
	if e != nil {
		if startErr == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Process.Release()
		}
		t.Fatal(e)
	}
	pid := cmd.Process.Pid
	if e = traceWriteJSON(filepath.Join(out, "syscall-process.json"), map[string]any{"pid": pid, "nonce": identity.Nonce, "argv": cmd.Args}); e != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Process.Release()
		t.Fatal(e)
	}
	if e = cmd.Process.Release(); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	var ready syscallTraceReady
	if e = waitTraceJSON(ctx, filepath.Join(control, "ready.json"), &ready); e != nil {
		t.Fatal(e)
	}
	if e = validateTraceReady(ready, identity); e != nil || ready.PID != pid {
		t.Fatal("minimal actor identity", e)
	}
	f, e := os.Open(filepath.Join(out, "raw-native.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := f.Close(); e != nil {
			t.Error(e)
		}
	}()
	reader := bufio.NewReader(f)
	if e = os.WriteFile(filepath.Join(control, "start"), []byte(identity.Nonce), 0600); e != nil {
		t.Fatal(e)
	}
	count, volumes := 0, 0
	fatalSeen, finished := false, false
	var pending, last []byte
	for !finished {
		if e = ctx.Err(); e != nil {
			writeErr := traceWriteJSON(filepath.Join(out, "raw-incomplete.json"), map[string]any{
				"complete":             false,
				"observed_cases":       count,
				"last_complete_record": json.RawMessage(last),
				"partial_record":       string(pending),
				"error":                e.Error(),
			})
			t.Fatal(errors.Join(e, writeErr))
		}
		part, readErr := reader.ReadBytes('\n')
		pending = append(pending, part...)
		if len(pending) > 1<<20 {
			t.Fatal("oversized minimal record")
		}
		if readErr == nil {
			line := append([]byte(nil), pending...)
			pending = nil
			var record rawNativeRecord
			if e = json.Unmarshal(line, &record); e != nil {
				t.Fatal(e)
			}
			last = append(last[:0], line...)
			fmt.Printf("NATIVE MINI %s", line)
			switch record.Type {
			case "start", "volume-uuid":
			case "volume":
				volumes++
			case "fatal":
				fatalSeen = true
			case "case":
				if count >= len(report.Cases) {
					t.Fatal("extra minimal case")
				}
				if e = validateRawCase(record, report.Cases[count].ID, count); e != nil {
					t.Fatal(e)
				}
				count++
			case "finished":
				finished = true
				if record.Count != len(report.Cases) || count != len(report.Cases) || volumes != 1 || fatalSeen || record.Error != 0 || record.Stopped || record.CleanupErrno != 0 {
					t.Fatal("incomplete minimal native record", string(line))
				}
			default:
				t.Fatal("unknown minimal record", record.Type)
			}
			continue
		}
		if !errors.Is(readErr, io.EOF) {
			t.Fatal(readErr)
		}
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Millisecond):
		}
	}
	var final struct {
		syscallTraceFinished
		Error int
	}
	if e = waitTraceJSON(ctx, filepath.Join(control, "finished.json"), &final); e != nil {
		t.Fatal(e)
	}
	if final.Schema != 1 || final.Nonce != identity.Nonce || final.PID != pid || final.Completed != len(report.Cases) || final.Stopped || final.CleanupErrno != 0 || final.Error != 0 {
		t.Fatal("minimal final process identity", final)
	}
	exitCode, exitErr := waitRawExit(ctx, pid)
	if e = traceWriteJSON(filepath.Join(out, "raw-process-exit.json"), map[string]any{
		"pid":       pid,
		"nonce":     identity.Nonce,
		"exit_code": exitCode,
		"error":     fmt.Sprint(exitErr),
	}); e != nil {
		t.Fatal(e)
	}
	if exitErr != nil || exitCode != 0 {
		t.Fatal("minimal process exit", exitCode, exitErr)
	}
	hashResult := make(chan error, 1)
	go func() {
		b, e := os.ReadFile(filepath.Join(dir, report.Kind+".dmg"))
		if e == nil && sum(b) != report.Volume.ImageSHA256 {
			e = errors.New("minimal native changed image")
		}
		hashResult <- e
	}()
	hashCtx, hashCancel := context.WithTimeout(ctx, 10*time.Second)
	defer hashCancel()
	select {
	case e = <-hashResult:
		if e != nil {
			t.Fatal(e)
		}
	case <-hashCtx.Done():
		t.Fatal(hashCtx.Err())
	}
	if e = traceWriteJSON(filepath.Join(out, "raw-completion.json"), map[string]any{
		"diagnostic_only":     true,
		"qualifies_full_gate": false,
		"observed_cases":      count,
		"observations":        count * 2,
		"final":               final,
		"exit_code":           exitCode,
		"image_sha256":        report.Volume.ImageSHA256,
	}); e != nil {
		t.Fatal(e)
	}
}
func TestCompareMinimalNativeReceiver(t *testing.T) {
	out, _, report, _ := miniReceiver(t)
	if _, e := os.ReadFile(filepath.Join(out, "raw-completion.json")); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(out, "raw-native.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	var cases []json.RawMessage
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var r rawNativeRecord
		if e = json.Unmarshal([]byte(line), &r); e != nil {
			t.Fatal(e)
		}
		if r.Type == "case" {
			cases = append(cases, json.RawMessage(line))
		}
	}
	b, e := json.Marshal(struct {
		Cases []json.RawMessage `json:"cases"`
		Count int               `json:"count"`
	}{cases, len(cases)})
	if e != nil {
		t.Fatal(e)
	}
	validateNativeNameResults(t, b, report.Volume.Native.Cases, len(report.Cases))
}

func TestMinimalNativeValidation(t *testing.T) {
	miniRoot(t)
	cases := miniCases(t, "ascii-a7ce")
	for _, kind := range []string{"APFS", "APFSX"} {
		sensitive := kind == "APFSX"
		native := nativeCapture{
			Filesystem: "apfs",
			Sensitive:  sensitive,
			Count:      len(cases),
			Retained:   true,
			Valid:      [4]uint32{0x100},
		}
		if sensitive {
			native.Capabilities[0] = 0x100
		}
		for i, c := range cases {
			inode := uint64(i + 101)
			entry := nativeCase{
				ID:           c.ID,
				Created:      c.Created,
				Queried:      c.Queried,
				Parent:       inode + 100,
				Inode:        inode,
				StoredInode:  inode,
				Stored:       c.Created,
				Same:         !sensitive,
				QueriedInode: inode,
			}
			if sensitive {
				entry.LookupErrno = 2
				entry.QueriedInode = 0
			}
			native.Cases = append(native.Cases, entry)
		}
		if e := miniValidateNative(native, kind, cases); e != nil {
			t.Fatal(e)
		}
		for _, mutate := range []func(*nativeCapture){
			func(n *nativeCapture) { n.Count-- },
			func(n *nativeCapture) { n.Valid[0] = 0 },
			func(n *nativeCapture) { n.Cases[0].ID = "other" },
			func(n *nativeCapture) { n.Cases[0].Created = "00" },
			func(n *nativeCapture) { n.Cases[0].CreateErrno = 22 },
			func(n *nativeCapture) { n.Cases[0].StoredInode++ },
			func(n *nativeCapture) { n.Cases[0].Parent = 0 },
			func(n *nativeCapture) { n.Cases[0].LookupErrno = 5 },
		} {
			bad := native
			bad.Cases = append([]nativeCase(nil), native.Cases...)
			mutate(&bad)
			if miniValidateNative(bad, kind, cases) == nil {
				t.Fatal("accepted invalid minimal evidence", kind, bad)
			}
		}
	}
	if miniCheckSources(miniMetadata{Schema: 1, Sources: map[string]string{}}, t.TempDir()) == nil {
		t.Fatal("accepted missing source manifest")
	}
}

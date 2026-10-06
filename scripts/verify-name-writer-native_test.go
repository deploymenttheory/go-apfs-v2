//go:build ignore

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

func TestNativeNameWriterReadback(t *testing.T) {
	qualifyNativeNameWriters(t, []string{"linux", "windows", "darwin"})
}

// This explicitly named local control cannot satisfy the three-producer CI gate.
func TestLocalNameWriterReadback(t *testing.T) {
	qualifyNativeNameWriters(t, []string{"darwin"})
}
func qualifyNativeNameWriters(t *testing.T, producers []string) {
	if runtime.GOOS != "darwin" {
		t.Fatal("native writer qualification requires Darwin")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	base := os.Getenv("FILESYSTEM_NAME_WRITER_ARTIFACTS")
	if base == "" {
		t.Fatal("all three portable writer artifacts are required")
	}
	output := os.Getenv("FILESYSTEM_NAME_WRITER_NATIVE_OUTPUT")
	if output == "" {
		output = "artifacts/name-writer-native"
	}
	out, err := filepath.Abs(output)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(out, 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Minute)
	defer cancel()
	host, err := command(ctx, "sw_vers")
	if err != nil {
		t.Fatal(err)
	}
	target, err := osversion.ParseProductVersion(string(host))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = osversion.ProfileForMacOS(target); err != nil {
		t.Fatal(err)
	}
	revision, err := command(ctx, "git", "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	sources, err := nameWriterSources()
	if err != nil {
		t.Fatal(err)
	}
	oracle, provenance := compileWriterOracle(t, ctx, out, "name-writer-readback.c")
	preflight, preflightProvenance := compileWriterOracle(t, ctx, out, "name-writer-preflight.c")
	observedImages, observedNames, observedChecks := 0, 0, 0
	var firstChecks = map[string][]nameWriterCheck{}
	for _, producer := range producers {
		directory := filepath.Join(base, "name-writer-"+producer)
		report := readWriterReport(t, filepath.Join(directory, "manifest.json"))
		if report.Schema != 1 || report.Host != producer || report.Arch == "" || report.Revision != strings.TrimSpace(string(revision)) || !reflect.DeepEqual(report.Sources, sources) {
			t.Fatal("producer source/revision identity differs", producer)
		}
		if len(report.Images) != 12 {
			t.Fatal("producer image inventory differs", producer)
		}
		expected := map[string]bool{}
		for _, major := range []uint32{15, 26, 27} {
			for _, kind := range []string{"APFS", "APFSX", "HFS+", "HFSX"} {
				expected[fmt.Sprintf("%d/%s", major, kind)] = true
			}
		}
		allowedFiles := map[string]bool{"manifest.json": true}
		for _, image := range report.Images {
			key := fmt.Sprintf("%d/%s", image.Target, image.Kind)
			if !expected[key] {
				t.Fatal("duplicate/unexpected produced image", key)
			}
			delete(expected, key)
			if image.File != fmt.Sprintf("macos%d-%s.img", image.Target, image.Kind) || image.Size != 64<<20 {
				t.Fatal("unqualified image pathname/size", key)
			}
			allowedFiles[image.File] = true
			native := readComparisonCapture(t, fmt.Sprintf("testdata/appledouble/native/name-collation-macos%d.json.gz", image.Target))
			fixture, err := os.ReadFile(fmt.Sprintf("testdata/appledouble/native/name-collation-macos%d.json.gz", image.Target))
			if err != nil || sum(fixture) != image.FixtureSHA256 {
				t.Fatal("producer native source fixture differs", key, err)
			}
			if err = compareStable(native, native); err != nil {
				t.Fatal(err)
			}
			var source *volumeCapture
			for i := range native.Volumes {
				if native.Volumes[i].Kind == image.Kind {
					source = &native.Volumes[i]
				}
			}
			if source == nil {
				t.Fatal("missing native filesystem profile", key)
			}
			validateWriterImageManifest(t, image, *source)
			imagePath := filepath.Join(directory, image.File)
			raw, err := os.ReadFile(imagePath)
			if err != nil || int64(len(raw)) != image.Size || sum(raw) != image.SHA256 {
				t.Fatal("producer image digest/size differs", key, err)
			}
			if image.Target != target.Major {
				continue
			}
			stem := producer + "-" + strings.ReplaceAll(image.Kind, "+", "plus")
			casePath := filepath.Join(out, stem+"-cases.tsv")
			var cases strings.Builder
			for _, c := range append(append([]nameWriterRecord{}, image.Cases...), image.ExtraCases...) {
				fmt.Fprintf(&cases, "%s\t%s\t%s\n", c.ID, c.Created, c.Queried)
			}
			if err = os.WriteFile(casePath, []byte(cases.String()), 0644); err != nil {
				t.Fatal(err)
			}
			mountedWriterVolume(t, ctx, out, stem, imagePath, true, func(mount string) {
				result := runWriterNative(t, ctx, filepath.Join(out, stem+"-readback.json"), oracle, mount, casePath)
				validateWriterReadback(t, result, image)
			})
			after, err := os.ReadFile(imagePath)
			if err != nil || sum(after) != image.SHA256 {
				t.Fatal("native readback changed producer image", key, err)
			}
			if prior, ok := firstChecks[image.Kind]; ok {
				if !reflect.DeepEqual(prior, image.Checks) {
					t.Fatal("portable rejection decisions differ", producer, key)
				}
			} else {
				firstChecks[image.Kind] = image.Checks
			}
			observedImages++
			observedNames += (len(image.Cases) + len(image.ExtraCases)) * 2
		}
		if len(expected) != 0 {
			t.Fatal("missing produced target image", producer)
		}
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != len(allowedFiles) {
			t.Fatal("unexpected producer artifact inventory", producer)
		}
		for _, entry := range entries {
			if entry.IsDir() || !allowedFiles[entry.Name()] {
				t.Fatal("unexpected producer artifact", entry.Name())
			}
		}
	}
	for _, kind := range []string{"APFS", "APFSX", "HFS+", "HFSX"} {
		checks, ok := firstChecks[kind]
		if !ok {
			t.Fatal("missing native rejection profile", kind)
		}
		stem := "preflight-" + strings.ReplaceAll(kind, "+", "plus")
		table := filepath.Join(out, stem+".tsv")
		var input strings.Builder
		for _, c := range checks {
			fmt.Fprintf(&input, "%s\t%s\t%s\t%s\n", c.ID, c.Kind, c.First, c.Second)
		}
		if err = os.WriteFile(table, []byte(input.String()), 0644); err != nil {
			t.Fatal(err)
		}
		image := filepath.Join(out, stem+".dmg")
		format := kind
		if kind == "APFSX" {
			format = "Case-sensitive APFS"
		}
		if kind == "HFSX" {
			format = "Case-sensitive HFS+"
		}
		if _, err = command(ctx, "hdiutil", "create", "-size", "64m", "-fs", format, "-volname", "NamePreflight", image); err != nil {
			t.Fatal(err)
		}
		mountedWriterVolume(t, ctx, out, stem, image, false, func(mount string) {
			result := runWriterNative(t, ctx, filepath.Join(out, stem+"-native.json"), preflight, mount, table)
			validateWriterPreflight(t, result, kind, checks)
		})
		observedChecks += len(checks)
	}
	if observedImages != 4*len(producers) || observedNames != len(producers)*(4*casesPerVolume*2+44) {
		t.Fatal("native writer readback inventory incomplete", observedImages, observedNames)
	}
	evidence := map[string]string{}
	if err = filepath.WalkDir(out, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(out, path)
		if err != nil {
			return err
		}
		evidence[filepath.ToSlash(relative)] = sum(raw)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	manifests := map[string]string{}
	for _, producer := range producers {
		raw, err := os.ReadFile(filepath.Join(base, "name-writer-"+producer, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		manifests[producer] = sum(raw)
	}
	summary := map[string]any{"evidence_sha256": evidence, "producer_manifests": manifests, "schema": 1, "host": string(host), "revision": strings.TrimSpace(string(revision)), "target": target, "producers": producers, "images": observedImages, "name_lookups": observedNames, "exclusive_create_controls": observedChecks, "readback_provenance": provenance, "preflight_provenance": preflightProvenance, "all_images_unchanged": true, "all_mounts_detached": true}
	raw, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(out, "report.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
}
func readWriterReport(t *testing.T, path string) nameWriterReport {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	var report nameWriterReport
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&report); err != nil {
		t.Fatal(err)
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		t.Fatal("trailing producer manifest data", err)
	}
	return report
}
func validateWriterImageManifest(t *testing.T, image nameWriterImage, source volumeCapture) {
	t.Helper()
	if len(image.Cases) != casesPerVolume {
		t.Fatal("incomplete produced case manifest")
	}
	checks := map[string]nameWriterCheck{}
	nativeRecords := map[string]diskRecord{}
	for _, r := range source.Records {
		nativeRecords[r.ID] = r
	}
	for i, c := range image.Cases {
		expected := source.Native.Cases[i]
		if c.Payload != "" || len(c.UTF16) != 0 || c.ID != expected.ID || c.Created != expected.Created || c.Queried != expected.Queried || c.Stored != expected.Stored || c.CreateErrno != expected.CreateErrno || c.LookupErrno != expected.LookupErrno || c.Parent == 0 {
			t.Fatal("produced case differs from native input", c.ID)
		}
		if (c.Inode != 0) != (c.CreateErrno == 0) || (c.QueriedInode != 0) != (c.LookupErrno == 0) || (c.LookupErrno == 0 && c.Inode != c.QueriedInode) {
			t.Fatal("produced identity relationship differs", c.ID)
		}
		if strings.HasPrefix(image.Kind, "APFS") && c.CreateErrno == 0 {
			record := apfs.NewDirectoryEntryRecord()
			key, err := hex.DecodeString(c.Key)
			if err != nil {
				t.Fatal(err)
			}
			value, err := hex.DecodeString(c.Value)
			if err != nil {
				t.Fatal(err)
			}
			if err = record.ReadKeyData(key); err != nil {
				t.Fatal(err)
			}
			if err = record.ReadValueData(value); err != nil {
				t.Fatal(err)
			}
			native, ok := nativeRecords[c.ID]
			if !ok || record.ParentIdentifier != c.Parent || record.Identifier != c.Inode || record.NameHash != c.Hash || c.Hash != native.Hash || hex.EncodeToString([]byte(strings.TrimSuffix(string(record.Name), "\x00"))) != c.Stored {
				t.Fatal("produced raw directory record differs", c.ID)
			}
		} else if c.Key != "" || c.Value != "" || c.Hash != 0 {
			t.Fatal("unexpected raw APFS directory record", c.ID)
		}
		if c.CreateErrno != 0 {
			checks["rejected/"+c.ID] = nameWriterCheck{ID: c.ID, Kind: "rejected", First: c.Created, Errno: c.CreateErrno}
		}
		if expected.Same {
			checks["collision/"+c.ID] = nameWriterCheck{ID: c.ID, Kind: "collision", First: c.Created, Second: c.Queried, Errno: 17}
		}
	}
	for _, check := range writerExtraPreflights(t, image.Target, source.Native.Filesystem, source.Native.Sensitive) {
		checks[check.Kind+"/"+check.ID] = check
	}

	validateWriterSpecialManifest(t, image, checks)
	for _, check := range image.Checks {
		key := check.Kind + "/" + check.ID
		if expected, ok := checks[key]; !ok || check != expected {
			t.Fatal("invalid or duplicate zero-write check", key)
		}
		delete(checks, key)
	}
	if len(checks) != 0 {
		t.Fatal("missing zero-write checks")
	}
}
func validateWriterReadback(t *testing.T, raw []byte, image nameWriterImage) {
	t.Helper()
	cases := append(append([]nameWriterRecord{}, image.Cases...), image.ExtraCases...)
	var result struct {
		Count int
		Cases []struct {
			ID      string
			Results []struct {
				Data       string
				Errno      int
				Inode      uint64
				Size, Read int64
			}
			Stored []struct {
				Name  string
				Inode uint64
			}
		}
	}
	decodeWriterNative(t, raw, &result)
	if result.Count != len(cases) || len(result.Cases) != len(cases) {
		t.Fatal("incomplete native readback")
	}
	for i, actual := range result.Cases {
		want := cases[i]
		if actual.ID != want.ID || len(actual.Results) != 2 {
			t.Fatal("native readback case mismatch")
		}
		for j, r := range actual.Results {
			code, inode := want.LookupErrno, want.QueriedInode
			if j == 0 {
				inode = want.Inode
				if want.CreateErrno == 0 {
					code = 0
				}
			}
			payload, err := hex.DecodeString(want.Payload)
			if err != nil {
				t.Fatal(err)
			}
			size, read, data := int64(len(payload)), int64(len(payload)), want.Payload
			if code != 0 {
				size, read, data = 0, -1, ""
			}
			if r.Errno != code || r.Inode != inode || r.Size != size || r.Read != read || r.Data != data {
				t.Fatalf("native produced image mismatch %s/%d: %+v expected errno%d inode%d", want.ID, j, r, code, inode)
			}
		}
		expected := 0
		if want.CreateErrno == 0 {
			expected = 1
		}
		if len(actual.Stored) != expected {
			t.Fatal("native stored-name inventory differs", want.ID)
		}
		if expected == 1 && (actual.Stored[0].Name != want.Stored || actual.Stored[0].Inode != want.Inode) {
			t.Fatal("native stored spelling/identity differs", want.ID, actual.Stored[0], want.Stored)
		}
	}
}
func validateWriterPreflight(t *testing.T, raw []byte, kind string, checks []nameWriterCheck) {
	t.Helper()
	var result struct {
		Filesystem string
		GID        uint32
		MountFlags uint32 `json:"mount_flags"`
		UID        uint32
		Sensitive  bool `json:"case_sensitive"`
		Valid      bool `json:"capability_valid"`
		Cleanup    bool `json:"cleanup_complete"`
		Count      int
		Cases      []struct {
			ID, Kind      string
			FirstErr      int  `json:"first_errno"`
			SecondErr     int  `json:"second_errno"`
			FirstCreated  bool `json:"first_created"`
			SecondCreated bool `json:"second_created"`
		}
	}
	decodeWriterNative(t, raw, &result)
	filesystem := "apfs"
	if strings.HasPrefix(kind, "HFS") {
		filesystem = "hfs"
	}
	if result.Filesystem != filesystem || result.UID == 0 || result.MountFlags&1 != 0 || !result.Valid || result.Sensitive != strings.HasSuffix(kind, "X") || !result.Cleanup || result.Count != len(checks) || len(result.Cases) != len(checks) {
		t.Fatal("incomplete native create context", kind)
	}
	for i, actual := range result.Cases {
		want := checks[i]
		if actual.ID != want.ID || actual.Kind != want.Kind {
			t.Fatal("native create input inventory differs")
		}
		if want.Kind != "collision" && want.Kind != "rejected" {
			t.Fatal("unqualified native create operation", want.Kind)
		}
		code := actual.FirstErr
		if want.Kind == "collision" {
			if actual.FirstErr != 0 || !actual.FirstCreated {
				t.Fatal("native alias initial creation failed", want.ID)
			}
			code = actual.SecondErr
		} else if actual.FirstCreated || actual.SecondErr != 0 {
			t.Fatal("native rejected create changed storage", want.ID)
		}
		if code != want.Errno || actual.SecondCreated {
			t.Fatal("native exclusive-create ordering differs", want.ID, kind, code, want.Errno)
		}
	}
}
func compileWriterOracle(t *testing.T, ctx context.Context, out, sourceName string) (string, map[string]string) {
	t.Helper()
	directory := filepath.Join(out, strings.TrimSuffix(sourceName, ".c"))
	if err := os.Mkdir(directory, 0755); err != nil {
		t.Fatal(err)
	}
	source := "testdata/appledouble/native/" + sourceName
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "probe.c"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	sources := map[string]string{source: sum(raw)}
	sdk, err := command(ctx, "xcrun", "--show-sdk-path")
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := command(ctx, "xcrun", "clang", "--version")
	if err != nil {
		t.Fatal(err)
	}
	toolchain, err := json.Marshal(map[string]string{"compiler": string(compiler), "sdk": strings.TrimSpace(string(sdk))})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "toolchain.json"), toolchain, 0644); err != nil {
		t.Fatal(err)
	}
	sources["toolchain.json"] = sum(toolchain)
	binary := filepath.Join(directory, "probe")
	if _, err = command(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", source, "-o", binary); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	sources["binary"] = sum(raw)
	for _, arch := range []string{"arm64", "x86_64"} {
		raw, err = command(ctx, "xcrun", "clang", "-target", arch+"-apple-macos15", "-isysroot", strings.TrimSpace(string(sdk)), "-std=c11", "-Xclang", "-ast-dump=json", "-fsyntax-only", source)
		if err != nil {
			t.Fatal(err)
		}
		name := arch + ".ast.json"
		sources[name] = sum(raw)
		if err = os.WriteFile(filepath.Join(directory, name), raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, header := range []string{"sys/stat.h", "sys/mount.h", "sys/attr.h", "sys/acl.h", "sys/fcntl.h", "dirent.h", "unistd.h", "sys/errno.h"} {
		raw, err = os.ReadFile(filepath.Join(strings.TrimSpace(string(sdk)), "usr/include", header))
		if err != nil {
			t.Fatal(err)
		}
		name := "SDK/" + header
		sources[name] = sum(raw)
		destination := filepath.Join(directory, name)
		if err = os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(destination, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"scripts/verify-name-writer-native_test.go", "scripts/verify-name-writer_test.go", "go.mod", "go.sum"} {
		raw, err = os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		sources[file] = sum(raw)
	}
	return binary, sources
}
func mountedWriterVolume(t *testing.T, ctx context.Context, out, stem, image string, readonly bool, operation func(string)) {
	t.Helper()
	mount := filepath.Join(out, stem+"-mount")
	if err := os.Mkdir(mount, 0700); err != nil {
		t.Fatal(err)
	}
	device := mount
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		var attempts []map[string]any
		err := diskimage.RetryDetach(cleanup, func() (int, error) {
			raw, err := exec.CommandContext(cleanup, "hdiutil", "detach", device).CombinedOutput()
			code := 0
			if err != nil {
				code = -1
				var exit *exec.ExitError
				if errors.As(err, &exit) {
					code = exit.ExitCode()
				}
			}
			attempts = append(attempts, map[string]any{"device": device, "exit": code, "output": string(raw)})
			return code, err
		})
		raw, marshalErr := json.Marshal(attempts)
		if err = errors.Join(err, marshalErr, os.WriteFile(filepath.Join(out, stem+"-detach.json"), raw, 0644)); err != nil {
			t.Error(err)
		}
	}()
	args := []string{"attach", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", mount}
	if readonly {
		args = append(args, "-readonly")
	}
	args = append(args, image)
	raw, attachErr := command(ctx, "hdiutil", args...)
	parsed, parseErr := diskimage.AttachmentDevice(raw)
	if parsed != "" {
		device = parsed
	}
	recordErr := os.WriteFile(filepath.Join(out, stem+"-attach.plist"), raw, 0644)
	if err := errors.Join(attachErr, parseErr, recordErr); err != nil {
		t.Fatal(err)
	}
	operation(mount)
}

func decodeWriterNative(t *testing.T, raw []byte, destination any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatal("trailing native evidence", err)
	}
}

// Retain even partial stdout and all stderr before reporting an oracle failure.
func runWriterNative(t *testing.T, ctx context.Context, path, binary string, args ...string) []byte {
	t.Helper()
	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(ctx, binary, args...)
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()
	recordErr := errors.Join(os.WriteFile(path, stdout.Bytes(), 0644), os.WriteFile(path+".stderr.txt", stderr.Bytes(), 0644))
	if recordErr != nil {
		t.Fatal(recordErr)
	}
	if runErr != nil {
		message := stderr.String()
		if len(message) > 4096 {
			message = message[:4096] + " [full stderr retained]"
		}
		t.Fatalf("native oracle failed: %v; output retained at %s; stderr: %s", runErr, path, message)
	}
	return stdout.Bytes()
}

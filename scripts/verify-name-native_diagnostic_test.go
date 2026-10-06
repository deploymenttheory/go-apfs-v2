//go:build ignore

// This supplemental diagnostic isolates one native image. It cannot satisfy the
// full cross-version qualification gate and never changes its required count.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

type singleNameCheckpoint struct {
	CaseID           string            `json:"case_id,omitempty"`
	ReferenceCase    *nameCase         `json:"reference_case,omitempty"`
	ReferenceNative  *nativeCase       `json:"reference_native,omitempty"`
	Schema           int               `json:"schema"`
	DiagnosticOnly   bool              `json:"diagnostic_only"`
	Profile          int               `json:"producer_profile"`
	Filesystem       string            `json:"filesystem"`
	ProducerRun      string            `json:"producer_run"`
	ProducerRevision string            `json:"producer_revision"`
	ConsumerRevision string            `json:"consumer_revision"`
	Host             string            `json:"host"`
	Cases            int               `json:"cases"`
	Observations     int               `json:"observations"`
	InputSHA256      map[string]string `json:"input_sha256"`
	SourceSHA256     map[string]string `json:"source_sha256"`
	BinarySHA256     string            `json:"binary_sha256"`
}

func singleNameSelector(profile, kind string) (int, string, error) {
	major, err := strconv.Atoi(profile)
	if err != nil || (major != 15 && major != 26 && major != 27) {
		return 0, "", errors.New("explicit producer profile must be 15, 26, or 27")
	}
	switch kind {
	case "APFS", "APFSX", "HFS+", "HFSX":
	default:
		return 0, "", errors.New("explicit filesystem must be APFS, APFSX, HFS+, or HFSX")
	}
	artifact := map[int]string{15: "name-collation-macos-15", 26: "name-collation-macos-latest", 27: "name-collation-xcode-27"}[major]
	return major, artifact, nil
}

func verifySingleNameSources(root, dir string, got, expected map[string]string) error {
	if len(got) != len(expected) || len(got) == 0 {
		return errors.New("producer source inventory changed")
	}
	for name, want := range got {
		if _, ok := expected[name]; !ok || !fs.ValidPath(name) || strings.Contains(name, "\\") {
			return fmt.Errorf("invalid producer source %q", name)
		}
		path := filepath.Join(dir, filepath.FromSlash(name))
		if name == "native-binary" {
			path = filepath.Join(dir, "probe")
		}
		if strings.HasPrefix(name, "testdata/") || strings.HasPrefix(name, "scripts/") || strings.HasPrefix(name, ".github/") || name == "go.mod" || name == "go.sum" {
			path = filepath.Join(root, filepath.FromSlash(name))
		}
		b, err := os.ReadFile(path)
		if err != nil || sum(b) != want {
			return fmt.Errorf("producer source %s hash: %w", name, errors.Join(err, errors.New("hash mismatch")))
		}
	}
	return nil
}

func validateSingleNameRun(raw []byte, run, revision string) error {
	var observed struct {
		ID         uint64 `json:"id"`
		HeadSHA    string `json:"head_sha"`
		Status     string `json:"status"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(raw, &observed); err != nil {
		return err
	}
	if observed.ID == 0 || strconv.FormatUint(observed.ID, 10) != run || observed.Status != "completed" || observed.Repository.FullName != "deploymenttheory/go-apfs-v2" || len(revision) != 40 || observed.HeadSHA != revision {
		return errors.New("producer run identity/status/revision mismatch")
	}
	return nil
}

func matchSingleNameCheckpoint(raw []byte, expected singleNameCheckpoint) error {
	var observed singleNameCheckpoint
	if err := json.Unmarshal(raw, &observed); err != nil {
		return err
	}
	if !reflect.DeepEqual(expected, observed) {
		return errors.New("durable pre-execution checkpoint no longer matches exact input/source/binary")
	}
	return nil
}

func singleNameInput(t *testing.T) (singleNameCheckpoint, string, string, volumeCapture) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Fatal("native image diagnostic requires Darwin")
	}
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Error(err)
		}
	})
	major, artifact, err := singleNameSelector(os.Getenv("APFS_NAME_DIAGNOSTIC_PROFILE"), os.Getenv("APFS_NAME_DIAGNOSTIC_FILESYSTEM"))
	if err != nil {
		t.Fatal(err)
	}
	base := os.Getenv("APFS_NAME_IMAGE_ARTIFACTS")
	if !filepath.IsAbs(base) {
		t.Fatal("absolute native image artifact directory required")
	}
	dir := filepath.Join(base, artifact)
	fresh := readComparisonCapture(t, filepath.Join(dir, "native.json.gz"), major)
	prior := readComparisonCapture(t, fmt.Sprintf("testdata/appledouble/native/name-collation-macos%d.json.gz", major))
	if err = compareStable(prior, fresh); err != nil {
		t.Fatal(err)
	}
	if err = verifySingleNameSources(root, dir, fresh.Sources, prior.Sources); err != nil {
		t.Fatal(err)
	}
	runPath := os.Getenv("APFS_NAME_DIAGNOSTIC_RUN_MANIFEST")
	raw, err := os.ReadFile(runPath)
	if err != nil {
		t.Fatal(err)
	}
	run := os.Getenv("APFS_NAME_DIAGNOSTIC_RUN")
	if err = validateSingleNameRun(raw, run, fresh.Revision); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "artifacts/name-native-diagnostic")
	if err = os.MkdirAll(out, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(out, "producer-run.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	checkpoint := singleNameCheckpoint{Schema: 1, DiagnosticOnly: true, Profile: major, Filesystem: os.Getenv("APFS_NAME_DIAGNOSTIC_FILESYSTEM"), ProducerRun: run, ProducerRevision: fresh.Revision, Cases: 3753, Observations: 7506, InputSHA256: map[string]string{"producer-run.json": sum(raw)}, SourceSHA256: map[string]string{}}
	for _, name := range []string{"native.json.gz", "cases.tsv"} {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		checkpoint.InputSHA256[name] = sum(b)
	}
	for _, name := range []string{"scripts/verify-name-native_diagnostic_test.go", "scripts/verify-name-native_boundary_test.go", ".github/workflows/name-image-boundary-diagnostic.yml", "scripts/verify-name-native_readback_test.go", "scripts/verify-name-native_commands_test.go", "scripts/verify-name-comparison_test.go", "scripts/capture-name-collation.go", "testdata/appledouble/native/name-readback.c", "go.mod", "go.sum"} {
		b, e := os.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		checkpoint.SourceSHA256[name] = sum(b)
	}
	for _, volume := range fresh.Volumes {
		if volume.Kind == checkpoint.Filesystem {
			name := strings.ReplaceAll(volume.Kind, "+", "plus") + ".dmg"
			b, e := os.ReadFile(filepath.Join(dir, name))
			if e != nil || sum(b) != volume.ImageSHA256 {
				t.Fatal("selected native image hash mismatch", e)
			}
			checkpoint.InputSHA256[name] = sum(b)
			if selector := os.Getenv("APFS_NAME_DIAGNOSTIC_CASE"); selector != "" {
				tsv, e := os.ReadFile(filepath.Join(dir, "cases.tsv"))
				if e != nil {
					t.Fatal(e)
				}
				index, derived, e := selectSingleNameDiagnosticCase(tsv, fresh.Cases, selector)
				if e != nil {
					t.Fatal(e)
				}
				if volume.Native.Cases[index].ID != selector {
					t.Fatal("native reference case mismatch")
				}
				reference := fresh.Cases[index]
				native := volume.Native.Cases[index]
				checkpoint.CaseID, checkpoint.ReferenceCase, checkpoint.ReferenceNative = selector, &reference, &native
				checkpoint.Cases, checkpoint.Observations = 1, 2
				checkpoint.InputSHA256["selected-cases.tsv"] = sum(derived)
				volume.Native.Cases = []nativeCase{native}
			}
			return checkpoint, out, dir, volume

		}
	}
	t.Fatal("selected native volume missing")
	return checkpoint, "", "", volumeCapture{}
}

func TestPrepareNativeSingleNameImageDiagnostic(t *testing.T) {
	checkpoint, out, _, _ := singleNameInput(t)
	if checkpoint.ReferenceCase != nil {
		c := checkpoint.ReferenceCase
		if err := os.WriteFile(filepath.Join(out, "selected-cases.tsv"), []byte(fmt.Sprintf("%s\t%s\t%s\n", c.ID, c.Created, c.Queried)), 0644); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	commands := &nativeCommandRunner{Directory: filepath.Join(out, "build-commands")}
	binary := filepath.Join(out, "native-probe")
	if _, err := commands.run(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "testdata/appledouble/native/name-readback.c", "-o", binary); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name string
		args []string
	}{{"host", []string{"sw_vers"}}, {"revision", []string{"git", "rev-parse", "HEAD"}}, {"compiler", []string{"xcrun", "clang", "--version"}}, {"sdk", []string{"xcrun", "--show-sdk-path"}}} {
		b, err := commands.run(ctx, item.args[0], item.args[1:]...)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(out, item.name+".txt"), b, 0644); err != nil {
			t.Fatal(err)
		}
		checkpoint.SourceSHA256[item.name+".txt"] = sum(b)
		if item.name == "host" {
			checkpoint.Host = string(b)
		}
		if item.name == "revision" {
			checkpoint.ConsumerRevision = strings.TrimSpace(string(b))
		}
	}
	hostMajor, _, err := singleNameSelector(os.Getenv("APFS_NAME_DIAGNOSTIC_HOST"), "APFS")
	if err != nil {
		t.Fatal("explicit diagnostic receiving host profile required", err)
	}
	if err = validateComparisonProfile(capture{Host: checkpoint.Host}, hostMajor); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.BinarySHA256 = sum(b)
	b, err = json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(out, "pre-execution.json"), b, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestNativeSingleNameImageDiagnostic(t *testing.T) {
	checkpoint, out, dir, volume, raw := preparedSingleNameInput(t)
	if checkpoint.CaseID != "" {
		t.Fatal("single-case selection requires the explicit command-boundary route")
	}
	binary := filepath.Join(out, "native-probe")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	commands := &nativeCommandRunner{Directory: filepath.Join(out, "native-commands")}
	actualHost, err := commands.run(ctx, "sw_vers")
	if err != nil || string(actualHost) != checkpoint.Host {
		t.Fatal("receiving host changed after checkpoint", err)
	}
	actualRevision, err := commands.run(ctx, "git", "rev-parse", "HEAD")
	if err != nil || strings.TrimSpace(string(actualRevision)) != checkpoint.ConsumerRevision {
		t.Fatal("consumer revision changed after checkpoint", err)
	}
	nativeImageReadback(t, ctx, commands, out, dir, binary, checkpoint.Profile, volume)
	report := struct {
		DiagnosticOnly bool   `json:"diagnostic_only"`
		Qualification  bool   `json:"qualifies_full_gate"`
		Observations   int    `json:"observations"`
		Checkpoint     string `json:"checkpoint_sha256"`
	}{true, false, 7506, sum(raw)}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(out, "diagnostic-result.json"), b, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestSingleNameDiagnosticValidation(t *testing.T) {
	for _, major := range []string{"15", "26", "27"} {
		for _, kind := range []string{"APFS", "APFSX", "HFS+", "HFSX"} {
			if _, _, err := singleNameSelector(major, kind); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, pair := range [][2]string{{"", "APFS"}, {"16", "APFS"}, {"27", ""}, {"27", "../APFS"}, {"oops", "HFS+"}} {
		if _, _, err := singleNameSelector(pair[0], pair[1]); err == nil {
			t.Fatal("accepted invalid selector", pair)
		}
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cases.tsv"), []byte("genuine"), 0600); err != nil {
		t.Fatal(err)
	}
	good := map[string]string{"cases.tsv": sum([]byte("genuine"))}
	if err := verifySingleNameSources(root, root, good, good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]string{{}, {"cases.tsv": "wrong"}, {"../cases.tsv": good["cases.tsv"]}, {"missing": good["cases.tsv"]}, {"cases.tsv": good["cases.tsv"], "extra": "bad"}} {
		if err := verifySingleNameSources(root, root, bad, good); err == nil {
			t.Fatal("accepted invalid source inventory/hash", bad)
		}
	}
}

func TestSingleNameDiagnosticRunAndCheckpoint(t *testing.T) {
	revision := strings.Repeat("a", 40)
	good := fmt.Sprintf(`{"id":37433253504,"head_sha":%q,"status":"completed","repository":{"full_name":"deploymenttheory/go-apfs-v2"}}`, revision)
	if err := validateSingleNameRun([]byte(good), "37433253504", revision); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"{", good + "{}", strings.Replace(good, "completed", "in_progress", 1), strings.Replace(good, "deploymenttheory/go-apfs-v2", "other/repo", 1), strings.Replace(good, "37433253504", "0", 1), strings.Replace(good, revision, strings.Repeat("b", 40), 1)} {
		if err := validateSingleNameRun([]byte(raw), "37433253504", revision); err == nil {
			t.Fatal("accepted invalid producer run", raw)
		}
	}
	if err := validateSingleNameRun([]byte(good), "different", revision); err == nil {
		t.Fatal("accepted wrong source run selector")
	}
	expected := singleNameCheckpoint{Schema: 1, DiagnosticOnly: true, Profile: 27, Filesystem: "APFS", Cases: 3753, Observations: 7506, InputSHA256: map[string]string{"image": "expected"}, SourceSHA256: map[string]string{"source": "expected"}, BinarySHA256: "expected"}
	raw, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	if err = matchSingleNameCheckpoint(raw, expected); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*singleNameCheckpoint){func(c *singleNameCheckpoint) { c.Profile = 15 }, func(c *singleNameCheckpoint) { c.DiagnosticOnly = false }, func(c *singleNameCheckpoint) { c.Observations = 90072 }, func(c *singleNameCheckpoint) { c.BinarySHA256 = "tampered" }, func(c *singleNameCheckpoint) { c.InputSHA256 = map[string]string{"image": "tampered"} }, func(c *singleNameCheckpoint) { c.SourceSHA256 = nil }} {
		bad := expected
		mutate(&bad)
		b, e := json.Marshal(bad)
		if e != nil {
			t.Fatal(e)
		}
		if matchSingleNameCheckpoint(b, expected) == nil {
			t.Fatal("accepted altered checkpoint")
		}
	}
	if matchSingleNameCheckpoint(append(raw, []byte("{}")...), expected) == nil {
		t.Fatal("accepted trailing checkpoint JSON")
	}
}

func preparedSingleNameInput(t *testing.T) (singleNameCheckpoint, string, string, volumeCapture, []byte) {
	t.Helper()
	expected, out, dir, volume := singleNameInput(t)
	raw, err := os.ReadFile(filepath.Join(out, "pre-execution.json"))
	if err != nil {
		t.Fatal(err)
	}
	var checkpoint singleNameCheckpoint
	if err = json.Unmarshal(raw, &checkpoint); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"host.txt", "revision.txt", "compiler.txt", "sdk.txt"} {
		b, e := os.ReadFile(filepath.Join(out, name))
		if e != nil {
			t.Fatal(e)
		}
		expected.SourceSHA256[name] = sum(b)
		if name == "host.txt" {
			expected.Host = string(b)
		}
		if name == "revision.txt" {
			expected.ConsumerRevision = strings.TrimSpace(string(b))
		}
	}
	binary := filepath.Join(out, "native-probe")
	b, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	expected.BinarySHA256 = sum(b)
	if err = matchSingleNameCheckpoint(raw, expected); err != nil {
		t.Fatal(err)
	}
	if checkpoint.CaseID != "" {
		selected, err := os.ReadFile(filepath.Join(out, "selected-cases.tsv"))
		if err != nil || sum(selected) != checkpoint.InputSHA256["selected-cases.tsv"] {
			t.Fatal("derived selected TSV changed", err)
		}
	}
	return checkpoint, out, dir, volume, raw
}

func selectSingleNameDiagnosticCase(tsv []byte, cases []nameCase, selector string) (int, []byte, error) {
	if selector == "" {
		return -1, nil, errors.New("explicit diagnostic case required")
	}
	lines := strings.Split(strings.TrimSuffix(string(tsv), "\n"), "\n")
	if len(lines) != len(cases) || len(cases) == 0 {
		return -1, nil, errors.New("source TSV inventory mismatch")
	}
	found := -1
	for i, c := range cases {
		if lines[i] != fmt.Sprintf("%s\t%s\t%s", c.ID, c.Created, c.Queried) {
			return -1, nil, errors.New("source TSV differs from retained case bytes")
		}
		if c.ID == selector {
			if found >= 0 {
				return -1, nil, errors.New("ambiguous diagnostic case")
			}
			found = i
		}
	}
	if found < 0 {
		return -1, nil, errors.New("diagnostic case absent from validated source")
	}
	return found, []byte(lines[found] + "\n"), nil
}
func TestSingleNameDiagnosticCaseSelection(t *testing.T) {
	cases := []nameCase{{"ascii", "61", "41"}, {"fold-A7CE", "ea9f8e", "ea9f8f"}}
	source := []byte("ascii\t61\t41\nfold-A7CE\tea9f8e\tea9f8f\n")
	index, selected, err := selectSingleNameDiagnosticCase(source, cases, "fold-A7CE")
	if err != nil || index != 1 || string(selected) != "fold-A7CE\tea9f8e\tea9f8f\n" {
		t.Fatal("exact selected source bytes", index, string(selected), err)
	}
	for _, bad := range []string{"", "unknown", "../ascii"} {
		if _, _, err := selectSingleNameDiagnosticCase(source, cases, bad); err == nil {
			t.Fatal("accepted invalid case", bad)
		}
	}
	for _, bad := range [][]byte{[]byte("ascii\t61\t41\n"), []byte("ascii\t62\t41\nfold-A7CE\tea9f8e\tea9f8f\n"), append(append([]byte(nil), source...), []byte("extra\t61\t41\n")...)} {
		if _, _, err := selectSingleNameDiagnosticCase(bad, cases, "ascii"); err == nil {
			t.Fatal("accepted altered source TSV")
		}
	}
	duplicate := []nameCase{{"ascii", "61", "41"}, {"ascii", "61", "41"}}
	if _, _, err := selectSingleNameDiagnosticCase([]byte("ascii\t61\t41\nascii\t61\t41\n"), duplicate, "ascii"); err == nil {
		t.Fatal("accepted duplicate source case")
	}
}

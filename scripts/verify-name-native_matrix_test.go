//go:build ignore

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

type nativeNameMatrixReport struct {
	Schema       int               `json:"schema"`
	Selection    nativeNameCell    `json:"selection"`
	Host         string            `json:"host"`
	Revision     string            `json:"revision"`
	Sources      map[string]string `json:"source_sha256"`
	Inputs       map[string]string `json:"input_sha256"`
	Evidence     map[string]string `json:"evidence_sha256"`
	Observations int               `json:"observations"`
	Profiles     int               `json:"producer_profiles"`
	Volumes      int               `json:"volumes"`
}

func requiredNativeNameCells() []nativeNameCell {
	var cells []nativeNameCell
	for _, producer := range []int{15, 26, 27} {
		for _, receiver := range []int{15, 26, 27} {
			for _, filesystem := range []string{"APFS", "APFSX", "HFS+", "HFSX"} {
				cells = append(cells, nativeNameCell{producer, receiver, filesystem})
			}
		}
	}
	return cells
}

func nativeNameCellArtifact(c nativeNameCell) string {
	return fmt.Sprintf("name-native-cell-%d-%d-%s", c.Producer, c.Receiver, c.Filesystem)
}

func validateNativeNameCellReport(r nativeNameMatrixReport, cell nativeNameCell, revision string) error {
	if r.Schema != 2 || r.Selection != cell || r.Observations != 7506 || r.Profiles != 1 || r.Volumes != 1 || len(revision) != 40 || r.Revision != revision {
		return errors.New("incomplete, mismatched or stale native matrix report")
	}
	v, err := osversion.ParseProductVersion(r.Host)
	if err != nil || int(v.Major) != cell.Receiver {
		return errors.New("actual native receiver does not match matrix cell")
	}
	return nil
}

func validateNativeNameCellInventory(names []string) error {
	want := map[string]bool{}
	for _, cell := range requiredNativeNameCells() {
		want[nativeNameCellArtifact(cell)] = true
	}
	if len(names) != len(want) {
		return fmt.Errorf("native matrix has %d cells, requires %d", len(names), len(want))
	}
	for _, name := range names {
		if !want[name] {
			return fmt.Errorf("duplicate or unexpected native matrix cell %q", name)
		}
		delete(want, name)
	}
	return nil
}

// Both the requested image subtest and its enclosing test/package must finish.
// A report alone cannot establish successful process completion.
func validateNativeNameCellTranscript(raw []byte, cell nativeNameCell) error {
	want := map[string]bool{
		"":                                 false,
		"TestNativeCrossVersionNameImages": false,
		fmt.Sprintf("TestNativeCrossVersionNameImages/%d/%s", cell.Producer, cell.Filesystem): false,
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	for {
		var event struct{ Action, Test string }
		err := decoder.Decode(&event)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if event.Action == "fail" || event.Action == "skip" {
			return errors.New("failed or skipped native qualification")
		}
		if event.Action == "pass" {
			passed, exists := want[event.Test]
			if !exists || passed {
				return errors.New("unexpected or repeated native completion")
			}
			want[event.Test] = true
		}
	}
	for _, passed := range want {
		if !passed {
			return errors.New("unfinished native qualification")
		}
	}
	return nil
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

func TestQualifyNativeNameMatrix(t *testing.T) {
	base := os.Getenv("APFS_NAME_MATRIX_ARTIFACTS")
	inputs := os.Getenv("APFS_NAME_IMAGE_ARTIFACTS")
	revision := os.Getenv("GITHUB_SHA")
	if !filepath.IsAbs(base) || !filepath.IsAbs(inputs) || len(revision) != 40 {
		t.Fatal("absolute artifact roots and exact CI revision required")
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() {
			t.Fatal("non-directory matrix artifact", entry.Name())
		}
		names = append(names, entry.Name())
	}
	if err = validateNativeNameCellInventory(names); err != nil {
		t.Fatal(err)
	}
	for _, cell := range requiredNativeNameCells() {
		t.Run(nativeNameCellArtifact(cell), func(t *testing.T) {
			dir := filepath.Join(base, nativeNameCellArtifact(cell))
			out := filepath.Join(dir, "name-native-readback")
			read := func(path string) []byte {
				t.Helper()
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			var report nativeNameMatrixReport
			if err := json.Unmarshal(read(filepath.Join(out, "report.json")), &report); err != nil {
				t.Fatal(err)
			}
			if err := validateNativeNameCellReport(report, cell, revision); err != nil {
				t.Fatal(err)
			}
			if err := validateNativeNameCellTranscript(read(filepath.Join(dir, "name-native-readback-tests.jsonl")), cell); err != nil {
				t.Fatal(err)
			}
			if err := verifyNativeNameEvidence(out, report.Evidence); err != nil {
				t.Fatal(err)
			}
			sources, err := captureprovenance.Inventory(os.DirFS(".."))
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range nativeNameHarnessSources {
				sources[path] = sum(read(filepath.Join("..", filepath.FromSlash(path))))
			}
			for _, path := range []string{"arm64.ast.json", "x86_64.ast.json", "SDK/sys/stat.h", "SDK/sys/fcntl.h", "SDK/unistd.h", "SDK/sys/errno.h"} {
				sources[path] = sum(read(filepath.Join(out, filepath.FromSlash(path))))
			}
			sources["native-binary"] = sum(read(filepath.Join(out, "probe")))
			if !reflect.DeepEqual(sources, report.Sources) {
				t.Fatal("native source inventory or content changed")
			}
			artifact := map[int]string{15: "name-collation-macos-15", 26: "name-collation-macos-latest", 27: "name-collation-xcode-27"}[cell.Producer]
			producerDir := filepath.Join(inputs, artifact)
			producerRaw := read(filepath.Join(producerDir, "native.json.gz"))
			producer := readComparisonCapture(t, filepath.Join(producerDir, "native.json.gz"), cell.Producer)
			if producer.Revision != revision {
				t.Fatal("producer revision differs from receiver")
			}
			image := strings.ReplaceAll(cell.Filesystem, "+", "plus") + ".dmg"
			expectedInputs := map[string]string{
				artifact + "/native.json.gz": sum(producerRaw),
				artifact + "/cases.tsv":      sum(read(filepath.Join(producerDir, "cases.tsv"))),
				artifact + "/" + image:       sum(read(filepath.Join(producerDir, image))),
			}
			if !reflect.DeepEqual(expectedInputs, report.Inputs) {
				t.Fatal("matrix input hashes differ from genuine producer")
			}
			stem := fmt.Sprintf("%d-%s", cell.Producer, strings.ReplaceAll(cell.Filesystem, "+", "plus"))
			matched := 0
			for _, volume := range producer.Volumes {
				if volume.Kind == cell.Filesystem {
					matched++
					if volume.ImageSHA256 != expectedInputs[artifact+"/"+image] {
						t.Fatal("producer image hash mismatch")
					}
					validateNativeNameReadback(t, read(filepath.Join(out, stem+"-readback.json")), volume)
				}
			}
			if matched != 1 {
				t.Fatal("missing or duplicated source volume")
			}
			for _, suffix := range []string{"-attach.plist", "-detach.json"} {
				if len(read(filepath.Join(out, stem+suffix))) == 0 {
					t.Fatal("missing mount lifecycle evidence")
				}
			}
		})
	}
}

func TestNativeNameMatrixSelection(t *testing.T) {
	for _, cell := range requiredNativeNameCells() {
		got, err := nativeNameSelection(strconv.Itoa(cell.Producer), strconv.Itoa(cell.Receiver), cell.Filesystem)
		if err != nil || got != cell {
			t.Fatalf("selection %+v: %+v %v", cell, got, err)
		}
	}
	if got, err := nativeNameSelection("", "", ""); err != nil || got != (nativeNameCell{}) {
		t.Fatal(got, err)
	}
	for _, values := range [][3]string{{"", "15", "APFS"}, {"15", "", "APFS"}, {"15", "15", ""}, {"14", "15", "APFS"}, {"15", "28", "APFS"}, {"15", "15", "apfs"}, {"+15", "15", "APFS"}, {"015", "15", "APFS"}} {
		if _, err := nativeNameSelection(values[0], values[1], values[2]); err == nil {
			t.Fatal("accepted invalid selector", values)
		}
	}
}

func TestNativeNameMatrixInventory(t *testing.T) {
	var names []string
	for _, cell := range requiredNativeNameCells() {
		names = append(names, nativeNameCellArtifact(cell))
	}
	if len(names) != 36 {
		t.Fatal("matrix reduced", len(names))
	}
	if err := validateNativeNameCellInventory(names); err != nil {
		t.Fatal(err)
	}
	duplicate := append([]string(nil), names...)
	duplicate[0] = duplicate[1]
	unknown := append([]string(nil), names...)
	unknown[0] = "unexpected"
	for _, bad := range [][]string{nil, names[:35], append(append([]string(nil), names...), "extra"), duplicate, unknown} {
		if err := validateNativeNameCellInventory(bad); err == nil {
			t.Fatal("accepted incomplete matrix", bad)
		}
	}
}

func TestNativeNameMatrixReport(t *testing.T) {
	cell := nativeNameCell{26, 15, "APFS"}
	revision := strings.Repeat("a", 40)
	valid := nativeNameMatrixReport{Schema: 2, Selection: cell, Host: "ProductVersion: 15.7.9", Revision: revision, Observations: 7506, Profiles: 1, Volumes: 1}
	if err := validateNativeNameCellReport(valid, cell, revision); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*nativeNameMatrixReport){
		func(r *nativeNameMatrixReport) { r.Schema = 1 },
		func(r *nativeNameMatrixReport) { r.Selection.Producer = 15 },
		func(r *nativeNameMatrixReport) { r.Selection.Receiver = 27 },
		func(r *nativeNameMatrixReport) { r.Selection.Filesystem = "HFSX" },
		func(r *nativeNameMatrixReport) { r.Host = "ProductVersion: 26.6.2" },
		func(r *nativeNameMatrixReport) { r.Host = "unknown" },
		func(r *nativeNameMatrixReport) { r.Revision = strings.Repeat("b", 40) },
		func(r *nativeNameMatrixReport) { r.Observations-- },
		func(r *nativeNameMatrixReport) { r.Profiles++ },
		func(r *nativeNameMatrixReport) { r.Volumes++ },
	} {
		r := valid
		mutate(&r)
		if err := validateNativeNameCellReport(r, cell, revision); err == nil {
			t.Fatal("accepted invalid report", r)
		}
	}
	if err := validateNativeNameCellReport(valid, cell, ""); err == nil {
		t.Fatal("accepted missing revision")
	}
}

func TestNativeNameMatrixTranscript(t *testing.T) {
	cell := nativeNameCell{26, 15, "APFS"}
	sub := `{"Action":"pass","Test":"TestNativeCrossVersionNameImages/26/APFS"}` + "\n"
	parent := `{"Action":"pass","Test":"TestNativeCrossVersionNameImages"}` + "\n"
	end := `{"Action":"pass"}` + "\n"
	if err := validateNativeNameCellTranscript([]byte(sub+parent+end), cell); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", "{", sub + parent, sub + end, parent + end, sub + parent + end + end, sub + parent + end + `{"Action":"skip"}`, sub + parent + end + `{"Action":"fail"}`, sub + parent + end + `{"Action":"pass","Test":"other"}`} {
		if err := validateNativeNameCellTranscript([]byte(raw), cell); err == nil {
			t.Fatal("accepted invalid transcript", raw)
		}
	}
}

func TestNativeNameMatrixEvidence(t *testing.T) {
	dir := t.TempDir()
	data := []byte("retained raw observation")
	if err := os.WriteFile(filepath.Join(dir, "raw"), data, 0600); err != nil {
		t.Fatal(err)
	}
	valid := map[string]string{"raw": sum(data)}
	if err := verifyNativeNameEvidence(dir, valid); err != nil {
		t.Fatal(err)
	}
	for _, hashes := range []map[string]string{nil, {"../outside": sum(data)}, {"bad\\path": sum(data)}, {"report.json": sum(data)}, {"raw": "changed"}, {"missing": sum(data)}} {
		if err := verifyNativeNameEvidence(dir, hashes); err == nil {
			t.Fatal("accepted invalid evidence", hashes)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "extra"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyNativeNameEvidence(dir, valid); err == nil {
		t.Fatal("accepted unlisted evidence")
	}
}

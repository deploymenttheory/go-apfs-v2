//go:build ignore

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

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
	if r.Schema != 3 || r.Reference || r.Preparation || r.Selection != cell || !nativeReportComplete(r, cell) || len(revision) != 40 || r.Revision != revision {
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
	return validateNativeNameTranscript(raw, cell, "TestNativeCrossVersionNameImages")
}
func validateNativeNameTranscript(raw []byte, cell nativeNameCell, test string) error {

	want := map[string]bool{
		"":   false,
		test: false,
		fmt.Sprintf("%s/%d/%s", test, cell.Producer, cell.Filesystem): false,
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

func TestQualifyNativeNameMatrix(t *testing.T) {
	// Producer captures and receiver references bind repository-root paths.
	t.Chdir("..")
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
			if err := validateNativeNameTranscript(read(filepath.Join(dir, "name-native-reference-tests.jsonl")), cell, "TestCaptureNativeNameReceiver"); err != nil {
				t.Fatal(err)
			}
			if err := verifyNativeNameEvidence(out, report.Evidence); err != nil {
				t.Fatal(err)
			}
			sources, err := captureprovenance.Inventory(os.DirFS("."))
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range nativeNameHarnessSources {
				sources[path] = sum(read(filepath.FromSlash(path)))
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
			incompatible := false
			for _, volume := range producer.Volumes {
				if volume.Kind == cell.Filesystem {
					matched++
					if volume.ImageSHA256 != expectedInputs[artifact+"/"+image] {
						t.Fatal("producer image hash mismatch")
					}
					want, record, err := loadNativeReceiverReference(filepath.Join(out, "reference"), cell, report.Host, volume, producerDir)
					if err != nil {
						t.Fatal(err)
					}
					if record != nil {
						// The receiver must not have mounted this image; its replay
						// record must equal the re-derived reference record.
						expected, err := json.MarshalIndent(record, "", "  ")
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(read(filepath.Join(out, stem+"-forward-incompatible.json")), append(expected, '\n')) || report.Observations != 0 || report.Incompatible != 1 {
							t.Fatal("forward-incompatible cell record differs from the images")
						}
						for _, suffix := range []string{"-attach.plist", "-detach.json", "-readback.json"} {
							if _, err := os.Stat(filepath.Join(out, stem+suffix)); err == nil {
								t.Fatal("forward-incompatible cell mounted the image")
							}
						}
						incompatible = true
						continue
					}
					if report.Incompatible != 0 {
						t.Fatal("mountable cell reported a forward-incompatible volume")
					}
					if err = compareNativeReceiver(read(filepath.Join(out, stem+"-readback.json")), want, volume.Native.Cases); err != nil {
						t.Fatal(err)
					}
				}
			}
			if matched != 1 {
				t.Fatal("missing or duplicated source volume")
			}
			if incompatible {
				return
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
	valid := nativeNameMatrixReport{Schema: 3, Selection: cell, Host: "ProductVersion: 15.7.9", Revision: revision, Observations: 7506, Profiles: 1, Volumes: 1}
	if err := validateNativeNameCellReport(valid, cell, revision); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*nativeNameMatrixReport){
		func(r *nativeNameMatrixReport) { r.Schema = 1 },
		func(r *nativeNameMatrixReport) { r.Reference = true },
		func(r *nativeNameMatrixReport) { r.Preparation = true },
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

func TestNativeNameMatrixReceiverResults(t *testing.T) {
	producer := []nativeCase{{ID: "fold-A7CE", Inode: 42, QueriedInode: 42}}
	// Historical native macOS15 outcome on the specific macOS26 diagnostic
	// image. This is not an error policy for any other filename or image.
	stream := []byte("fold-A7CE\t0\t22\t0\t0\t-1\tclosed\nfold-A7CE\t1\t2\t0\t0\t-1\tclosed\ncomplete\t1\n")
	reference, err := parseNativeReceiver(stream, producer)
	if err != nil {
		t.Fatal(err)
	}
	if err = compareNativeReceiver(reference, reference, producer); err != nil {
		t.Fatal(err)
	}
	if err = compareNativeReceiver(bytes.Replace(reference, []byte(`"errno":22`), []byte(`"errno":0`), 1), reference, producer); err == nil {
		t.Fatal("accepted changed receiver outcome")
	}
	good := []byte(`{"count":1,"cases":[{"id":"fold-A7CE","results":[{"errno":0,"inode":42,"size":0,"read":0},{"errno":0,"inode":42,"size":0,"read":0}]}]}`)
	if _, err = validateNativeObservations(good, producer, 1); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]byte{
		"missing-read":  bytes.Replace(good, []byte(`,"read":0`), nil, 1),
		"missing-size":  bytes.Replace(good, []byte(`,"size":0`), nil, 1),
		"missing-errno": bytes.Replace(good, []byte(`"errno":0,`), nil, 1),
		"null-errno":    bytes.Replace(good, []byte(`"errno":0`), []byte(`"errno":null`), 1),
		"missing-case":  []byte(`{"count":1,"cases":[]}`), "malformed": []byte("{"), "trailing": append(append([]byte{}, good...), []byte(` {}`)...),
		"unknown":      bytes.Replace(good, []byte(`"count":1`), []byte(`"count":1,"unexpected":true`), 1),
		"count":        bytes.Replace(good, []byte(`"count":1`), []byte(`"count":2`), 1),
		"identity":     bytes.Replace(good, []byte(`"inode":42`), []byte(`"inode":43`), 1),
		"nonempty":     bytes.Replace(good, []byte(`"size":0`), []byte(`"size":1`), 1),
		"read":         bytes.Replace(good, []byte(`"read":0`), []byte(`"read":1`), 1),
		"case":         bytes.Replace(good, []byte(`fold-A7CE`), []byte(`other`), 1),
		"negative":     bytes.Replace(reference, []byte(`"errno":22`), []byte(`"errno":-1`), 1),
		"failed-inode": bytes.Replace(reference, []byte(`"inode":0`), []byte(`"inode":42`), 1),
		"failed-size":  bytes.Replace(reference, []byte(`"size":0`), []byte(`"size":1`), 1),
		"failed-read":  bytes.Replace(reference, []byte(`"read":-1`), []byte(`"read":0`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateNativeObservations(bad, producer, 1); err == nil {
				t.Fatal("accepted invalid native observations")
			}
		})
	}
	for _, bad := range [][]byte{nil, stream[:len(stream)-1], append(append([]byte{}, stream...), []byte("extra\n")...), bytes.Replace(stream, []byte("complete\t1"), []byte("complete\t0"), 1), bytes.Replace(stream, []byte("\tclosed"), []byte("\topen"), 1), bytes.Replace(stream, []byte("\t22\t"), []byte("\tx\t"), 1), bytes.Replace(stream, []byte("fold-A7CE\t1"), []byte("fold-A7CE\t0"), 1), bytes.Replace(stream, []byte("\t0\t0\t-1"), []byte("\tx\t0\t-1"), 1)} {
		if _, err := parseNativeReceiver(bad, producer); err == nil {
			t.Fatal("accepted incomplete reference stream")
		}
	}
	if _, err := validateNativeObservations(good, nil, 0); err == nil {
		t.Fatal("accepted empty expected inventory")
	}
	if err := compareNativeReceiver(good, nil, producer); err == nil {
		t.Fatal("accepted missing reference")
	}
	if err := compareNativeReceiver(good, reference, producer); err == nil {
		t.Fatal("accepted producer success in place of receiver error")
	}
	duplicate := []nativeCase{producer[0], producer[0]}
	var value nativeNameReadback
	if err := json.Unmarshal(good, &value); err != nil {
		t.Fatal(err)
	}
	value.Count = 2
	value.Cases = append(value.Cases, value.Cases[0])
	raw, _ := json.Marshal(value)
	if _, err := validateNativeObservations(raw, duplicate, 2); err == nil {
		t.Fatal("accepted duplicate case IDs")
	}
	producer[0].CreateErrno = 92
	if _, err := validateNativeObservations(good, producer, 1); err == nil {
		t.Fatal("accepted nonexistent producer object")
	}
}

func TestNativeNameMatrixReceiverLifecycle(t *testing.T) {
	attached := []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>system-entities</key><array><dict><key>dev-entry</key><string>/dev/disk6</string></dict></array></dict></plist>`)
	detached := []byte(`[{"device":"/dev/disk6","exit_code":0,"output":"detached"}]`)
	if err := validateNativeReceiverLifecycle(attached, detached); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "null", "[]", `[{"device":"/dev/disk6"}]`, `[{"device":"/dev/disk6","exit_code":null}]`, `[{"device":"/dev/disk6","exit_code":1}]`, `[{"device":"/dev/disk7","exit_code":0}]`, `[{"device":"/dev/disk6","exit_code":0},{"device":"/dev/disk6","exit_code":0}]`} {
		if err := validateNativeReceiverLifecycle(attached, []byte(bad)); err == nil {
			t.Fatal("accepted missing/invalid detach", bad)
		}
	}
	if err := validateNativeReceiverLifecycle(nil, detached); err == nil {
		t.Fatal("accepted missing attachment")
	}
	if err := validateNativeReceiverLifecycle(attached, []byte(`[{"device":"/dev/disk6","exit_code":1},{"device":"/dev/disk6","exit_code":0}]`)); err != nil {
		t.Fatal(err)
	}
}

func TestNativeNameMatrixHistoricalReceiverEvidence(t *testing.T) {
	dir := "../testdata/appledouble/native/name-receiver-macos15-a7ce"
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var metadata struct{ Host, Revision string }
	if err := json.Unmarshal(read("metadata.json"), &metadata); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(metadata.Host, "15.7.9") || metadata.Revision != "7e6554ac8f41a62af1f8cffe6950aa06c400e86f" {
		t.Fatal("historical provenance changed")
	}
	var completion struct {
		Exit         int  `json:"exit_code"`
		Full         bool `json:"qualifies_full_gate"`
		Diagnostic   bool `json:"diagnostic_only"`
		Observations int  `json:"observations"`
	}
	if err := json.Unmarshal(read("raw-completion.json"), &completion); err != nil {
		t.Fatal(err)
	}
	if completion.Exit != 0 || completion.Full || !completion.Diagnostic || completion.Observations != 4 {
		t.Fatal("invalid historical completion")
	}
	var observed nativeNameReadback
	finished := false
	for _, line := range bytes.Split(bytes.TrimSpace(read("raw-native.jsonl")), []byte("\n")) {
		var r struct {
			Type, ID             string
			Results              []nativeNameResult
			Count, Error         int
			Cleanup              int `json:"cleanup_errno"`
			Stopped, Interrupted bool
		}
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		if r.Type == "case" {
			if r.Interrupted {
				t.Fatal("interrupted evidence")
			}
			observed.Cases = append(observed.Cases, nativeNameObservation{r.ID, r.Results})
		}
		if r.Type == "finished" {
			if r.Error != 0 || r.Cleanup != 0 || r.Stopped || r.Count != 2 {
				t.Fatal("incomplete historical process")
			}
			finished = true
			observed.Count = r.Count
		}
	}
	if !finished || len(observed.Cases) != 2 || observed.Cases[1].ID != "fold-A7CE" {
		t.Fatal("missing genuine native case")
	}
	if observed.Cases[1].Results[0] != (nativeNameResult{22, 0, 0, -1}) || observed.Cases[1].Results[1] != (nativeNameResult{2, 0, 0, -1}) {
		t.Fatal("historical errno changed")
	}
	raw, _ := json.Marshal(observed)
	producer := []nativeCase{{ID: "ascii", Inode: 18, QueriedInode: 18}, {ID: "fold-A7CE", Inode: 19, QueriedInode: 19}}
	if _, err := validateNativeObservations(raw, producer, 2); err != nil {
		t.Fatal(err)
	}
}

func stubAPFSVolumeVersions(t *testing.T, versions map[string][2]string) {
	t.Helper()
	prior := readAPFSVolumeVersions
	readAPFSVolumeVersions = func(image string) (string, string, error) {
		v, ok := versions[filepath.Base(filepath.Dir(image))+"/"+filepath.Base(image)]
		if !ok {
			return "", "", fmt.Errorf("unexpected image %s", image)
		}
		return v[0], v[1], nil
	}
	t.Cleanup(func() { readAPFSVolumeVersions = prior })
}

func TestNativeNameForwardIncompatibility(t *testing.T) {
	for id, want := range map[string]int{"newfs_apfs (2811.160.7.0.4)": 2811, "apfs_kext (2332.140.13.702.2)": 2332, "newfs_apfs (3288.1.3)": 3288, "apfs_kext (2632.0.84)": 2632} {
		if got, err := apfsVersionLine(id); err != nil || got != want {
			t.Fatalf("%q: %d %v", id, got, err)
		}
	}
	for _, bad := range []string{"", "go-apfs (apfswrite)", "newfs_apfs 2811.1", "newfs_apfs ()", "newfs_apfs (2811.1) extra", "NEWFS (2811)"} {
		if _, err := apfsVersionLine(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	for _, c := range []struct {
		receiver, image int
		want            bool
	}{{2332, 2811, true}, {2332, 3288, true}, {2317, 2632, true}, {2332, 2332, false}, {2332, 2313, false}, {2811, 3288, false}, {3288, 2811, false}, {2632, 2811, false}, {2811, 2332, false}} {
		if got := forwardIncompatibleAPFS(c.receiver, c.image); got != c.want {
			t.Fatalf("receiver %d image %d: %v", c.receiver, c.image, got)
		}
	}
	base := t.TempDir()
	write := func(path string, b []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	producer := filepath.Join(base, "name-collation-macos-latest")
	write(filepath.Join(producer, "APFS.dmg"), []byte("newer image"))
	write(filepath.Join(producer, "APFSX.dmg"), []byte("newer sensitive image"))
	write(filepath.Join(base, "name-collation-macos-15", "APFS.dmg"), []byte("receiver image"))
	write(filepath.Join(base, "name-collation-macos-15", "APFSX.dmg"), []byte("receiver sensitive image"))
	write(filepath.Join(base, "name-collation-xcode-27", "APFS.dmg"), []byte("newest image"))
	stubAPFSVolumeVersions(t, map[string][2]string{
		"name-collation-macos-latest/APFS.dmg":  {"newfs_apfs (2811.160.7.0.4)", "apfs_kext (2811.160.7.0.4)"},
		"name-collation-macos-latest/APFSX.dmg": {"newfs_apfs (2811.160.7.0.4)", "newfs_apfs (2811.160.7.0.4)"},
		"name-collation-macos-15/APFS.dmg":      {"newfs_apfs (2332.140.13.702.2)", "apfs_kext (2332.140.13.702.2)"},
		"name-collation-macos-15/APFSX.dmg":     {"newfs_apfs (2332.140.13.702.2)", "newfs_apfs (2332.140.13.702.2)"},
		"name-collation-xcode-27/APFS.dmg":      {"newfs_apfs (3288.1.3)", "apfs_kext (3288.1.3)"},
	})
	host := "ProductVersion: 15.7.9"
	v := volumeCapture{Kind: "APFS", ImageSHA256: sum([]byte("newer image"))}
	record, err := nativeForwardIncompatible(host, nativeNameCell{26, 15, "APFS"}, v, base, producer)
	if err != nil || record == nil {
		t.Fatal(record, err)
	}
	want := &nativeForwardIncompatibility{Schema: 1, Outcome: nativeForwardIncompatibleOutcome, Producer: 26, Receiver: 15, Filesystem: "APFS", Host: host, ImageSHA256: v.ImageSHA256, ImageFormattedBy: "newfs_apfs (2811.160.7.0.4)", ImageModifiedBy: "apfs_kext (2811.160.7.0.4)", ImageLine: 2811, ReceiverImage: sum([]byte("receiver image")), ReceiverKext: "apfs_kext (2332.140.13.702.2)", ReceiverLine: 2332, Rule: nativeForwardIncompatibleRule}
	if !reflect.DeepEqual(record, want) {
		t.Fatalf("record %+v", record)
	}
	// Same line, HFS, and a receiver newer than the image never produce a record.
	if r, err := nativeForwardIncompatible(host, nativeNameCell{26, 26, "APFS"}, v, base, producer); err != nil || r != nil {
		t.Fatal(r, err)
	}
	if r, err := nativeForwardIncompatible(host, nativeNameCell{26, 15, "HFS+"}, volumeCapture{Kind: "HFS+"}, base, producer); err != nil || r != nil {
		t.Fatal(r, err)
	}
	if r, err := nativeForwardIncompatible("ProductVersion: 27.0.1", nativeNameCell{26, 27, "APFS"}, v, base, producer); err != nil || r != nil {
		t.Fatal(r, err)
	}
	// A tampered image, an image whose receiver evidence was not written by the
	// receiver kernel, and a receiver without its own producer artifact all fail.
	if _, err := nativeForwardIncompatible(host, nativeNameCell{26, 15, "APFS"}, volumeCapture{Kind: "APFS", ImageSHA256: "0"}, base, producer); err == nil {
		t.Fatal("accepted image hash mismatch")
	}
	if _, err := nativeForwardIncompatible(host, nativeNameCell{26, 15, "APFSX"}, volumeCapture{Kind: "APFSX", ImageSHA256: sum([]byte("newer sensitive image"))}, base, producer); err == nil {
		t.Fatal("accepted receiver evidence not written by the receiver kernel")
	}
	if _, err := nativeForwardIncompatible(host, nativeNameCell{26, 14, "APFS"}, v, base, producer); err == nil {
		t.Fatal("accepted unknown receiver")
	}
}

func TestNativeNameForwardIncompatibleReference(t *testing.T) {
	t.Chdir("..")
	cell := nativeNameCell{26, 15, "APFS"}
	host := "ProductVersion: 15.7.9"
	for _, mutation := range []string{"valid", "tampered", "mount-evidence", "missing-record", "observations-claimed"} {
		t.Run(mutation, func(t *testing.T) {
			base := t.TempDir()
			out := filepath.Join(base, "reference")
			input := filepath.Join(base, "name-collation-macos-latest")
			write := func(path string, b []byte) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			revision := strings.Repeat("b", 40)
			var compressed bytes.Buffer
			z := gzip.NewWriter(&compressed)
			if err := json.NewEncoder(z).Encode(map[string]string{"Revision": revision}); err != nil {
				t.Fatal(err)
			}
			if err := z.Close(); err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(input, "native.json.gz"), compressed.Bytes())
			write(filepath.Join(input, "cases.tsv"), []byte("producer manifest"))
			write(filepath.Join(input, "APFS.dmg"), []byte("newer image"))
			write(filepath.Join(base, "name-collation-macos-15", "APFS.dmg"), []byte("receiver image"))
			stubAPFSVolumeVersions(t, map[string][2]string{
				"name-collation-macos-latest/APFS.dmg": {"newfs_apfs (2811.160.7.0.4)", "apfs_kext (2811.160.7.0.4)"},
				"name-collation-macos-15/APFS.dmg":     {"newfs_apfs (2332.140.13.702.2)", "apfs_kext (2332.140.13.702.2)"},
			})
			for _, name := range []string{"arm64.ast.json", "x86_64.ast.json", "SDK/sys/stat.h", "SDK/sys/fcntl.h", "SDK/unistd.h", "SDK/sys/errno.h", "probe"} {
				write(filepath.Join(out, name), []byte(name))
			}
			sources, err := nativeNameSourceInventory(out)
			if err != nil {
				t.Fatal(err)
			}
			v := volumeCapture{Kind: "APFS", ImageSHA256: sum([]byte("newer image"))}
			for i := 0; i < casesPerVolume; i++ {
				v.Native.Cases = append(v.Native.Cases, nativeCase{ID: fmt.Sprintf("case-%d", i)})
			}
			record, err := nativeForwardIncompatible(host, cell, v, base, input)
			if err != nil || record == nil {
				t.Fatal(record, err)
			}
			encoded, err := json.MarshalIndent(record, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			encoded = append(encoded, '\n')
			switch mutation {
			case "tampered":
				encoded = bytes.Replace(encoded, []byte("2811"), []byte("2632"), 1)
			case "mount-evidence":
				write(filepath.Join(out, "26-APFS-attach.plist"), []byte("attached"))
			}
			if mutation != "missing-record" {
				write(filepath.Join(out, "26-APFS-forward-incompatible.json"), encoded)
			}
			r := nativeNameMatrixReport{Schema: 3, Reference: true, Selection: cell, Host: host, Revision: revision, Sources: sources, Inputs: map[string]string{}, Evidence: map[string]string{}, Observations: 0, Incompatible: 1, Profiles: 1, Volumes: 1}
			if mutation == "observations-claimed" {
				r.Observations = casesPerVolume * 2
			}
			for _, name := range []string{"native.json.gz", "cases.tsv", "APFS.dmg"} {
				b, err := os.ReadFile(filepath.Join(input, name))
				if err != nil {
					t.Fatal(err)
				}
				r.Inputs[filepath.Base(input)+"/"+name] = sum(b)
			}
			if err = filepath.WalkDir(out, func(path string, entry os.DirEntry, err error) error {
				if err != nil || entry.IsDir() {
					return err
				}
				b, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				rel, err := filepath.Rel(out, path)
				if err != nil {
					return err
				}
				r.Evidence[filepath.ToSlash(rel)] = sum(b)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			b, err := json.MarshalIndent(r, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(out, "report.json"), b)
			observations, got, err := loadNativeReceiverReference(out, cell, host, v, input)
			if mutation == "valid" {
				if err != nil || observations != nil || !reflect.DeepEqual(got, record) {
					t.Fatal(got, err)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted", mutation)
			}
		})
	}
}

func TestNativeNameMatrixReceiverReference(t *testing.T) {
	t.Chdir("..")
	cell := nativeNameCell{27, 27, "APFS"}
	host := "ProductVersion: 27.0.1"
	stubAPFSVolumeVersions(t, map[string][2]string{"name-collation-xcode-27/APFS.dmg": {"newfs_apfs (3288.1.3)", "apfs_kext (3288.1.3)"}})
	for _, mutation := range []string{"valid", "missing-report", "schema", "preparation", "not-reference", "host", "selection", "inventory", "revision", "sources", "inputs", "extra-input", "hash", "missing-raw", "truncated-raw", "changed-observations", "missing-detach", "failed-detach"} {
		t.Run(mutation, func(t *testing.T) {
			base := t.TempDir()
			out := filepath.Join(base, "reference")
			input := filepath.Join(base, "name-collation-xcode-27")
			write := func(path string, b []byte) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			revision := strings.Repeat("a", 40)
			var compressed bytes.Buffer
			z := gzip.NewWriter(&compressed)
			if err := json.NewEncoder(z).Encode(map[string]string{"Revision": revision}); err != nil {
				t.Fatal(err)
			}
			if err := z.Close(); err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(input, "native.json.gz"), compressed.Bytes())
			write(filepath.Join(input, "cases.tsv"), []byte("producer manifest"))
			write(filepath.Join(input, "APFS.dmg"), []byte("producer image"))
			for _, name := range []string{"arm64.ast.json", "x86_64.ast.json", "SDK/sys/stat.h", "SDK/sys/fcntl.h", "SDK/unistd.h", "SDK/sys/errno.h", "probe"} {
				write(filepath.Join(out, name), []byte(name))
			}
			sources, err := nativeNameSourceInventory(out)
			if err != nil {
				t.Fatal(err)
			}
			v := volumeCapture{Kind: "APFS", ImageSHA256: sum([]byte("producer image"))}
			var stream strings.Builder
			for i := 0; i < 3753; i++ {
				id := fmt.Sprintf("case-%d", i)
				v.Native.Cases = append(v.Native.Cases, nativeCase{ID: id, Inode: uint64(i + 1)})
				for j := 0; j < 2; j++ {
					fmt.Fprintf(&stream, "%s\t%d\t0\t%d\t0\t0\tclosed\n", id, j, i+1)
				}
			}
			stream.WriteString("complete\t3753\n")
			normalized, err := parseNativeReceiver([]byte(stream.String()), v.Native.Cases)
			if err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(out, "27-APFS-readback.json"), []byte(stream.String()))
			write(filepath.Join(out, "27-APFS-observations.json"), normalized)
			write(filepath.Join(out, "27-APFS-attach.plist"), []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>system-entities</key><array><dict><key>dev-entry</key><string>/dev/disk6</string></dict></array></dict></plist>`))
			write(filepath.Join(out, "27-APFS-detach.json"), []byte(`[{"device":"/dev/disk6","exit_code":0,"output":"detached"}]`))
			r := nativeNameMatrixReport{Schema: 3, Reference: true, Selection: cell, Host: host, Revision: revision, Sources: sources, Inputs: map[string]string{}, Evidence: map[string]string{}, Observations: 7506, Profiles: 1, Volumes: 1}
			for _, name := range []string{"native.json.gz", "cases.tsv", "APFS.dmg"} {
				b, err := os.ReadFile(filepath.Join(input, name))
				if err != nil {
					t.Fatal(err)
				}
				r.Inputs[filepath.Base(input)+"/"+name] = sum(b)
			}
			switch mutation {
			case "schema":
				r.Schema = 2
			case "preparation":
				r.Preparation = true
			case "not-reference":
				r.Reference = false
			case "host":
				r.Host = "ProductVersion: 15.7.9"
			case "selection":
				r.Selection.Producer = 26
			case "inventory":
				r.Observations--
			case "revision":
				r.Revision = strings.Repeat("b", 40)
			case "sources":
				r.Sources["native-binary"] = "changed"
			case "inputs":
				r.Inputs[filepath.Base(input)+"/APFS.dmg"] = "changed"
			case "extra-input":
				r.Inputs["unexpected"] = "extra"
			case "missing-raw":
				if err := os.Remove(filepath.Join(out, "27-APFS-readback.json")); err != nil {
					t.Fatal(err)
				}
			case "truncated-raw":
				write(filepath.Join(out, "27-APFS-readback.json"), []byte("incomplete"))
			case "changed-observations":
				write(filepath.Join(out, "27-APFS-observations.json"), []byte("{}"))
			case "missing-detach":
				if err := os.Remove(filepath.Join(out, "27-APFS-detach.json")); err != nil {
					t.Fatal(err)
				}
			case "failed-detach":
				write(filepath.Join(out, "27-APFS-detach.json"), []byte(`[{"device":"/dev/disk6","exit_code":1}]`))
			}
			if err := filepath.WalkDir(out, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.IsDir() {
					return nil
				}
				b, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				name, err := filepath.Rel(out, path)
				if err != nil {
					return err
				}
				r.Evidence[filepath.ToSlash(name)] = sum(b)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if mutation == "hash" {
				r.Evidence["probe"] = "wrong"
			}
			encoded, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if mutation != "missing-report" {
				write(filepath.Join(out, "report.json"), encoded)
			}
			got, _, err := loadNativeReceiverReference(out, cell, host, v, input)
			if mutation == "valid" {
				if err != nil || !bytes.Equal(got, normalized) {
					t.Fatal("valid reference rejected", err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid receiver reference", mutation)
			}
		})
	}
}

func TestNativeNameMatrixReferenceTranscript(t *testing.T) {
	cell := nativeNameCell{26, 15, "APFS"}
	raw := []byte("{\"Action\":\"pass\",\"Test\":\"TestCaptureNativeNameReceiver/26/APFS\"}\n{\"Action\":\"pass\",\"Test\":\"TestCaptureNativeNameReceiver\"}\n{\"Action\":\"pass\"}\n")
	if err := validateNativeNameTranscript(raw, cell, "TestCaptureNativeNameReceiver"); err != nil {
		t.Fatal(err)
	}
	if err := validateNativeNameCellTranscript(raw, cell); err == nil {
		t.Fatal("capture transcript accepted as independent replay")
	}
	if err := validateNativeNameTranscript(bytes.ReplaceAll(raw, []byte("TestCaptureNativeNameReceiver"), []byte("TestPrepareNativeNameReceiver")), cell, "TestCaptureNativeNameReceiver"); err == nil {
		t.Fatal("preparation accepted as complete reference")
	}
}

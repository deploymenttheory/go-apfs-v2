//go:build ignore

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This suite mutates genuine native output after a successful pristine replay.
// Its local control remains separate from the mandatory three-producer gate.
func TestWriterNativeGuards(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"readback", "preflight"} {
		mutations := []string{"positive", "missing-case", "duplicate-case", "unknown-case", "count", "unknown-field", "trailing-json", "truncated-json"}
		if family == "readback" {
			mutations = append(mutations, "payload", "missing-result", "lookup-errno", "inode", "size", "read", "missing-stored", "stored-name", "stored-inode")
		} else {
			mutations = append(mutations, "filesystem", "root-actor", "readonly", "case-policy", "unknown-policy", "cleanup", "operation", "first-errno", "first-created", "second-errno", "second-created")
		}
		for _, mutation := range mutations {
			t.Run(family+"/"+mutation, func(t *testing.T) {
				cmd := exec.CommandContext(t.Context(), binary, "-test.run=^TestWriterNativeGuardChild$", "-test.v")
				cmd.Env = append(os.Environ(), "APFS_WRITER_NATIVE_GUARD="+family+"/"+mutation)
				output, err := cmd.CombinedOutput()
				if mutation == "positive" {
					if err != nil {
						t.Fatalf("genuine native positive control failed: %v\n%s", err, output)
					}
					return
				}
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(output), "--- FAIL: TestWriterNativeGuardChild") {
					t.Fatalf("mutation was not rejected: %v\n%s", err, output)
				}
			})
		}
	}
}

func TestWriterNativeGuardChild(t *testing.T) {
	mutation := os.Getenv("APFS_WRITER_NATIVE_GUARD")
	if mutation == "" {
		return
	}
	pieces := strings.Split(mutation, "/")
	if len(pieces) != 2 {
		t.Fatal("invalid guard")
	}
	family, change := pieces[0], pieces[1]
	out := os.Getenv("FILESYSTEM_NAME_WRITER_NATIVE_OUTPUT")
	if out == "" {
		out = "../artifacts/name-writer-native"
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	out, err = filepath.Abs(out)
	if err != nil {
		t.Fatal(err)
	}
	base := os.Getenv("FILESYSTEM_NAME_WRITER_ARTIFACTS")
	if base == "" {
		t.Fatal("genuine producer artifacts are required")
	}
	base, err = filepath.Abs(base)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Producers []string
		Target    struct{ Major uint32 }
	}
	if err = json.Unmarshal(raw, &summary); err != nil {
		t.Fatal(err)
	}
	if len(summary.Producers) == 0 {
		t.Fatal("missing genuine producer context")
	}
	producer := summary.Producers[0]
	report := readWriterReport(t, filepath.Join(base, "name-writer-"+producer, "manifest.json"))
	var image *nameWriterImage
	for i := range report.Images {
		if report.Images[i].Kind == "APFS" && report.Images[i].Target == summary.Target.Major {
			image = &report.Images[i]
		}
	}
	if image == nil {
		t.Fatal("native matching target is missing")
	}
	file := producer + "-APFS-readback.json"
	if family == "preflight" {
		file = "preflight-APFS-native.json"
	} else if family != "readback" {
		t.Fatal("unknown family")
	}
	raw, err = os.ReadFile(filepath.Join(out, file))
	if err != nil {
		t.Fatal(err)
	}
	validate := func(value []byte) {
		if family == "readback" {
			validateWriterReadback(t, value, *image)
		} else {
			validateWriterPreflight(t, value, "APFS", image.Checks)
		}
	}
	validate(raw)
	if change == "positive" {
		return
	}
	var object map[string]any
	if err = json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	cases := object["cases"].([]any)
	first := cases[0].(map[string]any)
	switch change {
	case "missing-case":
		object["cases"] = cases[:len(cases)-1]
	case "duplicate-case":
		cases[1] = cases[0]
	case "unknown-case":
		first["id"] = "unqualified"
	case "count":
		object["count"] = 0
	case "unknown-field":
		object["unexpected"] = true
	case "trailing-json", "truncated-json":
	case "payload":
		first["results"].([]any)[0].(map[string]any)["data"] = "70"
	case "missing-result":
		first["results"] = first["results"].([]any)[:1]
	case "lookup-errno", "inode", "size", "read":
		result := first["results"].([]any)[0].(map[string]any)
		field := change
		if field == "lookup-errno" {
			field = "errno"
		}
		result[field] = result[field].(float64) + 1
	case "missing-stored":
		first["stored"] = []any{}
	case "stored-name":
		first["stored"].([]any)[0].(map[string]any)["name"] = "00"
	case "stored-inode":
		first["stored"].([]any)[0].(map[string]any)["inode"] = 0
	case "filesystem":
		object["filesystem"] = "hfs"
	case "root-actor":
		object["uid"] = 0
	case "readonly":
		object["mount_flags"] = 1
	case "case-policy":
		object["case_sensitive"] = true
	case "unknown-policy":
		object["capability_valid"] = false
	case "cleanup":
		object["cleanup_complete"] = false
	case "operation":
		first["kind"] = "unqualified"
	case "first-errno":
		first["first_errno"] = 13
	case "first-created":
		first["first_created"] = false
	case "second-errno":
		first["second_errno"] = 0
	case "second-created":
		first["second_created"] = true
	default:
		t.Fatal("unknown mutation", change)
	}
	raw, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if change == "trailing-json" {
		raw = append(raw, []byte(`{}`)...)
	}
	if change == "truncated-json" {
		raw = raw[:len(raw)/2]
	}
	validate(raw)
	t.Log(fmt.Sprintf("unexpectedly accepted %s", mutation))
}

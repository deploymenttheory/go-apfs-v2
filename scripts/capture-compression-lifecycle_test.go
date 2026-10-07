//go:build ignore

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func lifecycleCases(t *testing.T, name string) []trial {
	t.Helper()
	file, err := os.Open("../testdata/appledouble/native/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	z, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var c capture
	if err := json.NewDecoder(z).Decode(&c); err != nil {
		t.Fatal(err)
	}
	if c.Schema != 1 || len(c.Cases) != 591 {
		t.Fatal("incomplete lifecycle corpus", name)
	}
	return c.Cases
}

func TestLifecycleMacOS26FullCapture(t *testing.T) {
	prior := lifecycleCases(t, "compression-lifecycle.json.gz")
	fresh := lifecycleCases(t, "compression-lifecycle-macos26.json.gz")
	for i, b := range fresh {
		a := prior[i]
		// The CI host is unprotected APFS. Match its observed storage context to
		// the independently mounted APFS cases, exactly as the native recapture.
		if b.Filesystem == "host" {
			a = prior[i+197]
			a.Filesystem = "host"
		}
		x, err := comparison(a)
		if err != nil {
			t.Fatal(i, err)
		}
		y, err := comparison(b)
		if err != nil {
			t.Fatal(i, err)
		}
		if !bytes.Equal(x, y) {
			t.Fatalf("complete native capture differs at %d: %s/%s/%s/%s", i, b.Filesystem, b.Scenario, b.Requested, b.Fault)
		}
	}
}

func TestLifecycleAdmissionErrnoQualification(t *testing.T) {
	cases := lifecycleCases(t, "compression-lifecycle-macos26.json.gz")
	for _, index := range []int{154, 156, 158, 165, 169, 176, 181, 183, 184} {
		native := cases[index]
		before := bytes.Clone(native.Observation)
		var values map[string]any
		if err := json.Unmarshal(native.Observation, &values); err != nil {
			t.Fatal(err)
		}
		if values["accepted"] != true || values["errno"] == float64(0) {
			t.Fatal("missing captured variant", index)
		}
		values["errno"] = 0
		zero := native
		zero.Observation, _ = json.Marshal(values)
		a, err := comparison(native)
		if err != nil {
			t.Fatal(err)
		}
		b, err := comparison(zero)
		if err != nil || !bytes.Equal(a, b) {
			t.Fatal(index, err)
		}
		if !bytes.Equal(native.Observation, before) {
			t.Fatal("comparison mutated raw capture")
		}
	}
	original := cases[154]
	canonical, err := comparison(original)
	if err != nil {
		t.Fatal(err)
	}
	edits := map[string]func(*trial){
		"failed-admission":         func(c *trial) { editObservation(t, c, "accepted", false) },
		"unqualified-errno":        func(c *trial) { editObservation(t, c, "errno", 13) },
		"missing-errno":            func(c *trial) { editObservation(t, c, "errno", nil) },
		"missing-admission":        func(c *trial) { editObservation(t, c, "accepted", nil) },
		"changed-flags":            func(c *trial) { editObservation(t, c, "after_flags", 32) },
		"changed-readback":         func(c *trial) { c.Data = append([]byte("changed"), c.Data...) },
		"changed-fork":             func(c *trial) { c.Fork = append([]byte("changed"), c.Fork...) },
		"changed-attribute":        func(c *trial) { c.Attribute = []byte("changed") },
		"different-scenario":       func(c *trial) { c.Scenario = "ordinary" },
		"different-inline":         func(c *trial) { c.Inline = "default" },
		"different-count":          func(c *trial) { c.FaultCount = 2 },
		"different-skip":           func(c *trial) { c.FaultSkip = 3 },
		"different-fault":          func(c *trial) { c.Fault = "fsync" },
		"different-injected-errno": func(c *trial) { c.FaultErrno = 5 },
		"missing-trace":            func(c *trial) { c.Trace = "" },
		"changed-operation-errno":  func(c *trial) { editWriteTrace(t, c, "errno", 5) },
		"changed-operation-result": func(c *trial) { editWriteTrace(t, c, "result", -1) },
		"wrong-fork":               func(c *trial) { editWriteTrace(t, c, "fork", false) },
		"missing-injection":        func(c *trial) { editWriteTrace(t, c, "injected", false) },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			changed := original
			edit(&changed)
			got, err := comparison(changed)
			if err == nil && bytes.Equal(got, canonical) {
				t.Fatal("accepted changed native outcome")
			}
		})
	}
	// A rejected admission must continue to compare its errno exactly.
	failed := original
	editObservation(t, &failed, "accepted", false)
	a, err := comparison(failed)
	if err != nil {
		t.Fatal(err)
	}
	editObservation(t, &failed, "errno", 0)
	b, err := comparison(failed)
	if err != nil || bytes.Equal(a, b) {
		t.Fatal("masked rejected admission errno", err)
	}
}

func editObservation(t *testing.T, c *trial, key string, value any) {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal(c.Observation, &fields); err != nil {
		t.Fatal(err)
	}
	if value == nil {
		delete(fields, key)
	} else {
		fields[key] = value
	}
	var err error
	c.Observation, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
}

func editWriteTrace(t *testing.T, c *trial, key string, value any) {
	t.Helper()
	var out bytes.Buffer
	for _, line := range bytes.Split([]byte(c.Trace), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		if event["operation"] == "pwrite" && event["injected"] == true {
			event[key] = value
		}
		if err := json.NewEncoder(&out).Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	c.Trace = out.String()
}

func TestLifecycleMacOS26ArtifactProvenance(t *testing.T) {
	const base = "../testdata/appledouble/native/compression-lifecycle-macos26"
	encoded, err := os.ReadFile(base + ".json.gz")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(base + ".provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	var provenance struct {
		SHA256, Revision, Source string
		ArtifactID               int64 `json:"artifact_id"`
	}
	if err := json.Unmarshal(raw, &provenance); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	if provenance.SHA256 != hex.EncodeToString(sum[:]) || provenance.Revision != "ff25c5cb315987a6830a535d35aa699f9295f09e" || provenance.ArtifactID != 11477551369 || provenance.Source != "https://github.com/deploymenttheory/go-apfs-v2/actions/runs/37608170531/job/112748665269" {
		t.Fatal("historical native artifact provenance changed", provenance)
	}
}

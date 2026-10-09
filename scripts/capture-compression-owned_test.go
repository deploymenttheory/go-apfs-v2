//go:build ignore

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/nativeevidence"
)

func TestOwnedQualificationUsesEveryIndependentNativeCase(t *testing.T) {
	t.Chdir("..")
	report, err := readCapture("testdata/appledouble/native/compression-owned-macos27.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	put := func(b []byte) (string, error) { return nativeevidence.Digest(b), nil }
	observation, err := ownedObservation(report, put)
	if err != nil || len(observation.Cases) != 72 || observation.Profile != "macos27" {
		t.Fatal(observation, err)
	}
	contract := ownedContract()
	if err = nativeevidence.ValidateContract(contract); err != nil {
		t.Fatal(err)
	}
	for i, item := range observation.Cases {
		if item.ID != contract.Cases[i] || item.Input == "" || item.Result == "" {
			t.Fatal("native case not preserved", i, item)
		}
	}
	for _, failure := range []string{"schema", "partial", "profile", "duplicate", "unknown", "invalid-json", "input-write", "output-write"} {
		b, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		var changed capture
		if err = json.Unmarshal(b, &changed); err != nil {
			t.Fatal(err)
		}
		switch failure {
		case "schema":
			changed.Schema++
		case "partial":
			changed.Cases = changed.Cases[:71]
		case "profile":
			changed.Host = "ProductVersion: 28.0\n"
		case "duplicate":
			changed.Cases[1] = changed.Cases[0]
		case "unknown":
			changed.Cases[0].Filesystem = "unknown"
		case "invalid-json":
			changed.Cases[0].Observation = json.RawMessage("invalid")
		}
		calls := 0
		writer := func(b []byte) (string, error) {
			calls++
			if failure == "input-write" && calls == 1 || failure == "output-write" && calls == 2 {
				return "", os.ErrPermission
			}
			return put(b)
		}
		if _, err := ownedObservation(changed, writer); err == nil {
			t.Fatal("invalid native bundle accepted", failure)
		}
	}
}

func TestOwnedLiveReceiptRequiresAllFilesystemCases(t *testing.T) {
	const suite = "TestNativeCompressionOwnedMounted"
	event := func(action, test string) string {
		b, _ := json.Marshal(map[string]string{"Action": action, "Package": "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata", "Test": test})
		return string(b) + "\n"
	}
	dir := t.TempDir()
	artifacts := map[string]string{}
	for _, filesystem := range []string{"host", "APFS", "HFS+"} {
		var cases string
		first := ""
		for compressed := 0; compressed <= 2; compressed++ {
			for _, route := range []string{"direct", "root"} {
				for _, mutation := range []string{"none", "root-before", "root-after", "leaf-after"} {
					name := suite + "/" + filesystem + "/" + string(rune('0'+compressed)) + "/" + route + "/" + mutation
					line := event("pass", name)
					cases += line
					if first == "" {
						first = line
					}
				}
			}
		}
		start := event("run", suite)
		end := event("pass", suite) + event("pass", "")
		valid := start + cases + end
		if err := ownedLiveTranscriptPassed([]byte(valid), filesystem); err != nil {
			t.Fatal(err)
		}
		for _, invalid := range []string{start + end, start + strings.Replace(cases, first, "", 1) + end, start + cases + first + end, strings.Replace(valid, filesystem, "other", 1), strings.Replace(valid, "\"pass\"", "\"skip\"", 1)} {
			if err := ownedLiveTranscriptPassed([]byte(invalid), filesystem); err == nil {
				t.Fatal("incomplete live qualification accepted")
			}
		}
		name := strings.ReplaceAll(filesystem, "+", "plus") + "-replay.jsonl"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(valid), 0600); err != nil {
			t.Fatal(err)
		}
		artifacts[name] = nativeevidence.Digest([]byte(valid))
		name = strings.ReplaceAll(filesystem, "+", "plus") + "-replay.stderr.log"
		if err := os.WriteFile(filepath.Join(dir, name), []byte("go: downloading fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
		artifacts[name] = nativeevidence.Digest([]byte("go: downloading fixture\n"))
	}
	if err := verifyOwnedLiveArtifacts(dir, artifacts); err != nil {
		t.Fatal(err)
	}
	if err := verifyOwnedLiveArtifacts(dir, map[string]string{}); err == nil {
		t.Fatal("missing live artifacts accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "host-replay.stderr.log"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyOwnedLiveArtifacts(dir, artifacts); err == nil {
		t.Fatal("changed diagnostic evidence accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "host-replay.stderr.log"), []byte("go: downloading fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "host-replay.jsonl"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyOwnedLiveArtifacts(dir, artifacts); err == nil {
		t.Fatal("changed live artifact accepted")
	}
	if err := os.Remove(filepath.Join(dir, "host-replay.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := verifyOwnedLiveArtifacts(dir, artifacts); err == nil {
		t.Fatal("missing live transcript accepted")
	}
}

func TestOwnedSemanticResultsPreserveQualifiedNativeFields(t *testing.T) {
	before := json.RawMessage(`{"before":{"inode":12,"mtime":1,"flags":32,"attribute":"AB"},"open_errno":0}`)
	clockChange := json.RawMessage(`{"before":{"inode":99,"mtime":8,"flags":32,"attribute":"AB"},"open_errno":0}`)
	a, err := ownedStableResult(before)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ownedStableResult(clockChange)
	if err != nil || string(a) != string(b) {
		t.Fatal("incidental identities changed semantic result", err)
	}
	for _, changed := range []json.RawMessage{
		json.RawMessage(`{"before":{"inode":12,"mtime":1,"flags":0,"attribute":"AB"},"open_errno":0}`),
		json.RawMessage(`{"before":{"inode":12,"mtime":1,"flags":32,"attribute":"CD"},"open_errno":0}`),
		json.RawMessage(`{"before":{"inode":12,"mtime":1,"flags":32,"attribute":"AB"},"open_errno":13}`),
	} {
		b, err := ownedStableResult(changed)
		if err != nil || string(a) == string(b) {
			t.Fatal("native policy change hidden", err)
		}
	}
	if _, err := ownedStableResult(json.RawMessage("invalid")); err == nil {
		t.Fatal("invalid raw result accepted")
	}
}

func TestOwnedReceiptsRejectIncompleteFailedAndSkippedGoExecution(t *testing.T) {
	const pkg = "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	event := func(action, test string) string {
		b, _ := json.Marshal(map[string]string{"Action": action, "Package": pkg, "Test": test})
		return string(b) + "\n"
	}
	start := event("run", "TestCompressionOwnedNativeEvidence")
	pass := event("pass", "TestCompressionOwnedNativeEvidence")
	complete := event("pass", "")
	valid := start + pass + complete
	if err := ownedTranscriptPassed([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", start, start + pass, pass + complete, start + start + pass + complete, start + pass + pass + complete, valid + complete, start + event("skip", "case") + pass + complete, start + event("fail", "case") + pass + complete, "invalid\n", strings.ReplaceAll(valid, pkg, "other"), strings.Repeat("x", (16<<20)+1)} {
		if err := ownedTranscriptPassed([]byte(invalid)); err == nil {
			t.Fatal("invalid verification receipt accepted")
		}
	}
	if err := qualifyOwnedCapture("missing", "macos27", "invented", t.TempDir()); err == nil {
		t.Fatal("undeclared consumer accepted")
	}
	if _, err := verifyOwnedBundle(t.Context(), "missing", "macos27"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing producer not rejected", err)
	}
}

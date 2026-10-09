//go:build ignore

package main

import (
	"encoding/json"
	"errors"
	"os"
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

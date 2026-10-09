//go:build ignore

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

func TestMain(m *testing.M) {
	if err := os.Chdir(".."); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func replacementReferenceBytes(t *testing.T) []byte {
	t.Helper()
	file, err := os.Open("testdata/appledouble/native/replacement-filesystem-macos27/cases.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func TestReplacementNativeCaseContract(t *testing.T) {
	original := replacementReferenceBytes(t)
	if err := validateNativePolicy(original, osversion.MacOS27); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []osversion.MacOSProfile{0, 14, 15, 28} {
		if err := validateNativePolicy(original, profile); err == nil {
			t.Fatal("wrong native profile accepted", profile)
		}
	}
	if err := validateCases(original, osversion.MacOS15); err != nil {
		t.Fatal("behavioral baseline incorrectly blocked independent collection", err)
	}
	if err := validateCases([]byte("corrupt"), osversion.MacOS27); err == nil {
		t.Fatal("invalid corpus accepted")
	}
	for _, kind := range []string{"missing", "duplicate", "input", "native", "errno", "profile", "filesystem"} {
		t.Run(kind, func(t *testing.T) {
			var records []map[string]json.RawMessage
			if err := json.Unmarshal(original, &records); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing":
				records = records[:len(records)-1]
			case "duplicate":
				records[1] = records[0]
			case "input":
				records[0]["Input"] = json.RawMessage(`""`)
			case "native":
				records[0]["Native"] = json.RawMessage(`""`)
			case "errno":
				records[0]["Errno"] = json.RawMessage(`-1`)
			case "profile":
				records[0]["Profile"] = json.RawMessage(`"value-invalid"`)
			case "filesystem":
				records[0]["Filesystem"] = json.RawMessage(`"APFS"`)
			}
			data, err := json.Marshal(records)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateCases(data, osversion.MacOS27); err == nil {
				t.Fatal("invalid native corpus accepted", kind)
			}
		})
	}
}

type transcriptEvent struct{ Action, Package, Test string }

// These are harness-protocol events, not fabricated Apple behavior fixtures.
func replacementTranscript(label string) []transcriptEvent {
	packages := []string{"hostdata"}
	if label == "replay" {
		packages = append(packages, "appledouble")
	}
	events := []transcriptEvent{}
	for _, pkg := range packages {
		name := "github.com/deploymenttheory/go-apfs-v2/pkg/" + pkg
		suite := "TestReplacementFilesystemNativeCapture"
		if label == "live" {
			suite = "TestReplacementFilesystemNativeEncoding"
		}
		if label == "replay" {
			suite = "TestReplacementFilesystemNativeCorpus"
			if pkg == "appledouble" {
				suite = "TestFilesystemEncodingNativeCopy"
			}
		}
		events = append(events, transcriptEvent{"start", name, ""}, transcriptEvent{"run", name, suite})
		for _, filesystem := range []string{"MS-DOS_FAT32", "ExFAT"} {
			group := suite + "/" + filesystem
			if label != "replay" {
				events = append(events, transcriptEvent{"run", name, group})
			}
			for _, size := range []int{0, 1, 3650, 3651, 3652, 4096, 65100, 65400, 65536, 131072} {
				for _, fork := range []int{0, 1, 4, 255, 256, 285, 286, 287, 65535, 65536, 65537} {
					key := group + "/" + fmtCase(size, fork)
					events = append(events, transcriptEvent{"run", name, key}, transcriptEvent{"pass", name, key})
				}
			}
			if label != "replay" {
				events = append(events, transcriptEvent{"pass", name, group})
			}
		}
		events = append(events, transcriptEvent{"pass", name, suite}, transcriptEvent{"pass", name, ""})
	}
	return events
}
func fmtCase(size, fork int) string { return fmt.Sprintf("value-%d-fork-%d", size, fork) }
func transcriptBytes(t *testing.T, events []transcriptEvent) []byte {
	t.Helper()
	var output bytes.Buffer
	for _, event := range events {
		if err := json.NewEncoder(&output).Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	return output.Bytes()
}
func TestReplacementCompletionContract(t *testing.T) {
	for _, label := range []string{"native", "live", "replay"} {
		packages := []string{"./pkg/hostdata"}
		if label == "replay" {
			packages = append(packages, "./pkg/appledouble")
		}
		original := replacementTranscript(label)
		if err := validateTestTranscript(transcriptBytes(t, original), packages, label); err != nil {
			t.Fatal(label, err)
		}
		for _, kind := range []string{"missing-package", "missing-case", "missing-filesystem", "missing-suite", "duplicate", "fail", "skip", "unknown-action", "unknown-package", "no-start", "no-run", "early-package-close"} {
			t.Run(label+"/"+kind, func(t *testing.T) {
				events := append([]transcriptEvent(nil), original...)
				switch kind {
				case "missing-package":
					events = events[:len(events)-1]
				case "missing-case":
					events = append(events[:3], events[5:]...)
				case "missing-filesystem":
					kept := events[:0]
					for _, event := range original {
						if event.Test != "TestReplacementFilesystemNativeCapture/ExFAT" {
							kept = append(kept, event)
						}
					}
					events = kept
					if label != "native" {
						events = events[:len(events)-1]
					}
				case "missing-suite":
					events = append(events[:1], events[2:len(events)-2]...)
					events = append(events, original[len(original)-1])
				case "duplicate":
					events = append(events, events[len(events)-1])
				case "fail", "skip":
					events[3].Action = kind
				case "unknown-action":
					events[3].Action = "invented"
				case "unknown-package":
					events[0].Package = "foreign"
				case "no-start":
					events = events[1:]
				case "no-run":
					events = append(events[:1], events[2:]...)
				case "early-package-close":
					events[1] = transcriptEvent{"pass", events[0].Package, ""}
				}
				if err := validateTestTranscript(transcriptBytes(t, events), packages, label); err == nil {
					t.Fatal("incomplete receipt accepted", kind)
				}
			})
		}
		raw := transcriptBytes(t, original)
		if err := validateTestTranscript(append([]byte("go: downloading fixture.invalid/module\n"), raw...), packages, label); err == nil {
			t.Fatal("diagnostics accepted as JSON")
		}
		if err := validateTestTranscript([]byte(strings.TrimSpace(string(raw))+"garbage"), packages, label); err == nil {
			t.Fatal("invalid tail accepted")
		}
	}
}

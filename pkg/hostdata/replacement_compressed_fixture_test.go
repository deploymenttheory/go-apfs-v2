package hostdata

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestReplacementCompressedNativeFixture(t *testing.T) {
	b, err := os.ReadFile("../../testdata/appledouble/native/replacement-compressed.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Schema int               `json:"schema"`
		Hashes map[string]string `json:"source_sha256"`
		Cases  []struct {
			Name                        string `json:"case"`
			Filesystem                  string `json:"filesystem"`
			Type                        uint32 `json:"type"`
			Source, Replacement, Native map[string]json.RawMessage
			Begin                       int64 `json:"native_begin"`
			End                         int64 `json:"native_end"`
			SourceUnchanged             bool  `json:"source_unchanged"`
			StageRemoved                bool  `json:"stage_removed"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &capture); err != nil {
		t.Fatal(err)
	}
	if capture.Schema != 1 || len(capture.Cases) != 68 {
		t.Fatalf("incomplete native capture: %d/%d", capture.Schema, len(capture.Cases))
	}
	for _, name := range []string{"testdata/appledouble/native/replacement-compressed.c", "testdata/appledouble/native/decmpfs-formats.c", "testdata/appledouble/native/decmpfs-formats.json.gz"} {
		b, err := os.ReadFile("../../" + name)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(b)
		if capture.Hashes[name] != hex.EncodeToString(h[:]) {
			t.Fatal("source hash mismatch", name)
		}
	}
	names := map[string]uint32{"producer-3": 4, "producer-7": 8, "producer-11": 12}
	for _, sample := range replacementCompressionSamples(t) {
		names[sample.Name] = sample.Type
	}
	seen := map[string]bool{}
	for _, tc := range capture.Cases {
		key := tc.Filesystem + "/" + tc.Name
		t.Run(key, func(t *testing.T) {
			parts := strings.Split(tc.Name, "/")
			if len(parts) != 3 || parts[0] != "TestReplacementCompressedDarwinNative" || (parts[1] != "path" && parts[1] != "root") {
				t.Fatal("invalid case name", tc.Name)
			}
			if want, ok := names[parts[2]]; !ok || tc.Type != want {
				t.Fatal("unexpected native storage profile", tc.Type)
			}
			if (tc.Filesystem != "APFS" && tc.Filesystem != "HFS+") || seen[key] {
				t.Fatal("duplicate or invalid filesystem", key)
			}
			seen[key] = true
			if !tc.SourceUnchanged || !tc.StageRemoved {
				t.Fatal("incomplete replacement lifecycle")
			}
			var sourceFlags, targetFlags uint32
			if err := json.Unmarshal(tc.Source["Flags"], &sourceFlags); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(tc.Replacement["Flags"], &targetFlags); err != nil {
				t.Fatal(err)
			}
			if sourceFlags&UFCompressed == 0 || targetFlags != sourceFlags&^UFCompressed {
				t.Fatal("invalid compression transition")
			}
			if !bytes.Equal(tc.Source["Birth"], tc.Replacement["Birth"]) {
				t.Fatal("SDK lost source birth time")
			}
			var nativeBirth struct{ Sec int64 }
			if err := json.Unmarshal(tc.Native["Birth"], &nativeBirth); err != nil {
				t.Fatal(err)
			}
			if tc.Begin > tc.End || nativeBirth.Sec < tc.Begin || nativeBirth.Sec > tc.End {
				t.Fatal("native birth outside capture interval")
			}
			for _, field := range []string{"Mode", "UID", "GID", "Flags", "Attributes", "ForkSize", "ForkSHA256", "ACL"} {
				if tc.Replacement[field] == nil || !bytes.Equal(tc.Replacement[field], tc.Native[field]) {
					t.Fatal("native metadata mismatch", field)
				}
			}
			var sourceAttrs, attrs map[string]string
			if err := json.Unmarshal(tc.Source["Attributes"], &sourceAttrs); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(tc.Replacement["Attributes"], &attrs); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(attrs, sourceAttrs) || attrs[DecmpfsName] != "" || attrs["user.replacement"] != hex.EncodeToString([]byte("independent metadata")) {
				t.Fatal("independent attributes changed")
			}
		})
	}
	for _, fs := range []string{"APFS", "HFS+"} {
		for _, api := range []string{"path", "root"} {
			for name := range names {
				if !seen[fs+"/TestReplacementCompressedDarwinNative/"+api+"/"+name] {
					t.Fatal("missing exact native case", fs, api, name)
				}
			}
		}
	}
}

//go:build ignore

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

// Named-file compilation with capture-hfs-special-names.go reuses its independent
// raw catalog parser and native inventory validator without copying either.
func TestInspectWriterHFSSpecial(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	var result any
	switch os.Getenv("APFS_WRITER_SPECIAL_MODE") {
	case "image":
		rows, err := readSpecialCatalog(os.Getenv("APFS_WRITER_SPECIAL_INPUT"))
		if err != nil {
			t.Fatal(err)
		}
		result = rows
	case "fixture":
		raw, err := os.ReadFile(os.Getenv("APFS_WRITER_SPECIAL_INPUT"))
		if err != nil {
			t.Fatal(err)
		}
		compressed, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		plain, readErr := io.ReadAll(compressed)
		if err = errors.Join(readErr, compressed.Close()); err != nil {
			t.Fatal(err)
		}
		var capture specialCapture
		decoder := json.NewDecoder(bytes.NewReader(plain))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&capture); err != nil {
			t.Fatal(err)
		}
		if err = decoder.Decode(new(any)); err != io.EOF {
			t.Fatal("trailing fixture data", err)
		}
		major, err := strconv.ParseUint(os.Getenv("APFS_WRITER_SPECIAL_TARGET"), 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		target, err := osversion.ParseProductVersion(capture.Host)
		if err != nil || uint64(target.Major) != major {
			t.Fatal("mismatched native target", err)
		}
		if capture.Schema != 1 || len(capture.Volumes) != 2 || len(capture.Sources) != 16 || capture.Compiler == "" || capture.SDK == "" {
			t.Fatal("incomplete native special corpus")
		}
		expected := map[string]bool{}
		for _, name := range []string{specialSource, "scripts/capture-hfs-special-names.go", "testdata/appledouble/native/name-comparison-source/vfs_utfconv.c.gz", "testdata/appledouble/native/name-comparison-source/sources.json", "go.mod", "go.sum", "native-binary", "arm64.ast.json", "x86_64.ast.json", "SDK/sys/stat.h", "SDK/sys/mount.h", "SDK/sys/attr.h", "SDK/sys/fcntl.h", "SDK/dirent.h", "SDK/unistd.h", "SDK/sys/errno.h"} {
			expected[name] = true
		}
		for name, digest := range capture.Sources {
			hash, err := hex.DecodeString(digest)
			if !expected[name] || err != nil || len(hash) != 32 {
				t.Fatal("unknown native provenance", name)
			}
			if strings.HasPrefix(name, "testdata/") || strings.HasPrefix(name, "scripts/") || name == "go.mod" || name == "go.sum" {
				body, err := os.ReadFile(name)
				if err != nil || specialHash(body) != digest {
					t.Fatal("stale native provenance", name, err)
				}
			}
		}
		for i, volume := range capture.Volumes {
			if volume.Kind != []string{"HFS+", "HFSX"}[i] {
				t.Fatal("native volume inventory")
			}
			if err = validateSpecial(volume); err != nil {
				t.Fatal(err)
			}
		}
		result = capture.Volumes
	default:
		t.Fatal("explicit image or fixture inspection is required")
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(os.Getenv("APFS_WRITER_SPECIAL_OUTPUT"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

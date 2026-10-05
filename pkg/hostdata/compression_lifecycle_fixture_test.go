package hostdata

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestCompressionLifecycleProvenance(t *testing.T) {
	file, e := os.Open("../../testdata/appledouble/native/compression-lifecycle.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	z, e := gzip.NewReader(file)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var corpus struct {
		Schema                       int
		Host, Compiler, SDK, Library string
		Sources                      map[string]string
		Cases                        []json.RawMessage
	}
	if e = json.NewDecoder(z).Decode(&corpus); e != nil {
		t.Fatal(e)
	}
	if corpus.Schema != 1 || len(corpus.Cases) != 384 || corpus.Host == "" || corpus.SDK == "" || !strings.Contains(corpus.Compiler, "clang") || !strings.Contains(corpus.Library, "-uuid:") {
		t.Fatal("incomplete native lifecycle provenance")
	}
	for _, path := range []string{"scripts/capture-compression-lifecycle.go", "testdata/appledouble/native/compression-lifecycle.c", "testdata/appledouble/native/compression-lifecycle-interpose.c", "testdata/appledouble/native/compression-policy.c", "go.mod", "go.sum"} {
		data, e := os.ReadFile("../../" + path)
		if e != nil {
			t.Fatal(e)
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != corpus.Sources[path] {
			t.Fatal("stale native lifecycle source", path)
		}
	}
	for _, key := range []string{"arm64-compression-lifecycle.c.ast.json", "x86_64-compression-lifecycle.c.ast.json", "arm64-compression-lifecycle-interpose.c.ast.json", "x86_64-compression-lifecycle-interpose.c.ast.json", "AppleFSCompression.disassembly.txt"} {
		if len(corpus.Sources[key]) != 64 {
			t.Fatal("missing AST/disassembly evidence", key)
		}
	}
	for _, header := range []string{"sys/mount.h", "sys/stat.h", "sys/xattr.h", "sys/attr.h", "sys/time.h"} {
		found := false
		for path, hash := range corpus.Sources {
			if strings.HasSuffix(path, "/usr/include/"+header) && len(hash) == 64 {
				found = true
			}
		}
		if !found {
			t.Fatal("missing native SDK header", header)
		}
	}
}

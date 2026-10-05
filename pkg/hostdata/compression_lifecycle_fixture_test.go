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
	testCompressionProvenance(t, "compression-lifecycle", 591, nil)
}
func TestCompressionOperationProvenance(t *testing.T) {
	testCompressionProvenance(t, "compression-operation", 330, []string{"testdata/appledouble/native/compression-lifecycle-interpose.c"})
}
func testCompressionProvenance(t *testing.T, name string, count int, additional []string) {
	t.Helper()
	file, e := os.Open("../../testdata/appledouble/native/" + name + ".json.gz")
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
	if corpus.Schema != 1 || len(corpus.Cases) != count || corpus.Host == "" || corpus.SDK == "" || !strings.Contains(corpus.Compiler, "clang") || !strings.Contains(corpus.Library, "-uuid:") {
		t.Fatal("incomplete native lifecycle provenance")
	}
	for _, path := range append(additional, "scripts/capture-"+name+".go", "testdata/appledouble/native/"+name+".c", "testdata/appledouble/native/"+name+"-interpose.c", "testdata/appledouble/native/compression-policy.c", "go.mod", "go.sum") {
		data, e := os.ReadFile("../../" + path)
		if e != nil {
			t.Fatal(e)
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != corpus.Sources[path] {
			t.Fatal("stale native lifecycle source", path)
		}
	}
	for _, key := range []string{"arm64-" + name + ".c.ast.json", "x86_64-" + name + ".c.ast.json", "arm64-" + name + "-interpose.c.ast.json", "x86_64-" + name + "-interpose.c.ast.json", "AppleFSCompression.disassembly.txt"} {
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

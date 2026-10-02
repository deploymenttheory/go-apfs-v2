//go:build ignore

// Capture the native basic-attribute/full-stat authorization distinction.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/entrytype"
	"os"
	"os/exec"
	"path/filepath"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func run(name string, args ...string) []byte {
	b, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("%s %v: %v: %s", name, args, err, b))
	}
	return b
}
func main() {
	out := flag.String("out", "testdata/appledouble/native/entry-type.json", "capture output")
	flag.Parse()
	dir, err := os.MkdirTemp("/tmp", "entry-type-native-")
	must(err)
	defer os.RemoveAll(dir)
	oracle := filepath.Join(dir, "oracle")
	run("/usr/bin/clang", "-Wall", "-Wextra", "-Werror", "testdata/appledouble/native/entry-type.c", "-o", oracle)
	cases := map[string]json.RawMessage{}
	for _, name := range entrytype.Cases {
		func() {
			parent := filepath.Join(dir, name)
			must(os.Mkdir(parent, 0700))
			cleanup, err := entrytype.Make(parent, name)
			defer func() { must(cleanup()) }()
			must(err)
			cases[name] = json.RawMessage(run(oracle, parent))
		}()
	}
	hashes := map[string]string{}
	for _, p := range []string{"scripts/capture-entry-type.go", "testdata/appledouble/native/entry-type.c", "internal/testutil/entrytype/fixture_darwin.go"} {
		b, err := os.ReadFile(p)
		must(err)
		h := sha256.Sum256(b)
		hashes[p] = hex.EncodeToString(h[:])
	}
	record := map[string]any{"schema": 1, "macos": string(run("/usr/bin/sw_vers")), "compiler": string(run("/usr/bin/clang", "--version")), "source_sha256": hashes, "cases": cases}
	b, err := json.MarshalIndent(record, "", "  ")
	must(err)
	must(os.MkdirAll(filepath.Dir(*out), 0755))
	must(os.WriteFile(*out, append(b, '\n'), 0644))
	fmt.Println("captured", len(cases), "native entry-type cases")
}

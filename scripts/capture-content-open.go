//go:build ignore

// Capture the native reader's permission/type matrix using the host C runtime.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"golang.org/x/sys/unix"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func run(name string, args ...string) []byte {
	b, err := cirunner.Command(name, args...).CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("%s %v: %v: %s", name, args, err, b))
	}
	return b
}
func hash(path string) string {
	b, err := os.ReadFile(path)
	must(err)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func main() {
	out := flag.String("out", "artifacts/content-open/native.json", "fresh capture output")
	flag.Parse()
	dir, err := os.MkdirTemp("", "content-open-native-")
	must(err)
	defer os.RemoveAll(dir)
	oracle := filepath.Join(dir, "oracle")
	run("/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "testdata/appledouble/native/content-open.c", "-o", oracle)
	cases := map[string]json.RawMessage{}
	for _, name := range []string{"ordinary", "read", "readattr", "readsecurity", "readextattr", "write", "writesecurity", "writeextattr", "directory", "symlink", "fifo", "missing"} {
		parent := filepath.Join(dir, name)
		must(os.Mkdir(parent, 0700))
		path := filepath.Join(parent, "file")
		switch name {
		case "directory":
			must(os.Mkdir(path, 0700))
		case "symlink":
			must(os.WriteFile(filepath.Join(parent, "target"), []byte("unchanged"), 0600))
			must(os.Symlink("target", path))
		case "fifo":
			must(unix.Mkfifo(path, 0600))
		case "missing":
		default:
			must(os.WriteFile(path, []byte("unchanged"), 0600))
			if name != "ordinary" {
				run("/bin/chmod", "+a", "everyone deny "+name, path)
			}
		}
		cases[name] = json.RawMessage(run(oracle, parent, "file"))
		run("/bin/chmod", "-RN", parent)
	}
	hashes := map[string]string{}
	must(captureprovenance.Bind(os.DirFS("."), filepath.Dir(*out), hashes))
	for _, p := range []string{"scripts/capture-content-open.go", "testdata/appledouble/native/content-open.c"} {
		hashes[p] = hash(p)
	}
	record := map[string]any{"schema": 1, "macos": string(run("/usr/bin/sw_vers")), "compiler": string(run("/usr/bin/clang", "--version")), "source_sha256": hashes, "cases": cases}
	b, err := json.MarshalIndent(record, "", "  ")
	must(err)
	must(os.WriteFile(*out, append(b, '\n'), 0644))
	fmt.Println("captured", len(cases), "native content acquisition cases")
}

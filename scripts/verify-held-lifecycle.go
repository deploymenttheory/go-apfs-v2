//go:build ignore

// Execute the unchanged pinned Apple fcopyfile outer function.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldlifecycle"
)

func main() {
	capture := flag.Bool("capture", false, "write unapproved native observations")
	source := flag.String("source", "", "optional pinned source cache (hash always checked)")
	flag.Parse()
	if err := verify(*capture, *source); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func verify(capture bool, cache string) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("native qualification requires macOS")
	}
	const dir = "artifacts/held-lifecycle"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	var source []byte
	var err error
	if cache != "" {
		source, err = os.ReadFile(cache)
	} else {
		client := http.Client{Timeout: 60 * time.Second}
		response, e := client.Get("https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c")
		if e != nil {
			return e
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("source HTTP %d", response.StatusCode)
		}
		source, err = io.ReadAll(io.LimitReader(response.Body, 2<<20))
	}
	if err != nil {
		return err
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(source))
	if sum != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" {
		return fmt.Errorf("copyfile source provenance: %s", sum)
	}
	if err = os.WriteFile(filepath.Join(dir, "copyfile.c"), source, 0600); err != nil {
		return err
	}
	start := bytes.Index(source, []byte("int fcopyfile(int src_fd, int dst_fd, copyfile_state_t state, copyfile_flags_t flags)"))
	if start < 0 {
		return fmt.Errorf("missing fcopyfile source")
	}
	end := bytes.Index(source[start:], []byte("\n/*\n * This routine implements the clonefileat functionality"))
	licenseEnd := bytes.Index(source, []byte("#include"))
	if end < 0 || licenseEnd < 0 {
		return fmt.Errorf("source boundaries")
	}
	function := append(bytes.Clone(source[:licenseEnd]), source[start:start+end]...)
	if err = os.WriteFile(filepath.Join(dir, "fcopyfile-source.h"), function, 0600); err != nil {
		return err
	}
	helperSource := "testdata/appledouble/native/held-lifecycle.c"
	helper := filepath.Join(dir, "held-lifecycle")
	for _, arch := range []string{"arm64", "x86_64"} {
		ast, e := exec.Command("xcrun", "clang", "-arch", arch, "-I", dir, "-fsyntax-only", "-Xclang", "-ast-dump=json", helperSource).Output()
		if e != nil {
			return fmt.Errorf("%s AST: %w", arch, e)
		}
		if e = os.WriteFile(filepath.Join(dir, arch+".ast.json"), ast, 0600); e != nil {
			return e
		}
	}
	if out, e := exec.Command("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-I", dir, helperSource, "-o", helper).CombinedOutput(); e != nil {
		return fmt.Errorf("compile: %w %s", e, out)
	}
	cases := heldlifecycle.Cases()
	var input strings.Builder
	for _, c := range cases {
		fmt.Fprintf(&input, "%d %d %d %d %d %d %d\n", c.SourceMode, c.SourceError, c.FallbackError, c.Selected, c.Cached, c.Failures, c.StageCode)
	}
	cmd := exec.Command(helper)
	cmd.Stdin = strings.NewReader(input.String())
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "inputs.txt"), []byte(input.String()), 0600); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "native.jsonl"), out, 0600); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(out))
	for i := range cases {
		if err = decoder.Decode(&cases[i].Native); err != nil {
			return err
		}
		if err = heldlifecycle.Replay(cases[i]); err != nil {
			return fmt.Errorf("case %d: %w", i, err)
		}
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("unexpected native trailing data: %v", err)
	}
	revision, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	host, err := exec.Command("sw_vers").Output()
	if err != nil {
		return err
	}
	helperBytes, err := os.ReadFile(helperSource)
	if err != nil {
		return err
	}
	fixture := heldlifecycle.Fixture{Revision: strings.TrimSpace(string(revision)), Host: string(host), SourceSHA256: sum, HelperSHA256: fmt.Sprintf("%x", sha256.Sum256(helperBytes)), Cases: cases}
	encoded, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "observations.json"), append(encoded, '\n'), 0600); err != nil {
		return err
	}
	if !capture {
		f, e := os.Open("testdata/appledouble/native/held-lifecycle.json.gz")
		if e != nil {
			return e
		}
		defer f.Close()
		z, e := gzip.NewReader(f)
		if e != nil {
			return e
		}
		defer z.Close()
		var approved heldlifecycle.Fixture
		if e = json.NewDecoder(z).Decode(&approved); e != nil {
			return e
		}
		if approved.SourceSHA256 != fixture.SourceSHA256 || approved.HelperSHA256 != fixture.HelperSHA256 || !reflect.DeepEqual(approved.Cases, cases) {
			return fmt.Errorf("native observations differ from approved fixture")
		}
	}
	hashes := map[string]string{}
	for _, path := range []string{helperSource, "scripts/verify-held-lifecycle.go", "internal/testutil/heldlifecycle/oracle.go", "pkg/hostmeta/held_lifecycle.go", "pkg/hostmeta/held_lifecycle_native_test.go"} {
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		hashes[path] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	report := map[string]any{"passed": !capture, "capture": capture, "cases": len(cases), "revision": fixture.Revision, "host": fixture.Host, "goos": runtime.GOOS, "goarch": runtime.GOARCH, "source_sha256": hashes, "copyfile_sha256": sum}
	encoded, err = json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "report.json"), encoded, 0600); err != nil {
		return err
	}
	fmt.Printf("Held lifecycle: %d unchanged-C cases; capture=%t; qualified=%t\n", len(cases), capture, !capture)
	return nil
}

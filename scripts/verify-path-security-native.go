//go:build ignore

// Extract complete pinned Apple permission functions, retain both architecture
// ASTs, and compare controlled-failure and actual filesec/ACL observations.
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

	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/pathsecurity"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func main() {
	capture := flag.Bool("capture", false, "capture unapproved observations; never passes qualification")
	source := flag.String("source", "", "optional pinned source file; SHA-256 remains mandatory")
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
	const dir = "artifacts/path-security-native"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	var source []byte
	var err error
	if cache != "" {
		source, err = os.ReadFile(cache)
	} else {
		client := http.Client{Timeout: 60 * time.Second}
		r, e := client.Get("https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c")
		if e != nil {
			return e
		}
		defer r.Body.Close()
		if r.StatusCode != http.StatusOK {
			return fmt.Errorf("copyfile source HTTP %d", r.StatusCode)
		}
		source, err = io.ReadAll(io.LimitReader(r.Body, 2<<20))
	}
	if err != nil {
		return err
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(source))
	if sum != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" {
		return fmt.Errorf("source hash %s", sum)
	}
	if err = os.WriteFile(filepath.Join(dir, "copyfile.c"), source, 0600); err != nil {
		return err
	}
	license := bytes.Index(source, []byte("#include"))
	if license < 0 {
		return fmt.Errorf("missing source license boundary")
	}
	extracted := bytes.Clone(source[:license])
	for _, bounds := range [][2]string{
		{"static int\nacl_compare_permset_np(acl_permset_t p1, acl_permset_t p2)", "\n\nstatic int\ndoesdecmpfs"},
		{"static int\nadd_uberace(acl_t *acl)", "\n/*\n * copytree --"},
		{"static filesec_t copyfile_fix_perms(copyfile_state_t s __unused, filesec_t *fsec)", "\n/*\n * Used to clear out the BSD/POSIX"},
	} {
		start := bytes.Index(source, []byte(bounds[0]))
		if start < 0 {
			return fmt.Errorf("missing function %s", bounds[0])
		}
		end := bytes.Index(source[start:], []byte(bounds[1]))
		if end < 0 {
			return fmt.Errorf("missing boundary %s", bounds[1])
		}
		extracted = append(extracted, source[start:start+end]...)
		extracted = append(extracted, '\n')
	}
	if err = os.WriteFile(filepath.Join(dir, "path-security-source.h"), extracted, 0600); err != nil {
		return err
	}
	const helperSource = "testdata/appledouble/native/path-security.c"
	for _, arch := range []string{"arm64", "x86_64"} {
		cmd := cirunner.Command("xcrun", "clang", "-arch", arch, "-I", dir, "-fsyntax-only", "-Xclang", "-ast-dump=json", helperSource)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		ast, e := cmd.Output()
		if e != nil {
			return fmt.Errorf("%s AST: %w: %s", arch, e, stderr.String())
		}
		if e = os.WriteFile(filepath.Join(dir, arch+".ast.json"), ast, 0600); e != nil {
			return e
		}
	}
	helper := filepath.Join(dir, "path-security")
	if out, e := cirunner.Command("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-I", dir, helperSource, "-o", helper).CombinedOutput(); e != nil {
		return fmt.Errorf("compile: %w: %s", e, out)
	}
	cases := pathsecurity.Cases()
	var input strings.Builder
	for _, c := range cases {
		fmt.Fprintf(&input, "%d %d %d %d %d %d\n", c.Operation, c.Count, c.First, c.Flags, c.Mode, c.Fault)
	}
	cmd := cirunner.Command(helper)
	cmd.Stdin = strings.NewReader(input.String())
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("native helper: %w; captured %d bytes", err, len(out))
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
			return fmt.Errorf("case %d: %w", i, err)
		}
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("unexpected trailing observations: %v", err)
	}
	revision, err := cirunner.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	host, err := cirunner.Command("sw_vers").Output()
	if err != nil {
		return err
	}
	help, err := os.ReadFile(helperSource)
	if err != nil {
		return err
	}
	fixture := pathsecurity.Fixture{Revision: strings.TrimSpace(string(revision)), Host: string(host), SourceSHA256: sum, HelperSHA256: fmt.Sprintf("%x", sha256.Sum256(help)), Cases: cases}
	encoded, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "observations.json"), append(encoded, '\n'), 0600); err != nil {
		return err
	}
	if !capture {
		f, e := os.Open("testdata/appledouble/native/path-security.json.gz")
		if e != nil {
			return e
		}
		defer f.Close()
		z, e := gzip.NewReader(f)
		if e != nil {
			return e
		}
		defer z.Close()
		var approved pathsecurity.Fixture
		if e = json.NewDecoder(z).Decode(&approved); e != nil {
			return e
		}
		if approved.SourceSHA256 != sum || approved.HelperSHA256 != fixture.HelperSHA256 || !reflect.DeepEqual(approved.Cases, cases) {
			return fmt.Errorf("native observations differ from approved fixture")
		}
	}
	hashes := map[string]string{}
	for _, p := range []string{helperSource, "scripts/verify-path-security-native.go", "internal/testutil/pathsecurity/oracle.go"} {
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		hashes[p] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	report := map[string]any{"passed": !capture, "capture": capture, "cases": len(cases), "revision": fixture.Revision, "host": fixture.Host, "goos": runtime.GOOS, "goarch": runtime.GOARCH, "source_sha256": hashes, "copyfile_sha256": sum}
	encoded, err = json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "report.json"), append(encoded, '\n'), 0600); err != nil {
		return err
	}
	fmt.Printf("path security: %d cases; capture=%t\n", len(cases), capture)
	return nil
}

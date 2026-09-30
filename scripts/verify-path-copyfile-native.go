//go:build ignore

// Run installed macOS copyfile on real disposable path objects, preserving
// creation/cleanup, ACL, contents, callback and explicit state-free evidence.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/pathnative"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func main() {
	capture := flag.Bool("capture", false, "retain unapproved native observations")
	flag.Parse()
	if err := verify(*capture); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func verify(capture bool) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("native qualification requires macOS")
	}
	const dir = "artifacts/path-copyfile-native"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	const source = "testdata/appledouble/native/path-copyfile.c"
	for _, arch := range []string{"arm64", "x86_64"} {
		cmd := exec.Command("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		ast, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("AST %s: %w %s", arch, err, stderr.String())
		}
		if err = os.WriteFile(filepath.Join(dir, arch+".ast.json"), ast, 0600); err != nil {
			return err
		}
	}
	helper, err := filepath.Abs(filepath.Join(dir, "path-copyfile"))
	if err != nil {
		return err
	}
	if out, err := exec.Command("xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", helper).CombinedOutput(); err != nil {
		return fmt.Errorf("compile: %w %s", err, out)
	}
	cases := pathnative.Cases()
	for i := range cases {
		if err := observe(helper, dir, &cases[i]); err != nil {
			return fmt.Errorf("case %d (%+v): %w", i, cases[i], err)
		}
	}
	revision, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	host, err := exec.Command("sw_vers").Output()
	if err != nil {
		return err
	}
	helperBytes, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	fixture := pathnative.Fixture{Revision: strings.TrimSpace(string(revision)), Host: string(host), HelperSHA256: fmt.Sprintf("%x", sha256.Sum256(helperBytes)), Cases: cases}
	encoded, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "observations.json"), append(encoded, '\n'), 0600); err != nil {
		return err
	}
	if !capture {
		f, err := os.Open("testdata/appledouble/native/path-copyfile.json.gz")
		if err != nil {
			return err
		}
		defer f.Close()
		z, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer z.Close()
		var approved pathnative.Fixture
		if err = json.NewDecoder(z).Decode(&approved); err != nil {
			return err
		}
		if approved.HelperSHA256 != fixture.HelperSHA256 || !reflect.DeepEqual(approved.Cases, cases) {
			return fmt.Errorf("native path behavior changed")
		}
	}
	hashes := map[string]string{}
	for _, p := range []string{source, "scripts/verify-path-copyfile-native.go", "internal/testutil/pathnative/oracle.go"} {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		hashes[p] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	report := map[string]any{"passed": !capture, "capture": capture, "cases": len(cases), "revision": fixture.Revision, "host": fixture.Host, "goos": runtime.GOOS, "goarch": runtime.GOARCH, "source_sha256": hashes}
	encoded, err = json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "report.json"), append(encoded, '\n'), 0600); err != nil {
		return err
	}
	fmt.Printf("public path copyfile: %d cases; capture=%t\n", len(cases), capture)
	return nil
}

func observe(helper, dir string, c *pathnative.Case) error {
	root, err := os.MkdirTemp(dir, "case-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	src, dst, target := filepath.Join(root, "source"), filepath.Join(root, "destination"), filepath.Join(root, "target")
	if err = os.WriteFile(target, []byte("TARGET"), 0440); err != nil {
		return err
	}
	data := []byte("SOURCE")
	if c.Route == 1 {
		data, err = (&appledouble.File{Attrs: []appledouble.Attr{{Name: "com.example.path", Value: []byte("source")}}}).Encode()
		if err != nil {
			return err
		}
	}
	kind := c.SourceKind
	if c.Route == 1 && kind == 1 {
		data = data[:len(data)-1]
		kind = 0
	} else if c.Route == 1 && kind > 1 {
		kind--
	}
	switch kind {
	case 0:
		err = os.WriteFile(src, data, 0440)
	case 1:
		err = os.Mkdir(src, 0550)
	case 2:
		err = os.WriteFile(filepath.Join(root, "source-target"), data, 0440)
		if err == nil {
			err = os.Symlink("source-target", src)
		}
	case 3:
		err = os.Symlink("missing-source", src)
	}
	if err != nil {
		return err
	}
	switch c.DestinationKind {
	case 1:
		err = os.WriteFile(dst, []byte("DESTINATION"), 0400)
	case 2:
		err = os.Mkdir(dst, 0500)
	case 3:
		err = os.Symlink("target", dst)
	case 4:
		err = os.Symlink("missing-destination", dst)
	}
	if err != nil {
		return err
	}
	if c.NullSource {
		src = os.DevNull
	}
	mask := -1
	if c.SetUmask {
		mask = c.Umask
	}
	cmd := exec.Command(helper, src, dst, target, strconv.Itoa(c.Route), strconv.Itoa(c.Selected), strconv.Itoa(c.Quit), strconv.Itoa(c.SourceMode), strconv.Itoa(mask))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("helper: %w %s %s", err, stderr.String(), out)
	}
	if err = json.Unmarshal(out, &c.Native); err != nil {
		return fmt.Errorf("decode: %w %s", err, out)
	}
	if st, err := os.Lstat(dst); err == nil && st.Mode().IsRegular() {
		b, err := os.ReadFile(dst)
		if err != nil {
			return err
		}
		c.Native.DestinationSHA256 = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	return nil
}

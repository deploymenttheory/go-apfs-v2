//go:build ignore

// Invoke with capture-pathname-authorization-ast.go to reuse its exact AST-body
// and compiler dependency validators without changing the retained base corpus.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

const nameCacheSource = "testdata/appledouble/native/name-cache-source"

type cacheSourceManifest struct {
	Schema         int             `json:"schema"`
	Release        string          `json:"release"`
	URL            string          `json:"url"`
	SourceSHA256   string          `json:"source_sha256"`
	Start          int             `json:"start"`
	End            int             `json:"end"`
	FragmentSHA256 string          `json:"fragment_sha256"`
	Functions      []cacheFunction `json:"functions"`
}
type cacheFunction struct {
	Name   string `json:"name"`
	Brace  int    `json:"brace"`
	End    int    `json:"end"`
	SHA256 string `json:"sha256"`
}

func cacheTranslation(m cacheSourceManifest, source []byte) ([]byte, map[string]bodyRange, error) {
	if m.Schema != 1 || m.Release != "xnu-11417.140.69" || m.URL != "https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-11417.140.69/bsd/vfs/vfs_cache.c" || digest(source) != m.SourceSHA256 || m.Start < 0 || m.End <= m.Start || m.End > len(source) || len(m.Functions) != 5 {
		return nil, nil, errors.New("invalid cache source manifest")
	}
	body := source[m.Start:m.End]
	if digest(body) != m.FragmentSHA256 {
		return nil, nil, errors.New("changed complete cache fragment")
	}
	prefix := []byte("#include \"declarations.h\"\n#include \"cache-declarations.h\"\n")
	want := []string{"save_ndp_state", "restore_ndp_state", "vid_is_same", "can_check_v_mountedhere", "cache_lookup_path"}
	ranges := map[string]bodyRange{}
	for i, f := range m.Functions {
		if f.Name != want[i] || f.Brace < m.Start || f.End <= f.Brace || f.End > m.End || source[f.Brace] != '{' || source[f.End-1] != '}' || digest(source[f.Brace:f.End]) != f.SHA256 {
			return nil, nil, errors.New("incomplete cache body inventory")
		}
		ranges[f.Name] = bodyRange{len(prefix) + f.Brace - m.Start, len(prefix) + f.End - m.Start - 1}
	}
	return append(prefix, body...), ranges, nil
}
func cacheInputs(t *testing.T) (string, cacheSourceManifest, []byte) {
	t.Helper()
	root, e := filepath.Abs("..")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(root, nameCacheSource)); e != nil {
		root, e = filepath.Abs(".")
		if e != nil {
			t.Fatal(e)
		}
	}
	raw, e := os.ReadFile(filepath.Join(root, nameCacheSource, "source.json"))
	if e != nil {
		t.Fatal(e)
	}
	var m cacheSourceManifest
	if e = json.Unmarshal(raw, &m); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(filepath.Join(root, nameCacheSource, "vfs_cache.c.gz"))
	if e != nil {
		t.Fatal(e)
	}
	z, e := gzip.NewReader(f)
	if e != nil {
		f.Close()
		t.Fatal(e)
	}
	source, e := io.ReadAll(z)
	e = errors.Join(e, z.Close(), f.Close())
	if e != nil {
		t.Fatal(e)
	}
	return root, m, source
}
func TestNameCacheSourceIntegrity(t *testing.T) {
	_, m, source := cacheInputs(t)
	if _, _, e := cacheTranslation(m, source); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*cacheSourceManifest){
		func(m *cacheSourceManifest) { m.Schema++ }, func(m *cacheSourceManifest) { m.Release = "other" }, func(m *cacheSourceManifest) { m.URL = "other" }, func(m *cacheSourceManifest) { m.SourceSHA256 = "changed" }, func(m *cacheSourceManifest) { m.Start = -1 }, func(m *cacheSourceManifest) { m.End = len(source) + 1 }, func(m *cacheSourceManifest) { m.FragmentSHA256 = "changed" }, func(m *cacheSourceManifest) { m.Functions = m.Functions[:4] }, func(m *cacheSourceManifest) { m.Functions[0].Name = "other" }, func(m *cacheSourceManifest) { m.Functions[0].Brace++ }, func(m *cacheSourceManifest) { m.Functions[0].End-- }, func(m *cacheSourceManifest) { m.Functions[0].SHA256 = "changed" },
	} {
		bad := m
		bad.Functions = append([]cacheFunction(nil), m.Functions...)
		mutate(&bad)
		if _, _, e := cacheTranslation(bad, source); e == nil {
			t.Fatal("changed source qualification accepted")
		}
	}
}
func TestNativeNameCacheAST(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Fatal("native SDK qualification requires Darwin")
	}
	root, m, source := cacheInputs(t)
	unit, ranges, e := cacheTranslation(m, source)
	if e != nil {
		t.Fatal(e)
	}
	out := os.Getenv("APFS_NAME_CACHE_AST_OUT")
	if out == "" {
		out = filepath.Join(root, "artifacts", "name-cache-ast")
	}
	if e = os.MkdirAll(out, 0755); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	run := func(name string, args ...string) string {
		t.Helper()
		b, e := cirunner.CommandContext(ctx, name, args...).CombinedOutput()
		if e != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, e, b)
		}
		return strings.TrimSpace(string(b))
	}
	sdk := run("xcrun", "--show-sdk-path")
	compiler := run("xcrun", "clang", "--version")
	inputs := map[string]string{}
	retained := map[string]string{}
	if e = os.MkdirAll(filepath.Join(out, "inputs"), 0755); e != nil {
		t.Fatal(e)
	}
	read := func(path string) []byte {
		t.Helper()
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		inputs[path] = digest(b)
		artifact := filepath.Join("inputs", digest(b)+"-"+filepath.Base(path))
		if e = os.WriteFile(filepath.Join(out, artifact), b, 0644); e != nil {
			t.Fatal(e)
		}
		retained[path] = filepath.ToSlash(artifact)
		return b
	}
	write := func(name string, b []byte) {
		t.Helper()
		if e := os.WriteFile(filepath.Join(out, name), b, 0644); e != nil {
			t.Fatal(e)
		}
	}
	base := read(filepath.Join(root, pinned, "declarations.h"))
	// These explicit private field projections allow syntax/control-flow parsing;
	// they are never linked, executed, or presented as ABI layouts.
	for _, edit := range [][2]string{
		{"const char *v_name; };", "const char *v_name; uint32_t v_id; uint32_t v_authorized_actions; int v_cred_timestamp; vnode_t v_fmlink; mount_t v_mountedhere; void *v_resolve; };"},
		{"uint32_t mnt_kern_flag; };", "uint32_t mnt_kern_flag; int mnt_authcache_ttl; uint32_t mnt_generation; vnode_t mnt_realrootvp; uint32_t mnt_realrootvp_vid; };"},
	} {
		if bytes.Count(base, []byte(edit[0])) != 1 {
			t.Fatal("private declaration projection changed")
		}
		base = bytes.Replace(base, []byte(edit[0]), []byte(edit[1]), 1)
	}
	write("declarations.h", base)
	write("cache-declarations.h", read(filepath.Join(root, nameCacheSource, "declarations.h")))
	write("bodies.c", unit)
	for _, p := range []string{"source.json", "vfs_cache.c.gz"} {
		read(filepath.Join(root, nameCacheSource, p))
	}
	for _, p := range []string{"scripts/capture-name-cache-ast_test.go", "scripts/capture-pathname-authorization-ast.go", ".github/workflows/name-cache-ast.yml", pinned + "/headers/vnode_internal.h.gz", pinned + "/headers/mount_internal.h.gz"} {
		read(filepath.Join(root, p))
	}
	outputs := map[string]string{"bodies.c": digest(unit), "declarations.h": digest(base)}
	summaries := map[string]map[string]int{}
	commands := map[string][]string{}
	for _, arch := range []string{"arm64", "x86_64"} {
		for _, enabled := range []string{"0", "1"} {
			id := arch + "-" + enabled
			dep := filepath.Join(out, id+".d")
			args := []string{"clang", "-target", arch + "-apple-macos15", "-isysroot", sdk, "-std=gnu11", "-fblocks", "-Werror", "-isystem", filepath.Join(sdk, "System/Library/Frameworks/Kernel.framework/Headers"), "-MD", "-MF", dep, "-Xclang", "-ast-dump=json", "-fsyntax-only"}
			for _, feature := range []string{"CONFIG_MACF", "CONFIG_TRIGGERS", "CONFIG_FIRMLINKS", "NAMEDRSRCFORK"} {
				args = append(args, "-D"+feature+"="+enabled)
			}
			args = append(args, filepath.Join(out, "bodies.c"))
			commands[id] = args
			cmd := cirunner.CommandContext(ctx, "xcrun", args...)
			var diag bytes.Buffer
			cmd.Stderr = &diag
			raw, e := cmd.Output()
			write(id+".diagnostics.txt", diag.Bytes())
			if e != nil {
				t.Fatalf("full cache bodies: %v\n%s", e, diag.Bytes())
			}
			write(id+".ast.json", raw)
			outputs[id+".ast.json"] = digest(raw)
			var ast astNode
			if e = json.Unmarshal(raw, &ast); e != nil {
				t.Fatal(e)
			}
			counts, e := qualifyAST(ast, ranges)
			if e != nil {
				t.Fatal(e)
			}
			summaries[id] = counts
			for _, path := range dependencyPaths(string(read(dep))) {
				read(path)
			}
		}
	}
	if len(summaries) != 4 || len(inputs) < 30 {
		t.Fatal("incomplete source and AST inventory")
	}
	report := map[string]any{"schema": 1, "release": m.Release, "revision": run("git", "-C", root, "rev-parse", "HEAD"), "host": run("sw_vers"), "sdk": sdk, "sdk_version": run("xcrun", "--show-sdk-version"), "compiler": compiler, "go": runtime.Version(), "source_sha256": inputs, "retained_inputs": retained, "evidence_sha256": outputs, "body_ranges": ranges, "ast_statement_nodes": summaries, "commands": commands, "functions": m.Functions, "qualification": "Five complete unchanged pinned bodies, declaration-only private field projections; syntax/control-flow evidence, not executable kernel behavior or ABI."}
	raw, e := json.MarshalIndent(report, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	write("capture.json", append(raw, '\n'))
	t.Log(fmt.Sprintf("5 full XNU cache bodies × 2 targets × 2 configurations; %d source dependencies", len(inputs)))
}

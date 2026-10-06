//go:build ignore

// Parse complete pinned XNU function bodies with explicit research declarations.
// This produces source/control-flow evidence, never a linked kernel substitute.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const pinned = "testdata/appledouble/native/pathname-authorization-source"

type sourceEntry struct{ File, URL, SHA256 string }
type sourceManifest struct {
	Release string
	Sources []sourceEntry
}
type fragment struct {
	Name, File, SHA256 string
	Start, End, Brace  int
}
type functionManifest struct {
	Schema  int
	Release string
	Entries []fragment
}
type astNode struct {
	Kind, Name string
	Inner      []astNode
	Range      struct{ Begin, End struct{ Offset int } }
}
type bodyRange struct{ Start, End int }

func main() {
	out := flag.String("out", "artifacts/pathname-authorization-ast", "new qualification directory")
	flag.Parse()
	if err := capture(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func capture(out string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("native SDK/Clang capture requires Darwin")
	}
	if err := os.MkdirAll(out, 0755); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	run := func(args ...string) ([]byte, error) {
		b, err := exec.CommandContext(ctx, "xcrun", args...).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("xcrun %v: %w\n%s", args, err, b)
		}
		return b, nil
	}
	compiler, err := run("clang", "--version")
	if err != nil {
		return err
	}
	rawSDK, err := run("--sdk", "macosx", "--show-sdk-path")
	if err != nil {
		return err
	}
	sdk := strings.TrimSpace(string(rawSDK))
	rawResource, err := run("clang", "-print-resource-dir")
	if err != nil {
		return err
	}
	resource := strings.TrimSpace(string(rawResource))
	sources := map[string]string{}
	decoded := map[string][]byte{}
	for _, dir := range []string{pinned, filepath.Join(pinned, "headers")} {
		raw, err := os.ReadFile(filepath.Join(dir, "sources.json"))
		if err != nil {
			return err
		}
		sources[filepath.ToSlash(filepath.Join(dir, "sources.json"))] = digest(raw)
		var m sourceManifest
		if err = json.Unmarshal(raw, &m); err != nil {
			return err
		}
		if m.Release != "xnu-11417.140.69" {
			return errors.New("unexpected pinned release")
		}
		for _, item := range m.Sources {
			if filepath.Base(item.File) != item.File || !strings.HasPrefix(item.URL, "https://raw.githubusercontent.com/apple-oss-distributions/xnu/"+m.Release+"/") {
				return errors.New("invalid source manifest identity")
			}
			p := filepath.Join(dir, item.File)
			raw, err = os.ReadFile(p)
			if err != nil {
				return err
			}
			sources[filepath.ToSlash(p)] = digest(raw)
			z, err := gzip.NewReader(bytes.NewReader(raw))
			if err != nil {
				return err
			}
			body, readErr := io.ReadAll(z)
			if err = errors.Join(readErr, z.Close()); err != nil {
				return err
			}
			if digest(body) != item.SHA256 {
				return fmt.Errorf("pinned source mismatch: %s", p)
			}
			if dir == pinned {
				decoded[strings.TrimSuffix(item.File, ".gz")] = body
			}
		}
	}
	manifestBytes, err := os.ReadFile(filepath.Join(pinned, "functions.json"))
	if err != nil {
		return err
	}
	var m functionManifest
	if err = json.Unmarshal(manifestBytes, &m); err != nil {
		return err
	}
	unit, ranges, err := translationUnit(m, decoded)
	if err != nil {
		return err
	}
	for _, p := range []string{filepath.Join(pinned, "functions.json"), filepath.Join(pinned, "declarations.h"), "scripts/capture-pathname-authorization-ast.go", "scripts/capture-pathname-authorization-ast_test.go", ".github/workflows/pathname-authorization.yml"} {
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		sources[filepath.ToSlash(p)] = digest(b)
	}
	shim, err := os.ReadFile(filepath.Join(pinned, "declarations.h"))
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(out, "declarations.h"), shim, 0644); err != nil {
		return err
	}
	unitPath := filepath.Join(out, "bodies.c")
	if err = os.WriteFile(unitPath, unit, 0644); err != nil {
		return err
	}
	evidence := map[string]string{"bodies.c": digest(unit), "declarations.h": digest(shim)}
	summaries := map[string]map[string]int{}
	commands := map[string][]string{}
	features := []string{"CONFIG_MACF", "CONFIG_APPLEDOUBLE", "CONFIG_AUDIT", "CONFIG_FSE", "CONFIG_TRIGGERS", "CONFIG_UNION_MOUNTS", "CONFIG_VOLFS", "DIAGNOSTIC", "NAMEDRSRCFORK", "SECURE_KERNEL"}
	for _, arch := range []string{"arm64", "x86_64"} {
		for _, config := range []string{"minimal", "enabled"} {
			key := arch + "-" + config
			astPath := filepath.Join(out, key+".ast.json")
			depPath := filepath.Join(out, key+".d")
			args := []string{"clang", "-target", arch + "-apple-macos15", "-isysroot", sdk, "-std=gnu11", "-fblocks", "-Werror", "-isystem", filepath.Join(sdk, "System/Library/Frameworks/Kernel.framework/Headers"), "-MD", "-MF", depPath, "-Xclang", "-ast-dump=json", "-fsyntax-only"}
			value := "0"
			if config == "enabled" {
				value = "1"
				args = append(args, "-DKAUTH_DEBUG_ENABLE=1")
			}
			for _, name := range features {
				args = append(args, "-D"+name+"="+value)
			}
			args = append(args, unitPath)
			commands[key] = args
			f, e := os.Create(astPath)
			if e != nil {
				return e
			}
			var diagnostic bytes.Buffer
			cmd := exec.CommandContext(ctx, "xcrun", args...)
			cmd.Stdout = f
			cmd.Stderr = &diagnostic
			runErr := cmd.Run()
			closeErr := f.Close()
			if e = os.WriteFile(filepath.Join(out, key+".diagnostics.txt"), diagnostic.Bytes(), 0644); e != nil {
				return e
			}
			if e = errors.Join(runErr, closeErr); e != nil {
				return fmt.Errorf("full-body Clang %s: %w\n%s", key, e, diagnostic.Bytes())
			}
			raw, e := os.ReadFile(astPath)
			if e != nil {
				return e
			}
			var ast astNode
			if e = json.Unmarshal(raw, &ast); e != nil {
				return e
			}
			counts, e := qualifyAST(ast, ranges)
			if e != nil {
				return fmt.Errorf("%s: %w", key, e)
			}
			summaries[key] = counts
			var compressed bytes.Buffer
			z := gzip.NewWriter(&compressed)
			_, e = z.Write(raw)
			if e = errors.Join(e, z.Close()); e != nil {
				return e
			}
			name := key + ".ast.json.gz"
			if e = os.WriteFile(filepath.Join(out, name), compressed.Bytes(), 0644); e != nil {
				return e
			}
			evidence[name] = digest(compressed.Bytes())
			if e = os.Remove(astPath); e != nil {
				return e
			}
			dep, e := os.ReadFile(depPath)
			if e != nil {
				return e
			}
			for _, p := range dependencyPaths(string(dep)) {
				prefix := ""
				relative := ""
				if strings.HasPrefix(p, sdk+"/") {
					prefix = "SDK"
					relative = strings.TrimPrefix(p, sdk+"/")
				} else if strings.HasPrefix(p, resource+"/") {
					prefix = "Clang"
					relative = strings.TrimPrefix(p, resource+"/")
				} else if filepath.Base(p) == "bodies.c" || filepath.Base(p) == "declarations.h" {
					continue
				} else {
					return fmt.Errorf("unbound compilation dependency: %s", p)
				}
				b, e := os.ReadFile(p)
				if e != nil {
					return e
				}
				name := prefix + "/" + filepath.ToSlash(relative)
				sources[name] = digest(b)
				destination := filepath.Join(out, prefix, relative)
				if e = os.MkdirAll(filepath.Dir(destination), 0755); e != nil {
					return e
				}
				if e = os.WriteFile(destination, b, 0644); e != nil {
					return e
				}
			}

		}
	}
	if len(summaries) != 4 || len(sources) < 40 {
		return errors.New("incomplete source/AST inventory")
	}
	revision, err := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	report := map[string]any{"schema": 1, "release": m.Release, "revision": strings.TrimSpace(string(revision)), "compiler": string(compiler), "sdk": sdk, "go": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "source_sha256": sources, "evidence_sha256": evidence, "functions": m.Entries, "body_ranges": ranges, "ast_statement_nodes": summaries, "commands": commands, "qualification": "Complete unchanged pinned bodies; declaration-only private layout projections; parsed control flow, not runtime ABI or a kernel execution oracle."}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(out, "capture.json"), append(b, '\n'), 0644); err != nil {
		return err
	}
	fmt.Printf("24 complete pinned XNU bodies, two configurations, two architectures; %d bound source inputs\n", len(sources))
	return nil
}
func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func translationUnit(m functionManifest, sources map[string][]byte) ([]byte, map[string]bodyRange, error) {
	if m.Schema != 1 || m.Release != "xnu-11417.140.69" || len(m.Entries) != 25 {
		return nil, nil, errors.New("incomplete function manifest")
	}
	var declarations, bodies bytes.Buffer
	declarations.WriteString("#include \"declarations.h\"\n")
	ranges := map[string]bodyRange{}
	seen := map[string]bool{}
	for _, f := range m.Entries {
		source := sources[f.File]
		if f.Name == "" || seen[f.Name] || f.Start < 0 || f.End <= f.Start || f.End > len(source) {
			return nil, nil, errors.New("invalid fragment range or name")
		}
		seen[f.Name] = true
		body := source[f.Start:f.End]
		if digest(body) != f.SHA256 {
			return nil, nil, fmt.Errorf("fragment source mismatch: %s", f.Name)
		}
		if f.Brace == 0 {
			if f.Name != "vauth_ctx" {
				return nil, nil, errors.New("unexpected declaration fragment")
			}
			declarations.Write(body)
			declarations.WriteByte('\n')
			continue
		}
		if f.Brace < f.Start || f.Brace >= f.End || source[f.Brace] != '{' || source[f.End-1] != '}' || !bytes.Contains(source[f.Start:f.Brace], []byte(f.Name+"(")) {
			return nil, nil, errors.New("fragment is not a complete named function")
		}
		declarations.Write(source[f.Start:f.Brace])
		declarations.WriteString(";\n")
		fmt.Fprintf(&bodies, "\n#line %d %q\n", bytes.Count(source[:f.Start], []byte{'\n'})+1, f.File)
		start := bodies.Len()
		bodies.Write(body)
		ranges[f.Name] = bodyRange{start + (f.Brace - f.Start), bodies.Len() - 1}
		bodies.WriteByte('\n')
	}
	if len(ranges) != 24 || !seen["vauth_ctx"] {
		return nil, nil, errors.New("incomplete policy body inventory")
	}
	offset := declarations.Len()
	for name, r := range ranges {
		ranges[name] = bodyRange{r.Start + offset, r.End + offset}
	}
	return append(declarations.Bytes(), bodies.Bytes()...), ranges, nil
}
func qualifyAST(root astNode, expected map[string]bodyRange) (map[string]int, error) {
	counts := map[string]int{}
	var problem error
	var visit func(astNode)
	visit = func(n astNode) {
		if n.Kind == "FunctionDecl" {
			if want, ok := expected[n.Name]; ok {
				for _, child := range n.Inner {
					if child.Kind == "CompoundStmt" {
						if _, exists := counts[n.Name]; exists || child.Range.Begin.Offset != want.Start || child.Range.End.Offset != want.End {
							problem = fmt.Errorf("incomplete or duplicate source body: %s", n.Name)
							return
						}
						counts[n.Name] = statementNodes(child)
					}
				}
			}
		}
		for _, child := range n.Inner {
			visit(child)
		}
	}
	visit(root)
	if problem != nil {
		return nil, problem
	}
	if len(counts) != len(expected) {
		return nil, errors.New("missing complete function bodies in AST")
	}
	for name, n := range counts {
		if n < 2 {
			return nil, fmt.Errorf("empty function AST: %s", name)
		}
	}
	return counts, nil
}
func statementNodes(n astNode) int {
	count := 0
	if strings.HasSuffix(n.Kind, "Stmt") || strings.HasSuffix(n.Kind, "Expr") {
		count++
	}
	for _, child := range n.Inner {
		count += statementNodes(child)
	}
	return count
}
func dependencyPaths(s string) []string {
	_, s, _ = strings.Cut(s, ":")
	s = strings.ReplaceAll(s, "\\\n", "")
	var paths []string
	var token strings.Builder
	escaped := false
	for _, r := range s {
		if escaped {
			token.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == ' ' || r == '\n' || r == '\t' {
			if token.Len() > 0 {
				paths = append(paths, token.String())
				token.Reset()
			}
			continue
		}
		token.WriteRune(r)
	}
	if token.Len() > 0 {
		paths = append(paths, token.String())
	}
	return paths
}

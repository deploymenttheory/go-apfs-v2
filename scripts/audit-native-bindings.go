//go:build ignore

// Audit the published dependency boundary independently of CGO-disabled builds.
// This is a research/CI driver, never a production runtime dependency.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"

	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

type finding struct {
	Source string `json:"source"`
	SHA256 string `json:"sha256"`
	Import string `json:"import"`
}

type target struct {
	OS        string   `json:"os"`
	Arch      string   `json:"arch"`
	Packages  int      `json:"packages"`
	Forbidden []string `json:"forbidden"`
}

func main() {
	check := flag.Bool("check", false, "fail if purego remains in source imports or any production target")
	out := flag.String("output", "artifacts/native-bindings/audit.json", "audit report")
	flag.Parse()
	if err := audit(*out, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func audit(output string, check bool) error {
	var imports []finding
	for _, root := range []string{"pkg", "internal", "cmd"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			source, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ParseComments)
			if err != nil {
				return err
			}
			record := func(reason string) {
				hash := sha256.Sum256(source)
				imports = append(imports, finding{filepath.ToSlash(path), hex.EncodeToString(hash[:]), reason})
			}
			approved := strings.HasPrefix(filepath.ToSlash(path), "internal/darwinabi/") || strings.HasPrefix(filepath.ToSlash(path), "internal/testutil/quarantineoracle/")
			for _, group := range file.Comments {
				for _, c := range group.List {
					if !approved && (strings.HasPrefix(c.Text, "//go:linkname") || strings.HasPrefix(c.Text, "//go:cgo_import_dynamic")) {
						record("native directive outside typed extension")
					}
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "Dlopen", "Dlsym", "RegisterFunc", "SyscallN":
					record("generic native call: " + sel.Sel.Name)
				}
				return true
			})
			for _, spec := range file.Imports {
				name, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					return err
				}
				if name == "C" || name == "github.com/ebitengine/purego" || strings.HasPrefix(name, "github.com/ebitengine/purego/") {
					hash := sha256.Sum256(source)
					imports = append(imports, finding{filepath.ToSlash(path), hex.EncodeToString(hash[:]), name})
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	var targets []target
	bad := len(imports) != 0
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, arch := range []string{"amd64", "arm64"} {
			cmd := cirunner.Command("go", "list", "-deps", "-json", "./cmd/...", "./pkg/...")
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+arch, "GOWORK=off")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			data, err := cmd.Output()
			if err != nil {
				return fmt.Errorf("%s/%s dependency enumeration: %w: %s", goos, arch, err, stderr.String())
			}
			result := target{OS: goos, Arch: arch, Forbidden: []string{}}
			decoder := json.NewDecoder(bytes.NewReader(data))
			for {
				var pkg struct {
					ImportPath string
					CgoFiles   []string
				}
				if err := decoder.Decode(&pkg); err == io.EOF {
					break
				} else if err != nil {
					return err
				}
				result.Packages++
				if pkg.ImportPath == "github.com/ebitengine/purego" || strings.HasPrefix(pkg.ImportPath, "github.com/ebitengine/purego/") || len(pkg.CgoFiles) != 0 {
					result.Forbidden = append(result.Forbidden, pkg.ImportPath)
				}
			}
			sort.Strings(result.Forbidden)
			bad = bad || len(result.Forbidden) != 0
			targets = append(targets, result)
			fmt.Printf("%s/%s: %d packages, %d forbidden dependencies\n", goos, arch, result.Packages, len(result.Forbidden))
		}
	}
	module, err := os.ReadFile("go.mod")
	if err != nil {
		return err
	}
	if bytes.Contains(module, []byte("github.com/ebitengine/purego")) {
		bad = true
	}
	moduleHash := sha256.Sum256(module)
	report := struct {
		ModuleSHA256  string    `json:"module_sha256"`
		SourceImports []finding `json:"source_imports"`
		Targets       []target  `json:"targets"`
		Passed        bool      `json:"passed"`
	}{hex.EncodeToString(moduleHash[:]), imports, targets, !bad}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(output, append(data, '\n'), 0644); err != nil {
		return err
	}
	if check && bad {
		return fmt.Errorf("native-binding audit failed; report: %s", output)
	}
	return nil
}

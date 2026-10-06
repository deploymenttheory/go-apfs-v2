//go:build ignore

// Research-only Darwin syscall capture. No production package dependencies.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type caseSpec struct {
	ID         string `json:"id"`
	Family     string `json:"family"`
	Profile    string `json:"profile"`
	Operation  string `json:"operation"`
	Route      string `json:"route"`
	Privileged bool   `json:"privileged_fixture"`
}

func cases() []caseSpec {
	var out []caseSpec
	add := func(family string, profiles, operations []string, privileged bool) {
		for _, profile := range profiles {
			for _, operation := range operations {
				for _, route := range []string{"path", "root", "parent"} {
					out = append(out, caseSpec{family + "/" + profile + "/" + operation + "/" + route, family, profile, operation, route, privileged})
				}
			}
		}
	}
	add("control", []string{"ordinary"}, []string{"open", "create", "unlink", "rename", "rename-absent", "rename-cross", "held-write", "chmod-open"}, false)
	add("search", []string{"root-no-search", "middle-no-search", "parent-no-search", "parent-search-only", "parent-list-only", "parent-no-write", "parent-deny-search", "parent-allow-search", "parent-allow-deny-search", "parent-deny-allow-search", "parent-generic-execute", "parent-group-deny-search", "parent-group-allow-search"}, []string{"open", "held-write", "chmod-open"}, false)
	add("search", []string{"group-search-allow", "group-search-deny", "other-search-allow", "other-search-deny"}, []string{"open"}, true)
	add("create", []string{"parent-no-search", "parent-no-write", "parent-deny-search", "parent-deny-add", "parent-allow-add", "parent-immutable", "parent-append"}, []string{"create"}, false)
	add("delete", []string{"parent-no-search", "parent-no-write", "parent-deny-delete", "leaf-deny-delete", "leaf-allow-parent-deny", "leaf-deny-parent-allow", "parent-immutable", "parent-append", "leaf-immutable", "leaf-append", "sticky-owner"}, []string{"unlink"}, false)
	add("delete", []string{"sticky-neither", "sticky-parent-owner"}, []string{"unlink"}, true)
	add("rename", []string{"parent-no-search", "parent-no-write", "parent-deny-add", "parent-deny-delete", "leaf-deny-delete", "leaf-allow-parent-deny", "leaf-deny-parent-allow", "stage-deny-delete", "stage-immutable", "parent-immutable", "parent-append", "leaf-immutable", "leaf-append", "sticky-owner"}, []string{"rename"}, false)
	add("rename", []string{"sticky-neither", "sticky-parent-owner"}, []string{"rename"}, true)
	add("rename-absent", []string{"parent-no-search", "parent-no-write", "parent-deny-add", "parent-deny-delete", "leaf-deny-delete", "stage-deny-delete", "stage-immutable", "parent-immutable", "parent-append"}, []string{"rename-absent"}, false)
	add("rename-cross", []string{"parent-no-search", "parent-no-write", "parent-deny-delete", "stage-deny-delete", "stage-immutable", "destination-deny-search", "destination-deny-add", "destination-deny-delete", "destination-no-write", "destination-immutable"}, []string{"rename-cross"}, false)
	return out
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(path string) []byte { b, e := os.ReadFile(path); must(e); return b }
func hash(b []byte) string    { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func command(name string, args ...string) []byte {
	b, e := exec.Command(name, args...).CombinedOutput()
	if e != nil {
		panic(fmt.Sprintf("%s %v: %v\n%s", name, args, e, b))
	}
	return b
}
func writeJSON(path string, v any) {
	b, e := json.MarshalIndent(v, "", "  ")
	must(e)
	must(os.WriteFile(path, append(b, '\n'), 0644))
}
func main() {
	out := flag.String("out", "", "new evidence directory")
	cfile := flag.String("source", "testdata/appledouble/native/pathname-authorization.c", "C oracle")
	apple := flag.String("apple-source-dir", "testdata/appledouble/native/pathname-authorization-source", "existing pinned Apple source captures")
	sudo := flag.Bool("sudo", false, "use sudo -n for privileged ownership cases only; never prompt")
	require := flag.Bool("require-complete", false, "fail if any planned case is unavailable")
	uid := flag.Int("actor-uid", os.Getuid(), "unprivileged actor uid")
	gid := flag.Int("actor-gid", os.Getgid(), "actor primary gid")
	flag.Parse()
	if runtime.GOOS != "darwin" || *uid == 0 {
		panic("capture requires Darwin and an explicitly non-root actor")
	}
	var err error
	if *out == "" {
		*out, err = os.MkdirTemp("", "apfs-pathname-evidence-")
		must(err)
	} else {
		must(os.Mkdir(*out, 0755))
	}
	oracle := filepath.Join(*out, "probe.c")
	must(os.WriteFile(oracle, read(*cfile), 0644))
	binary := filepath.Join(*out, "probe")
	compiler := command("xcrun", "clang", "--version")
	sdk := strings.TrimSpace(string(command("xcrun", "--sdk", "macosx", "--show-sdk-path")))
	command("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", oracle, "-o", binary)
	sources := map[string]string{"probe.c": hash(read(oracle)), "probe": hash(read(binary)), "capture.go": hash(read("scripts/capture-pathname-authorization.go"))}
	must(os.WriteFile(filepath.Join(*out, "capture.go"), read("scripts/capture-pathname-authorization.go"), 0644))
	for _, target := range []string{"arm64-apple-macos15", "x86_64-apple-macos15"} {
		ast := command("xcrun", "clang", "-target", target, "-isysroot", sdk, "-std=c11", "-Xclang", "-ast-dump=json", "-fsyntax-only", oracle)
		name := target + ".ast.json"
		must(os.WriteFile(filepath.Join(*out, name), ast, 0644))
		sources[name] = hash(ast)
	}
	for _, h := range []string{"sys/stat.h", "sys/mount.h", "sys/acl.h", "sys/kauth.h", "sys/fcntl.h", "sys/resource.h", "membership.h"} {
		sources["SDK/"+h] = hash(read(filepath.Join(sdk, "usr/include", h)))
	}
	appleDir := filepath.Join(*out, "apple-source")
	must(os.Mkdir(appleDir, 0755))
	var sourceManifest struct {
		Release string `json:"release"`
		Sources []struct {
			URL    string `json:"url"`
			File   string `json:"file"`
			SHA256 string `json:"sha256"`
		} `json:"sources"`
	}
	must(json.Unmarshal(read(filepath.Join(*apple, "sources.json")), &sourceManifest))
	if sourceManifest.Release != "xnu-11417.140.69" {
		panic("unexpected source release")
	}
	for _, entry := range sourceManifest.Sources {
		compressed := read(filepath.Join(*apple, entry.File))
		reader, e := gzip.NewReader(bytes.NewReader(compressed))
		must(e)
		raw, e := io.ReadAll(reader)
		must(e)
		must(reader.Close())
		if hash(raw) != entry.SHA256 {
			panic("retained source hash differs: " + entry.File)
		}
		name := strings.TrimSuffix(entry.File, ".gz")
		must(os.WriteFile(filepath.Join(appleDir, name), raw, 0644))
		sources["apple-source/"+name] = hash(raw)
	}
	manifest := cases()
	writeJSON(filepath.Join(*out, "case-manifest.json"), map[string]any{"schema": 1, "qualification": "specified-before-capture", "cases": manifest})
	sources["case-manifest.json"] = hash(read(filepath.Join(*out, "case-manifest.json")))
	var sudoAvailable bool
	var sudoDiagnostic string
	if *sudo {
		b, e := exec.Command("sudo", "-n", "true").CombinedOutput()
		sudoAvailable = e == nil
		sudoDiagnostic = string(b)
	}
	var observations []map[string]any
	unavailable, failed := 0, 0
	for _, c := range manifest {
		name := binary
		args := []string{c.Profile, c.Operation, c.Route, strconv.Itoa(*uid), strconv.Itoa(*gid)}
		if c.Privileged && sudoAvailable {
			args = append([]string{"-n", binary}, args...)
			name = "sudo"
		}
		cmd := exec.Command(name, args...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		b, e := cmd.Output()
		var row map[string]any
		if e != nil {
			row = map[string]any{"qualification": "failed", "error": e.Error(), "stdout": string(b), "stderr": stderr.String()}
			failed++
		} else {
			must(json.Unmarshal(b, &row))
		}
		row["id"] = c.ID
		row["family"] = c.Family
		if row["qualification"] == "unavailable" {
			unavailable++
		}
		if row["qualification"] == "captured" {
			if row["cleanup_complete"] != true {
				panic("cleanup incomplete: " + c.ID)
			}
			r, ok := row["result"].(map[string]any)
			if !ok || r["setup_errno"] != float64(0) || r["close_errno"] != float64(0) {
				panic("actor/descriptor setup failed: " + c.ID)
			}
			if c.Profile == "ordinary" && r["errno"] != float64(0) {
				panic("positive operation control failed: " + c.ID)
			}
			fmt.Printf("%s errno=%v\n", c.ID, r["errno"])
		} else {
			fmt.Printf("%s %v\n", c.ID, row["qualification"])
		}
		observations = append(observations, row)
	}
	writeJSON(filepath.Join(*out, "capture.json"), map[string]any{"schema": 1, "scope": "Independent pathname/search/create/delete/rename syscall observations. Held file reads used by snapshots may affect access time; timestamps do not isolate operation attribution. No native codesign acceptance is inferred. Both Clang ASTs describe the C driver and SDK declarations; pinned XNU policy bodies are source-reviewed and are not compiled into this oracle.", "host": string(command("sw_vers")), "compiler": string(compiler), "sdk": sdk, "source_sha256": sources, "apple_source_release": sourceManifest.Release, "actor_uid": *uid, "actor_gid": *gid, "sudo_requested": *sudo, "sudo_available": sudoAvailable, "sudo_diagnostic": sudoDiagnostic, "expected_cases": len(manifest), "unavailable_cases": unavailable, "failed_cases": failed, "cases": observations})
	f, err := os.Create(filepath.Join(*out, "capture.json.gz"))
	must(err)
	z := gzip.NewWriter(f)
	_, err = z.Write(read(filepath.Join(*out, "capture.json")))
	must(err)
	must(z.Close())
	must(f.Close())
	fmt.Printf("evidence=%s total=%d captured=%d unavailable=%d failed=%d\n", *out, len(manifest), len(manifest)-unavailable-failed, unavailable, failed)
	if failed > 0 || (*require && unavailable > 0) {
		os.Exit(1)
	}
}

//go:build ignore

// Capture guarded native compression-metadata queries on APFS/HFS+.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"runtime"
	"strings"
	"time"
)

type queryRecord struct {
	Result int    `json:"result"`
	Errno  int    `json:"errno"`
	Bytes  string `json:"bytes"`
	Guard  bool   `json:"guard"`
}
type queryObservation struct {
	InitialFlags                               uint32      `json:"initial_flags"`
	InitialSize                                int64       `json:"initial_size"`
	InitialHeld                                queryRecord `json:"initial_held_query"`
	PathQuery                                  queryRecord `json:"path_query"`
	HeldQuery                                  queryRecord `json:"held_query"`
	OpenErrno                                  int         `json:"open_errno"`
	Flags                                      uint32      `json:"flags"`
	Size                                       int64       `json:"size"`
	AttributeInstall, ForkInstall, FlagInstall struct {
		Result int `json:"result"`
		Errno  int `json:"errno"`
	}
}
type sample struct {
	Filesystem, Name              string
	Flags                         uint32
	Attribute, Fork               []byte
	MissingAttribute, MissingFork bool
	Observation                   json.RawMessage
}
type capture struct {
	Schema                       int
	Host, Compiler, SDK, Library string
	Sources                      map[string]string
	Cases                        []sample
}

func main() {
	out := flag.String("out", "artifacts/compression-query/native.json.gz", "fresh native observations")
	check := flag.Bool("check", false, "require exact retained query observations")
	flag.Parse()
	if err := run(*out, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(out string, check bool) (result error) {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("native capture requires macOS")
	}
	baseline := "testdata/appledouble/native/compression-query.json.gz"
	if check {
		a, e := filepath.Abs(out)
		if e != nil {
			return e
		}
		b, e := filepath.Abs(baseline)
		if e != nil {
			return e
		}
		if a == b || strings.HasSuffix(filepath.ToSlash(a), "/testdata/appledouble/native/compression-query-macos26.json.gz") {
			return fmt.Errorf("check must preserve fresh observations separately")
		}
	}
	dir, err := os.MkdirTemp("", "compression-query-")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(dir)) }()
	artifact := filepath.Dir(out)
	if err = os.MkdirAll(artifact, 0755); err != nil {
		return err
	}
	command := func(name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		var stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stderr = &stderr
		b, e := cmd.Output()
		if e != nil {
			return nil, fmt.Errorf("%s %v: %w\n%s", name, args, e, stderr.Bytes())
		}
		return b, nil
	}
	c := capture{Schema: 1, Sources: map[string]string{}}
	for _, v := range []struct {
		name   string
		args   []string
		target *string
	}{
		{"sw_vers", nil, &c.Host}, {"xcrun", []string{"clang", "--version"}, &c.Compiler}, {"xcrun", []string{"--show-sdk-version"}, &c.SDK},
	} {
		b, e := command(v.name, v.args...)
		if e != nil {
			return e
		}
		*v.target = string(b)
	}
	// macOS 26's kernel and framework do not recognize decmpfs LZ4.
	// Keep its complete native outcomes, including all rejection controls.
	if strings.Contains(c.Host, "BuildVersion:\t\t25G83") {
		baseline = "testdata/appledouble/native/compression-query-macos26.json.gz"
	}
	digest := func(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
	hashFile := func(path string) error {
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		c.Sources[path] = digest(b)
		return nil
	}
	const source = "testdata/appledouble/native/compression-query.c"
	for _, p := range []string{source, "testdata/appledouble/native/compression-policy.c", "scripts/capture-compression-query.go", "go.mod", "go.sum"} {
		if err = hashFile(p); err != nil {
			return err
		}
	}
	helper := filepath.Join(dir, "oracle")
	if _, err = command("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-framework", "CoreFoundation", "-lcompression", source, "-o", helper); err != nil {
		return err
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		ast, e := command("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		if e != nil {
			return e
		}
		if !json.Valid(ast) || !bytes.Contains(ast, []byte("CompoundStmt")) || !bytes.Contains(ast, []byte("query_record")) {
			return fmt.Errorf("incomplete %s AST", arch)
		}
		name := arch + ".ast.json"
		c.Sources[name] = digest(ast)
		if e = os.WriteFile(filepath.Join(artifact, name), ast, 0644); e != nil {
			return e
		}
	}
	const framework = "/System/Library/PrivateFrameworks/AppleFSCompression.framework/AppleFSCompression"
	library, err := command("xcrun", "dyld_info", "-uuid", framework)
	if err != nil {
		return err
	}
	c.Library = string(library)
	disassembly, err := command("xcrun", "dyld_info", "-disassemble", framework)
	if err != nil {
		return err
	}
	for _, symbol := range []string{"_queryCompressionInfo:", "_fqueryCompressionInfo:", "_CompressFile:", "_CreateStreamCompressorQueueWithOptions:"} {
		if !bytes.Contains(disassembly, []byte(symbol)) {
			return fmt.Errorf("missing %s", symbol)
		}
	}
	c.Sources["AppleFSCompression.disassembly.txt"] = digest(disassembly)
	if err = os.WriteFile(filepath.Join(artifact, "AppleFSCompression.disassembly.txt"), disassembly, 0644); err != nil {
		return err
	}
	sdk, err := command("xcrun", "--show-sdk-path")
	if err != nil {
		return err
	}
	for _, header := range []string{"sys/stat.h", "sys/xattr.h"} {
		if err = hashFile(filepath.Join(strings.TrimSpace(string(sdk)), "usr/include", header)); err != nil {
			return err
		}
	}
	var cases []sample
	for _, c := range []struct {
		name    string
		attr    []byte
		missing bool
	}{
		{"missing", nil, true}, {"empty", []byte{}, false}, {"short", []byte("fpmc"), false}, {"bad-magic", make([]byte, 16), false},
	} {
		cases = append(cases, sample{Name: c.name, Attribute: c.attr, MissingAttribute: c.missing, MissingFork: true})
	}
	for kind := uint32(0); kind <= 32; kind++ {
		h := make([]byte, 16)
		copy(h, "fpmc")
		binary.LittleEndian.PutUint32(h[4:], kind)
		binary.LittleEndian.PutUint64(h[8:], 65536)
		for _, shape := range []struct {
			name    string
			extra   []byte
			fork    []byte
			missing bool
		}{
			{"missing-fork", nil, nil, true}, {"empty-fork", nil, []byte{}, false}, {"fork", nil, []byte("fork"), false}, {"short-extension", []byte("abcdefg"), []byte("fork"), false}, {"extension", []byte("abcdefgh"), []byte("fork"), false},
		} {
			cases = append(cases, sample{Name: fmt.Sprintf("type-%d-%s", kind, shape.name), Attribute: append(append([]byte(nil), h...), shape.extra...), Fork: shape.fork, MissingFork: shape.missing})
		}
	}
	for _, filesystem := range []string{"APFS", "HFS+"} {
		err = func() (result error) {
			image := filepath.Join(dir, strings.ReplaceAll(filesystem, "+", "plus")+".dmg")
			mount := filepath.Join(dir, "mount")
			if e := os.Mkdir(mount, 0700); e != nil {
				return e
			}
			defer func() { result = errors.Join(result, os.Remove(mount)) }()
			if _, e := command("hdiutil", "create", "-size", "128m", "-fs", filesystem, "-volname", "CompressionQuery", image); e != nil {
				return e
			}
			if _, e := command("hdiutil", "attach", "-nobrowse", "-owners", "on", "-mountpoint", mount, image); e != nil {
				return e
			}
			defer func() { _, e := command("hdiutil", "detach", mount); result = errors.Join(result, e) }()
			for _, original := range cases {
				for _, flags := range []uint32{0, 32} {
					s := original
					s.Filesystem = filesystem
					s.Flags = flags
					attr, fork := hex.EncodeToString(s.Attribute), hex.EncodeToString(s.Fork)
					if s.MissingAttribute {
						attr = "none"
					}
					if s.MissingFork {
						fork = "none"
					}
					path, prefix := filepath.Join(mount, "input"), filepath.Join(dir, "result")
					observation, e := command(helper, path, attr, fork, fmt.Sprint(flags), prefix)
					if e != nil {
						return e
					}
					var record queryObservation
					if e = json.Unmarshal(observation, &record); e != nil {
						return e
					}
					if !record.InitialHeld.Guard || !record.PathQuery.Guard {
						return fmt.Errorf("query canary failed: %s", s.Name)
					}
					if record.InitialHeld.Result != record.PathQuery.Result || record.InitialHeld.Bytes != record.PathQuery.Bytes {
						return fmt.Errorf("held/path query mismatch: %s %s", s.Name, observation)
					}
					s.Observation = observation
					c.Cases = append(c.Cases, s)
					if e = os.Remove(path); e != nil {
						return e
					}
					for _, suffix := range []string{".attr", ".fork"} {
						if e = os.Remove(prefix + suffix); e != nil && !os.IsNotExist(e) {
							return e
						}
					}
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	if len(c.Cases) != 676 {
		return fmt.Errorf("incomplete native query inventory: %d", len(c.Cases))
	}

	var encoded bytes.Buffer
	z := gzip.NewWriter(&encoded)
	if err = json.NewEncoder(z).Encode(c); err != nil {
		return err
	}
	if err = z.Close(); err != nil {
		return err
	}
	if err = os.WriteFile(out, encoded.Bytes(), 0644); err != nil {
		return err
	}
	if check {
		f, e := os.Open(baseline)
		if e != nil {
			return e
		}
		defer f.Close()
		reader, e := gzip.NewReader(f)
		if e != nil {
			return e
		}
		defer reader.Close()
		var expected capture
		if e = json.NewDecoder(reader).Decode(&expected); e != nil {
			return e
		}
		// Marshal both inventories to compare every raw observation field while
		// ignoring JSON indentation introduced by the retained envelope.
		oldCases, e := json.Marshal(expected.Cases)
		if e != nil {
			return e
		}
		newCases, e := json.Marshal(c.Cases)
		if e != nil {
			return e
		}
		if expected.Schema != c.Schema || !bytes.Equal(oldCases, newCases) {
			return fmt.Errorf("native compression query differs; fresh observations retained at %s", out)
		}
	}
	fmt.Printf("Native compression query: %d cases across APFS/HFS+, guarded held/path metadata queries\n", len(c.Cases))
	return nil
}

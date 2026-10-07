//go:build ignore

// Capture native compression selection, eligibility and query records on APFS/HFS+.
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
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

type queryRecord struct {
	Result int    `json:"result"`
	Errno  int    `json:"errno"`
	Bytes  string `json:"bytes"`
	Guard  bool   `json:"guard"`
}
type observation struct {
	PathQuery  queryRecord `json:"path_query"`
	HeldQuery  queryRecord `json:"held_query"`
	Accepted   bool        `json:"accepted"`
	QueueErrno int         `json:"queue_errno"`
	OpenErrno  int         `json:"open_errno"`
	Flags      uint32      `json:"flags"`
	Size       int64       `json:"size"`
	Blocks     int64       `json:"blocks"`
	Links      uint32      `json:"links"`
	Mode       uint32      `json:"mode"`
}
type sample struct {
	Filesystem, Requested, Inline, Pattern string
	Family                                 string
	RandomTail, MeasuredPayload            int
	Size                                   int
	Before, After                          observation
	Attribute, Fork                        []byte
	LogicalSHA256                          string
}
type capture struct {
	Schema                       int
	Host, Compiler, SDK, Library string
	Sources                      map[string]string
	Cases                        []sample
}

func main() {
	out := flag.String("out", "artifacts/compression-policy/native.json.gz", "fresh native observations")
	check := flag.Bool("check", false, "require exact retained policy observations")
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
	const baseline = "testdata/appledouble/native/compression-policy.json.gz"
	if check {
		a, e := filepath.Abs(out)
		if e != nil {
			return e
		}
		b, e := filepath.Abs(baseline)
		if e != nil {
			return e
		}
		if a == b {
			return fmt.Errorf("check must preserve fresh observations separately")
		}
	}
	dir, err := os.MkdirTemp("", "compression-policy-")
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
		cmd := cirunner.CommandContext(ctx, name, args...)
		cmd.Stderr = &stderr
		b, e := cmd.Output()
		if e != nil {
			return nil, fmt.Errorf("%s %v: %w\n%s", name, args, e, stderr.Bytes())
		}
		return b, nil
	}
	c := capture{Schema: 1, Sources: map[string]string{}}
	if err := captureprovenance.Bind(os.DirFS("."), artifact, c.Sources); err != nil {
		return err
	}
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
	digest := func(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
	hashFile := func(path string) error {
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		c.Sources[path] = digest(b)
		return nil
	}
	const source = "testdata/appledouble/native/compression-policy.c"
	for _, p := range []string{source, "scripts/capture-compression-policy.go", "go.mod", "go.sum"} {
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
	sizes := []int{0, 1, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 3072, 3786, 3802, 4095, 4096, 4097, 8191, 8192, 8193, 16383, 16384, 16385, 32767, 32768, 32769, 65535, 65536, 65537, 131072}
	for _, filesystem := range []string{"APFS", "HFS+"} {
		err = func() (result error) {
			image := filepath.Join(dir, strings.ReplaceAll(filesystem, "+", "plus")+".dmg")
			mount := filepath.Join(dir, "mount")
			if e := os.Mkdir(mount, 0700); e != nil {
				return e
			}
			defer func() { result = errors.Join(result, os.Remove(mount)) }()
			if _, e := command("hdiutil", "create", "-size", "128m", "-fs", filesystem, "-volname", "CompressionPolicy", image); e != nil {
				return e
			}
			if _, e := command("hdiutil", "attach", "-nobrowse", "-owners", "on", "-mountpoint", mount, image); e != nil {
				return e
			}
			defer func() { _, e := command("hdiutil", "detach", mount); result = errors.Join(result, e) }()
			observe := func(s sample, plain []byte) error {
				path, prefix := filepath.Join(mount, "input"), filepath.Join(dir, "result")
				if e := os.WriteFile(path, plain, 0644); e != nil {
					return e
				}
				b, e := command(helper, "inspect", path, prefix)
				if e != nil {
					return e
				}
				if e = json.Unmarshal(b, &s.Before); e != nil {
					return e
				}
				b, e = command(helper, "compress", path, prefix, s.Requested, s.Inline)
				if e != nil {
					return e
				}
				if e = json.Unmarshal(b, &s.After); e != nil {
					return e
				}
				for _, pair := range []struct {
					suffix string
					target *[]byte
				}{{".attr", &s.Attribute}, {".fork", &s.Fork}} {
					data, e := os.ReadFile(prefix + pair.suffix)
					if e != nil && !os.IsNotExist(e) {
						return e
					}
					*pair.target = data
					if e = os.Remove(prefix + pair.suffix); e != nil && !os.IsNotExist(e) {
						return e
					}
				}
				file, e := os.Open(path)
				if e != nil {
					return e
				}
				h := sha256.New()
				n, e := io.Copy(h, file)
				e = errors.Join(e, file.Close())
				if e != nil {
					return e
				}
				if n != int64(s.Size) || hex.EncodeToString(h.Sum(nil)) != s.LogicalSHA256 {
					return fmt.Errorf("kernel readback differs: %+v", s)
				}
				if !s.Before.PathQuery.Guard || !s.Before.HeldQuery.Guard || !s.After.PathQuery.Guard || !s.After.HeldQuery.Guard {
					return fmt.Errorf("query guard failed")
				}
				if s.Before.PathQuery != s.Before.HeldQuery || s.After.PathQuery != s.After.HeldQuery {
					return fmt.Errorf("held/path query mismatch: %+v", s)
				}
				if e = os.Remove(path); e != nil {
					return e
				}
				c.Cases = append(c.Cases, s)
				return nil
			}
			for _, requested := range []string{"default", "3", "7", "9", "11", "13"} {
				for _, inline := range []string{"default", "yes", "no"} {
					for _, pattern := range []string{"text", "random", "half-random", "mostly-random"} {
						for _, size := range sizes {
							plain := make([]byte, size)
							var random uint32 = 0x12345678
							for i := range plain {
								random ^= random << 13
								random ^= random >> 17
								random ^= random << 5
								plain[i] = "ABCD"[i%4]
								if pattern == "random" || pattern == "half-random" && i >= size/2 || pattern == "mostly-random" && i >= size/10 {
									plain[i] = byte(random)
								}
							}
							s := sample{Filesystem: filesystem, Requested: requested, Inline: inline, Pattern: pattern, Family: "grid", Size: size, LogicalSHA256: digest(plain)}
							if e := observe(s, plain); e != nil {
								return e
							}
						}
					}
				}
			}
			// Native codec measurements choose inputs; native whole-file operations
			// remain the oracle for every decision and every resulting byte.
			for _, requested := range []string{"3", "7", "11", "13"} {
				for _, boundary := range []struct {
					name        string
					size, limit int
				}{
					{"inline", 65536, 3786},
					{"ratio-one-block", 65536, 49152},
					{"ratio-two-blocks", 131072, 102400},
				} {
					limit := boundary.limit
					if boundary.name != "inline" {
						blocks := (boundary.size + 65535) / 65536
						if requested == "3" {
							limit -= 314 + 8*blocks
						} else {
							limit -= 4 + 4*blocks
						}
					}
					measure := func(tail int) ([]byte, int, error) {
						plain := randomTail(boundary.size, tail)
						path := filepath.Join(dir, "measure")
						if e := os.WriteFile(path, plain, 0600); e != nil {
							return nil, 0, e
						}
						b, e := command(helper, "measure", path, requested)
						if e != nil {
							return nil, 0, e
						}
						n, e := strconv.Atoi(strings.TrimSpace(string(b)))
						return plain, n, e
					}
					low, high := 0, boundary.size
					for low < high {
						middle := low + (high-low)/2
						_, n, e := measure(middle)
						if e != nil {
							return e
						}
						if n <= limit {
							low = middle + 1
						} else {
							high = middle
						}
					}
					below, above := false, false
					for tail := low - 6; tail <= low+6; tail++ {
						if tail < 0 || tail > boundary.size {
							return fmt.Errorf("unbracketed %s boundary", boundary.name)
						}
						plain, n, e := measure(tail)
						if e != nil {
							return e
						}
						below = below || n <= limit
						above = above || n > limit
						s := sample{Filesystem: filesystem, Requested: requested, Inline: "default", Pattern: "random-tail", Family: boundary.name, Size: boundary.size, RandomTail: tail, MeasuredPayload: n, LogicalSHA256: digest(plain)}
						if e := observe(s, plain); e != nil {
							return e
						}
					}
					if !below || !above {
						return fmt.Errorf("missing native transition bracket for %s/%s", requested, boundary.name)
					}
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	if len(c.Cases) != 2*(6*3*4*30+4*3*13) {
		return fmt.Errorf("incomplete native policy inventory: %d", len(c.Cases))
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
		if err := captureprovenance.Verify(os.DirFS("."), expected.Sources); err != nil {
			return err
		}
		if expected.Schema != c.Schema || !reflect.DeepEqual(expected.Cases, c.Cases) {
			return fmt.Errorf("native compression policy differs; fresh observations retained at %s", out)
		}
	}
	fmt.Printf("Native compression policy: %d cases across APFS/HFS+, full kernel readback and guarded held/path queries\n", len(c.Cases))
	return nil
}

func randomTail(size, tail int) []byte {
	plain := make([]byte, size)
	var random uint32 = 0x12345678
	for i := range plain {
		random ^= random << 13
		random ^= random >> 17
		random ^= random << 5
		plain[i] = "ABCD"[i%4]
		if i >= size-tail {
			plain[i] = byte(random)
		}
	}
	return plain
}

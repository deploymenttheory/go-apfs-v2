//go:build ignore

// Capture Apple LZ4 frames and kernel-accepted decmpfs types 15/16 independently
// of Go codecs. These layouts are constructed, not native producer choices.
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
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
)

type bufferCase struct {
	Name           string
	Plain, Encoded []byte
}

// Decoded bytes are an independently verified prefix of the referenced Plain
// bytes, retaining exact content without duplicate megabyte values.
type decodeCase struct {
	Buffer, Variant, DecodedSHA256 string
	Capacity, Count                int
}
type kernelCase struct {
	Name, Filesystem, Origin string
	Type                     uint32
	Plain, Attribute, Fork   []byte
	Exit                     int
	Stdout, Stderr           string
}
type capture struct {
	Schema                       int
	Host, Compiler, SDK, Library string
	Sources                      map[string]string
	Buffers                      []bufferCase
	Decoders                     []decodeCase
	Kernel                       []kernelCase
}

func main() {
	out := flag.String("out", "artifacts/compression-lz4/native.json.gz", "fresh evidence")
	check := flag.Bool("check", false, "compare retained observations")
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
	baseline := "testdata/appledouble/native/compression-lz4.json.gz"
	a, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	b, err := filepath.Abs(baseline)
	if err != nil {
		return err
	}
	if check && (a == b || strings.HasSuffix(filepath.ToSlash(a), "/testdata/appledouble/native/compression-lz4-macos26.json.gz")) {
		return fmt.Errorf("fresh evidence must not replace the baseline")
	}
	dir, err := os.MkdirTemp("", "compression-lz4-")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(dir)) }()
	artifact := filepath.Dir(out)
	if err = os.MkdirAll(artifact, 0755); err != nil {
		return err
	}
	command := func(name string, args ...string) ([]byte, []byte, int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		var stdout, stderr bytes.Buffer
		cmd := cirunner.CommandContext(ctx, name, args...)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if ctx.Err() != nil {
			return stdout.Bytes(), stderr.Bytes(), -1, ctx.Err()
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return stdout.Bytes(), stderr.Bytes(), exit.ExitCode(), nil
		}
		return stdout.Bytes(), stderr.Bytes(), 0, err
	}
	mustCommand := func(name string, args ...string) ([]byte, error) {
		b, e, code, err := command(name, args...)
		if err != nil || code != 0 {
			return nil, errors.Join(err, fmt.Errorf("%s %v: exit=%d stderr=%s", name, args, code, e))
		}
		return b, nil
	}
	digest := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	c := capture{Schema: 1, Sources: map[string]string{}}
	if err := captureprovenance.Bind(os.DirFS("."), artifact, c.Sources); err != nil {
		return err
	}
	for _, x := range []struct {
		name   string
		args   []string
		target *string
	}{
		{"sw_vers", nil, &c.Host}, {"xcrun", []string{"clang", "--version"}, &c.Compiler}, {"xcrun", []string{"--show-sdk-version"}, &c.SDK},
		{"xcrun", []string{"dyld_info", "-uuid", "/usr/lib/libcompression.dylib"}, &c.Library},
	} {
		b, e := mustCommand(x.name, x.args...)
		if e != nil {
			return e
		}
		*x.target = string(b)
	}
	// macOS 26's kernel and framework do not recognize decmpfs LZ4.
	// Keep its complete native outcomes, including all rejection controls.
	if strings.Contains(c.Host, "BuildVersion:\t\t25G83") {
		baseline = "testdata/appledouble/native/compression-lz4-macos26.json.gz"
	}
	for _, path := range []string{"scripts/capture-compression-lz4.go", "testdata/appledouble/native/compression-lz4.c", "testdata/appledouble/native/decmpfs-formats.c", "go.mod", "go.sum"} {
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		c.Sources[path] = digest(b)
	}
	codec, install := filepath.Join(dir, "codec"), filepath.Join(dir, "install")
	for _, x := range []struct {
		source, target string
		libs           []string
	}{
		{"testdata/appledouble/native/compression-lz4.c", codec, []string{"-lcompression"}},
		{"testdata/appledouble/native/decmpfs-formats.c", install, []string{"-framework", "CoreFoundation"}},
	} {
		args := append([]string{"clang", "-Wall", "-Wextra", "-Werror", x.source, "-o", x.target}, x.libs...)
		if _, e := mustCommand("xcrun", args...); e != nil {
			return e
		}
		for _, arch := range []string{"arm64", "x86_64"} {
			ast, e := mustCommand("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", x.source)
			if e != nil {
				return e
			}
			if !json.Valid(ast) || !bytes.Contains(ast, []byte("CompoundStmt")) {
				return fmt.Errorf("incomplete AST")
			}
			name := filepath.Base(x.source) + "-" + arch + ".ast.json"
			c.Sources[name] = digest(ast)
			if e = os.WriteFile(filepath.Join(artifact, name), ast, 0644); e != nil {
				return e
			}
		}
	}
	encode := func(plain []byte) ([]byte, error) {
		input, output := filepath.Join(dir, "input"), filepath.Join(dir, "encoded")
		if e := os.WriteFile(input, plain, 0600); e != nil {
			return nil, e
		}
		if _, e := mustCommand(codec, "256", input, output); e != nil {
			return nil, e
		}
		encoded, e := os.ReadFile(output)
		if e != nil {
			return nil, e
		}
		if _, e = mustCommand(codec, "decode:256", output, filepath.Join(dir, "decoded")); e != nil {
			return nil, e
		}
		decoded, e := os.ReadFile(filepath.Join(dir, "decoded"))
		if e != nil {
			return nil, e
		}
		if !bytes.Equal(decoded, plain) {
			return nil, fmt.Errorf("native buffer readback differs")
		}
		return encoded, nil
	}
	for _, size := range []int{1, 2, 4, 7, 8, 12, 15, 16, 17, 31, 32, 63, 64, 127, 128, 255, 256, 4095, 4096, 4097, 65535, 65536, 65537, 131072, 262143, 262144, 262145, 1048576} {
		for _, pattern := range []string{"text", "random", "half-random", "history", "zeros"} {
			plain := input(size, pattern)
			encoded, e := encode(plain)
			if e != nil {
				return e
			}
			c.Buffers = append(c.Buffers, bufferCase{fmt.Sprintf("%s-%d", pattern, size), plain, encoded})
		}
	}
	for _, sample := range c.Buffers {
		variants := []string{"full"}
		if len(sample.Plain) == 16 || len(sample.Plain) == 65536 {
			variants = append(variants, "no-end", "wrong-end", "truncated-body", "trailing")
		}
		for _, variant := range variants {
			encoded := mutate(sample.Encoded, variant)
			input, output := filepath.Join(dir, "decode-input"), filepath.Join(dir, "decode-output")
			if err = os.WriteFile(input, encoded, 0600); err != nil {
				return err
			}
			for _, capacity := range []int{0, 1, len(sample.Plain) - 1, len(sample.Plain), len(sample.Plain) + 1} {
				if _, err = mustCommand(codec, "decode:256", input, output, strconv.Itoa(capacity)); err != nil {
					return err
				}
				decoded, e := os.ReadFile(output)
				if e != nil {
					return e
				}
				if len(decoded) > len(sample.Plain) || !bytes.Equal(decoded, sample.Plain[:len(decoded)]) {
					return fmt.Errorf("native decoder returned non-prefix output")
				}
				c.Decoders = append(c.Decoders, decodeCase{sample.Name, variant, digest(decoded), capacity, len(decoded)})
			}
		}
	}
	for _, filesystem := range []string{"APFS", "HFS+"} {
		err = func() (result error) {
			mount := filepath.Join(dir, "mount")
			if e := os.Mkdir(mount, 0700); e != nil {
				return e
			}
			defer func() { result = errors.Join(result, os.Remove(mount)) }()
			image := filepath.Join(dir, strings.ReplaceAll(filesystem, "+", "plus")+".dmg")
			if _, e := mustCommand("hdiutil", "create", "-size", "128m", "-fs", filesystem, "-volname", "CompressionLZ4", image); e != nil {
				return e
			}
			attached, e := mustCommand("hdiutil", "attach", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", mount, image)
			if e != nil {
				return e
			}
			device, e := diskimage.AttachmentDevice(attached)
			if e != nil {
				return e
			}
			defer func() {
				var attempts []map[string]any
				e := diskimage.RetryDetach(context.Background(), func() (int, error) {
					stdout, stderr, code, e := command("hdiutil", "detach", device)
					attempts = append(attempts, map[string]any{"device": device, "stdout": string(stdout), "stderr": string(stderr), "exit": code, "error": fmt.Sprint(e)})
					if code != 0 {
						e = errors.Join(e, fmt.Errorf("hdiutil detach %s: exit %d: %s", device, code, stderr))
					}
					return code, e
				})
				data, saveErr := json.MarshalIndent(attempts, "", "  ")
				if saveErr == nil {
					saveErr = os.WriteFile(filepath.Join(artifact, "detach-"+strings.ReplaceAll(filesystem, "+", "plus")+".json"), data, 0600)
				}
				result = errors.Join(result, e, saveErr)
			}()
			observe := func(k kernelCase) error {
				k.Filesystem = filesystem
				k.Origin = "constructed storage from native codec or explicit stored marker; kernel readback"
				attr, fork := filepath.Join(dir, "attr"), "-"
				if e := os.WriteFile(attr, k.Attribute, 0600); e != nil {
					return e
				}
				if k.Fork != nil {
					fork = filepath.Join(dir, "fork")
					if e := os.WriteFile(fork, k.Fork, 0600); e != nil {
						return e
					}
				}
				path, prefix := filepath.Join(mount, "target"), filepath.Join(dir, "result")
				o, e, code, err := command(install, "install", path, attr, fork, prefix)
				if err != nil {
					return err
				}
				k.Exit = code
				k.Stdout = string(o)
				k.Stderr = string(e)
				if code == 0 {
					readback, err := os.ReadFile(prefix + ".readback")
					if err != nil {
						return err
					}
					if !bytes.Equal(readback, k.Plain) {
						return fmt.Errorf("kernel readback differs: %s/%s", filesystem, k.Name)
					}
					got, err := os.ReadFile(prefix + ".attr")
					if err != nil {
						return err
					}
					if !bytes.Equal(got, k.Attribute) {
						return fmt.Errorf("kernel attribute changed")
					}
					var st struct {
						Flags uint32 `json:"flags"`
						Size  int64  `json:"size"`
					}
					if err = json.Unmarshal(o, &st); err != nil {
						return err
					}
					if st.Flags&32 == 0 || st.Size != int64(len(k.Plain)) {
						return fmt.Errorf("kernel flags/size differ")
					}
				}
				if err = os.Remove(path); err != nil {
					return err
				}
				c.Kernel = append(c.Kernel, k)
				return nil
			}
			for _, size := range []int{1, 16, 16384, 16385, 65535, 65536, 65537, 131072} {
				for _, pattern := range []string{"text", "random", "half-random", "history", "zeros"} {
					plain := input(size, pattern)
					var blocks [][]byte
					for at := 0; at < size; at += 65536 {
						part := plain[at:min(at+65536, size)]
						block, e := encode(part)
						if e != nil {
							return e
						}
						blocks = append(blocks, block)
					}
					if size <= 65536 && len(blocks[0]) <= 3786 {
						k := kernelCase{Name: fmt.Sprintf("inline-%s-%d", pattern, size), Type: 15, Plain: plain, Attribute: append(header(15, size), blocks[0]...)}
						if e := observe(k); e != nil {
							return e
						}
					}
					fork := make([]byte, 4*(len(blocks)+1))
					at := len(fork)
					for i, block := range blocks {
						binary.LittleEndian.PutUint32(fork[4*i:], uint32(at))
						fork = append(fork, block...)
						at += len(block)
					}
					binary.LittleEndian.PutUint32(fork[4*len(blocks):], uint32(at))
					if e := observe(kernelCase{Name: fmt.Sprintf("fork-%s-%d", pattern, size), Type: 16, Plain: plain, Attribute: header(16, size), Fork: fork}); e != nil {
						return e
					}
				}
			}
			for marker := 0; marker < 256; marker++ {
				plain := []byte("abcdefgh")
				block := append([]byte{byte(marker)}, plain...)
				for _, kind := range []uint32{15, 16} {
					k := kernelCase{Name: fmt.Sprintf("marker-%d-%s", kind, strconv.Itoa(marker)), Type: kind, Plain: plain, Attribute: header(kind, len(plain))}
					if kind == 15 {
						k.Attribute = append(k.Attribute, block...)
					} else {
						k.Fork = make([]byte, 8)
						binary.LittleEndian.PutUint32(k.Fork, 8)
						binary.LittleEndian.PutUint32(k.Fork[4:], uint32(8+len(block)))
						k.Fork = append(k.Fork, block...)
					}
					if e := observe(k); e != nil {
						return e
					}
				}
			}
			for _, size := range []int{16, 65536} {
				plain := input(size, "text")
				encoded, e := encode(plain)
				if e != nil {
					return e
				}
				for _, variant := range []string{"no-end", "wrong-end", "truncated-body", "trailing"} {
					block := mutate(encoded, variant)
					for _, kind := range []uint32{15, 16} {
						k := kernelCase{Name: fmt.Sprintf("terminator-%d-%d-%s", kind, size, variant), Type: kind, Plain: plain, Attribute: header(kind, size)}
						if kind == 15 {
							k.Attribute = append(k.Attribute, block...)
						} else {
							k.Fork = make([]byte, 8)
							binary.LittleEndian.PutUint32(k.Fork, 8)
							binary.LittleEndian.PutUint32(k.Fork[4:], uint32(8+len(block)))
							k.Fork = append(k.Fork, block...)
						}
						if e := observe(k); e != nil {
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
	if len(c.Buffers) != 140 || len(c.Kernel) != 1172 || len(c.Decoders) != 900 {
		return fmt.Errorf("incomplete LZ4 inventory: %d/%d", len(c.Buffers), len(c.Kernel))
	}
	var output bytes.Buffer
	z := gzip.NewWriter(&output)
	if err = json.NewEncoder(z).Encode(c); err != nil {
		return err
	}
	if err = z.Close(); err != nil {
		return err
	}
	if err = os.WriteFile(out, output.Bytes(), 0644); err != nil {
		return err
	}
	if check {
		f, e := os.Open(baseline)
		if e != nil {
			return e
		}
		defer f.Close()
		z, e := gzip.NewReader(f)
		if e != nil {
			return e
		}
		defer z.Close()
		var old capture
		if e = json.NewDecoder(z).Decode(&old); e != nil {
			return e
		}
		if err := captureprovenance.VerifyReference(os.DirFS("."), old.Sources); err != nil {
			return err
		}
		if old.Schema != c.Schema || !reflect.DeepEqual(old.Buffers, c.Buffers) || !reflect.DeepEqual(old.Kernel, c.Kernel) || !reflect.DeepEqual(old.Decoders, c.Decoders) {
			return fmt.Errorf("native LZ4 observations differ; fresh evidence: %s", out)
		}
	}
	fmt.Printf("Native LZ4: %d buffers and %d kernel storage/marker cases across APFS/HFS+\n", len(c.Buffers), len(c.Kernel))
	return nil
}
func mutate(encoded []byte, variant string) []byte {
	switch variant {
	case "no-end":
		return encoded[:len(encoded)-4]
	case "wrong-end":
		return append(append([]byte(nil), encoded[:len(encoded)-4]...), []byte("oops")...)
	case "truncated-body":
		return encoded[:len(encoded)-5]
	case "trailing":
		return append(append([]byte(nil), encoded...), []byte("ignored trailing data")...)
	default:
		return encoded
	}
}
func input(size int, pattern string) []byte {
	b := make([]byte, size)
	var x uint32 = 0x12345678
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = "abcd"[i%4]
		switch pattern {
		case "random":
			b[i] = byte(x)
		case "half-random":
			if i >= size/2 {
				b[i] = byte(x)
			}
		case "history":
			if i < 65536 {
				b[i] = byte(x)
			} else {
				b[i] = b[i%65536]
			}
		case "zeros":
			b[i] = 0
		}
	}
	return b
}
func header(kind uint32, size int) []byte {
	b := make([]byte, 16)
	copy(b, "fpmc")
	binary.LittleEndian.PutUint32(b[4:], kind)
	binary.LittleEndian.PutUint64(b[8:], uint64(size))
	return b
}

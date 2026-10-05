//go:build ignore

// Retain independent native codec outputs, including short-tail decisions.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(path string) []byte { b, e := os.ReadFile(path); must(e); return b }
func hash(b []byte) string    { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func run(name string, args ...string) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	b, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		panic(fmt.Sprintf("%s: %v: %s", name, e, b))
	}
	return b
}

type capture struct {
	Host, Compiler, SDK, Library string
	Sources                      map[string]string
	Cases                        []sample
	Bounded                      []boundedSample
	LegacyV1, LegacyV1Plain      []byte
}

type boundedSample struct {
	Input, Capacity int
	Encoded         []byte
}

type sample struct {
	Name           string
	Algorithm      uint32
	Plain, Encoded []byte
}

func main() {
	out := flag.String("out", "artifacts/compression-blocks/native.json.gz", "capture output")
	check := flag.Bool("check", false, "recapture and compare every retained native observation")
	flag.Parse()
	if *check {
		a, e := filepath.Abs(*out)
		must(e)
		b, e := filepath.Abs("testdata/appledouble/native/compression-blocks.json.gz")
		must(e)
		if a == b {
			panic("check cannot overwrite retained evidence")
		}
	}
	if runtime.GOOS != "darwin" {
		panic("native capture requires macOS")
	}
	dir, e := os.MkdirTemp("", "compression-blocks-")
	must(e)
	defer os.RemoveAll(dir)
	must(os.MkdirAll(filepath.Dir(*out), 0755))
	source := "testdata/appledouble/native/compression-blocks.c"
	helper := filepath.Join(dir, "producer")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-lcompression", source, "-o", helper)
	c := capture{Host: string(run("sw_vers")), Compiler: string(run("xcrun", "clang", "--version")), SDK: string(run("xcrun", "--show-sdk-version")), Library: string(run("xcrun", "dyld_info", "-uuid", "/usr/lib/libcompression.dylib")), Sources: map[string]string{}}
	sdk := strings.TrimSpace(string(run("xcrun", "--show-sdk-path")))
	c.Sources["SDK/compression.h"] = hash(read(filepath.Join(sdk, "usr/include/compression.h")))
	// Compression's LZBITMAP matcher is not in the published Apple C sources.
	// Retain complete host implementation evidence alongside the public API AST.
	disassembly := run("xcrun", "dyld_info", "-disassemble", "/usr/lib/libcompression.dylib")
	for _, symbol := range []string{"_lzbitmap_process_block:", "_lzbitmap_encode:", "_compression_encode_buffer:"} {
		if !bytes.Contains(disassembly, []byte(symbol)) {
			panic("missing host implementation symbol " + symbol)
		}
	}
	must(os.WriteFile(filepath.Join(filepath.Dir(*out), "libcompression.disassembly.txt"), disassembly, 0644))
	c.Sources["libcompression.disassembly.txt"] = hash(disassembly)
	constants := run("xcrun", "dyld_info", "-section_bytes", "__TEXT", "__const", "/usr/lib/libcompression.dylib")
	must(os.WriteFile(filepath.Join(filepath.Dir(*out), "libcompression.constants.txt"), constants, 0644))
	c.Sources["libcompression.constants.txt"] = hash(constants)

	for _, p := range []string{source, "scripts/capture-compression-blocks.go"} {
		c.Sources[p] = hash(read(p))
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		ast := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		for _, name := range []string{"main", "compression_encode_buffer", "compression_decode_buffer"} {
			if !bytes.Contains(ast, []byte(`"name": "`+name+`"`)) {
				panic("missing AST declaration " + name)
			}
		}
		p := arch + ".ast.json"

		c.Sources[p] = hash(ast)
		must(os.WriteFile(filepath.Join(filepath.Dir(*out), p), ast, 0644))
	}
	for _, n := range []int{0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 77, 123, 127, 128, 129, 143, 144, 145, 146, 255, 256, 257, 511, 512, 513, 1023, 1024, 4095, 4096, 32767, 32768, 32769, 65535, 65536} {
		for _, period := range []int{1, 8, 27, 251, 257, 4093, 0, -1, -2} {
			plain := make([]byte, n)
			var rng uint32 = 0x12345678
			for i := range plain {
				if period <= 0 {
					rng ^= rng << 13
					rng ^= rng >> 17
					rng ^= rng << 5
					plain[i] = byte(rng)
					if period == -1 && i%8 != 0 || period == -2 && i%2 != 0 {
						plain[i] = 11
					}
				} else {
					plain[i] = byte((i%period)*37 + 11)
				}
			}
			input := filepath.Join(dir, "input")
			output := filepath.Join(dir, "output")
			must(os.WriteFile(input, plain, 0600))
			for _, alg := range []uint32{0x205, 0x801, 0x702, 0x900, 0x901} {
				run(helper, fmt.Sprint(alg), input, output)
				c.Cases = append(c.Cases, sample{Name: fmt.Sprintf("n%d-period%d", n, period), Algorithm: alg, Plain: plain, Encoded: read(output)})
			}
		}
		fmt.Printf("captured %d-byte cases\n", n)
	}

	r := rand.New(rand.NewPCG(1, 2))
	random := make([]byte, 3*32768+7)
	for i := range random {
		random[i] = byte(r.Uint32())
	}
	for _, v := range []struct {
		name  string
		plain []byte
	}{
		{"random", random},
		{"random-to-repeated", append(bytes.Clone(random[:32768]), bytes.Repeat([]byte("abcdefgh12345678"), 4096)...)},
		{"repeated-to-random", append(bytes.Repeat([]byte("abcdefg"), 5000), random[:32768]...)},
		{"history", append(bytes.Clone(random[:65535]), random[1024:32768]...)},
		{"tail", bytes.Repeat([]byte("abcd"), 8193)},
	} {
		input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
		must(os.WriteFile(input, v.plain, 0600))
		run(helper, "1794", input, output)
		c.Cases = append(c.Cases, sample{Name: "scalar-" + v.name, Algorithm: 0x702, Plain: v.plain, Encoded: read(output)})
	}
	// Cross-chunk dictionary changes, 16-bit position wrap and noisy matches.
	// Recipes are generated independently of every encoder implementation.
	for seed := uint64(1); seed <= 12; seed++ {
		for _, n := range []int{145, 4096, 32769, 65535, 65536, 65537, 131073, 1048576} {
			rng := rand.New(rand.NewPCG(seed, seed*17+3))
			dictionary := make([]byte, 65535)
			for i := range dictionary {
				dictionary[i] = byte(rng.Uint32())
			}
			plain := make([]byte, n)
			for i := range plain {
				period := []int{8, 257, 4093, 32767, 65535}[i/32768%5]
				plain[i] = dictionary[i%period]
				if rng.Uint32()%uint32(2+seed*7) == 0 {
					plain[i] = byte(rng.Uint32())
				}
			}
			input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
			must(os.WriteFile(input, plain, 0600))
			algorithms := []uint32{0x702}
			if n <= 65536 {
				algorithms = append(algorithms, 0x205, 0x801, 0x900, 0x901)
			}
			for _, algorithm := range algorithms {
				run(helper, fmt.Sprint(algorithm), input, output)
				c.Cases = append(c.Cases, sample{Name: fmt.Sprintf("dictionary-seed%d-n%d", seed, n), Algorithm: algorithm, Plain: plain, Encoded: read(output)})
			}

		}
	}
	for index, s := range c.Cases {
		if s.Algorithm == 0x901 {
			continue
		}
		selected := len(s.Plain) <= 513 && (strings.HasSuffix(s.Name, "period1") || strings.HasSuffix(s.Name, "period27") || strings.HasSuffix(s.Name, "period-2"))
		selected = selected || strings.HasPrefix(s.Name, "scalar-") || strings.HasPrefix(s.Name, "dictionary-seed1-") || strings.HasPrefix(s.Name, "dictionary-seed12-")
		if !selected {
			continue
		}
		input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
		must(os.WriteFile(input, s.Plain, 0600))
		seen := map[int]bool{}
		for _, capacity := range []int{0, 1, 34, 35, len(s.Plain) / 2, len(s.Plain) - 2, len(s.Plain) - 1, len(s.Plain), len(s.Plain) + 1, len(s.Plain) + 31, len(s.Plain) + 64, len(s.Encoded) - 1, len(s.Encoded), len(s.Encoded) + 31, len(s.Encoded) + 32} {
			if capacity < 0 || seen[capacity] {
				continue
			}
			seen[capacity] = true
			run(helper, fmt.Sprint(s.Algorithm), input, output, fmt.Sprint(capacity))
			c.Bounded = append(c.Bounded, boundedSample{Input: index, Capacity: capacity, Encoded: read(output)})
		}
	}
	// Constructed compatibility control, not native encoder output: an empty
	// legacy V1 block followed by a raw block. Nonempty decoded output makes a
	// native rejection distinguishable from success.
	legacy := make([]byte, 772+16)
	copy(legacy, "bvx1")
	le := binary.LittleEndian
	le.PutUint32(legacy[8:], 16)
	le.PutUint32(legacy[20:], 8)
	le.PutUint32(legacy[24:], 8)
	le.PutUint32(legacy[28:], 0xfffffff9)
	le.PutUint32(legacy[40:], 0xfffffff9)
	le.PutUint16(legacy[50:], 64)
	le.PutUint16(legacy[90:], 64)
	le.PutUint16(legacy[130:], 256)
	le.PutUint16(legacy[258:], 1024)
	legacy = append(legacy, []byte("bvx-\x02\x00\x00\x00ab")...)
	legacy = append(legacy, []byte("bvx$")...)
	input, output := filepath.Join(dir, "legacy-v1"), filepath.Join(dir, "legacy-v1-decoded")
	must(os.WriteFile(input, legacy, 0600))
	run(helper, "decode:2049", input, output)
	c.LegacyV1, c.LegacyV1Plain = legacy, read(output)
	if !bytes.Equal(c.LegacyV1Plain, []byte("ab")) {
		panic("native legacy V1 control rejected")
	}
	b, e := json.Marshal(c)
	must(e)
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	_, e = z.Write(b)
	must(e)
	must(z.Close())
	must(os.WriteFile(*out, compressed.Bytes(), 0644))
	fmt.Printf("retained %d independent native codec cases\n", len(c.Cases))
	if len(c.Cases) != 1871 || len(c.Bounded) != 5050 {
		panic("native case inventory changed")
	}
	if *check {
		f, e := os.Open("testdata/appledouble/native/compression-blocks.json.gz")
		must(e)
		defer f.Close()
		z, e := gzip.NewReader(f)
		must(e)
		defer z.Close()
		var old capture
		must(json.NewDecoder(z).Decode(&old))
		for _, path := range []string{source, "scripts/capture-compression-blocks.go"} {
			if old.Sources[path] != c.Sources[path] {
				panic("stale retained source provenance: " + path)
			}
		}
		if !reflect.DeepEqual(old.Cases, c.Cases) || !reflect.DeepEqual(old.Bounded, c.Bounded) || !bytes.Equal(old.LegacyV1, c.LegacyV1) || !bytes.Equal(old.LegacyV1Plain, c.LegacyV1Plain) {
			panic("native codec observations changed; fresh evidence is retained in " + *out)
		}
	}

}

//go:build ignore

// Independently generate native resource forks and qualify inline storage with
// the macOS kernel, retaining complete raw data and provenance for every OS.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type sample struct {
	Name, Origin           string
	Type                   uint32
	Plain, Attribute, Fork []byte
}
type command struct {
	Args   []string
	Output string
}
type report struct {
	Revision, Host, Compiler, SDK string
	SourceSHA256                  map[string]string
	Commands                      []command
	Cases                         []sample
}

var evidence report
var out string

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func read(p string) []byte { b, e := os.ReadFile(p); must(e); return b }
func run(args ...string) []byte {
	b, e := exec.Command(args[0], args[1:]...).CombinedOutput()
	evidence.Commands = append(evidence.Commands, command{args, string(b)})
	if e != nil {
		panic(fmt.Sprintf("%v: %v\n%s", args, e, b))
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
func save(p string, b []byte) { must(os.WriteFile(p, b, 0600)) }
func sha(b []byte) string     { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func main() {
	dir := flag.String("out", "artifacts/decmpfs-formats", "artifact directory")
	capture := flag.Bool("capture", false, "replace retained native fixtures")
	flag.Parse()
	if runtime.GOOS != "darwin" {
		panic("native producer and kernel qualification require macOS")
	}
	var e error
	out, e = filepath.Abs(*dir)
	must(e)
	must(os.MkdirAll(filepath.Join(out, "source"), 0755))
	evidence.SourceSHA256 = map[string]string{}
	evidence.Revision = strings.TrimSpace(string(run("git", "rev-parse", "HEAD")))
	evidence.Host = string(run("sw_vers"))
	evidence.Compiler = string(run("xcrun", "clang", "--version"))
	evidence.SDK = string(run("xcrun", "--show-sdk-version"))
	defer func() {
		b, e := json.MarshalIndent(evidence, "", "  ")
		must(e)
		save(filepath.Join(out, "report.json"), b)
	}()
	refs := map[string]string{"decmpfs.h": "https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/decmpfs.h", "decmpfs.c": "https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/decmpfs.c", "fscmp.c": "https://raw.githubusercontent.com/Siguza/fscmp/905322c0e96c706e78b58237dab7e65c4f7a31f8/src/main.c", "AppleFSCompression.h": "https://raw.githubusercontent.com/Siguza/fscmp/905322c0e96c706e78b58237dab7e65c4f7a31f8/AppleFSCompression.framework/Headers/AppleFSCompression.h"}
	for name, url := range refs {
		p := filepath.Join(out, "source", name)
		run("curl", "-fsSL", url, "-o", p)
		evidence.SourceSHA256[url] = sha(read(p))
	}
	for _, p := range []string{"scripts/verify-decmpfs-formats.go", "testdata/appledouble/native/decmpfs-formats.c", "internal/decmpfs/decmpfs.go", "internal/decmpfs/decompress.go", "internal/decmpfs/handle.go", "internal/decmpfs/storage.go", "pkg/compression/lzbitmap/lzbitmap.go", "pkg/compression/lzbitmap/encode.go"} {
		evidence.SourceSHA256[p] = sha(read(p))
	}
	source := "testdata/appledouble/native/decmpfs-formats.c"
	oracle := filepath.Join(out, "oracle")
	run("xcrun", "clang", "-Wall", "-Werror", "-framework", "CoreFoundation", source, "-o", oracle)
	for _, arch := range []string{"arm64", "x86_64"} {
		b := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		save(filepath.Join(out, arch+".ast.json"), b)
		evidence.Commands[len(evidence.Commands)-1].Output = fmt.Sprintf("AST %d bytes sha256=%s", len(b), sha(b))
		for _, name := range []string{"getxattr", "setxattr", "chflags", "lstat", "dlsym"} {
			if !bytes.Contains(b, []byte(`"name": "`+name+`"`)) {
				panic("AST missing " + name)
			}
		}
	}
	temp, e := os.MkdirTemp("", "decmpfs-native-")
	must(e)
	defer os.RemoveAll(temp)
	for _, kind := range []uint32{10, 14} {
		for _, pattern := range []string{"dense", "mixed"} {
			plain := make([]byte, 2*65536+123)
			var state uint32 = 0x12345678
			for i := range plain {
				if pattern == "mixed" && i >= 65536 {
					state ^= state << 13
					state ^= state >> 17
					state ^= state << 5
					plain[i] = byte(state)
				} else {
					plain[i] = byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ "[i%27])
				}
			}
			name := fmt.Sprintf("native-%d-%s", kind, pattern)
			path := filepath.Join(temp, name)
			save(path, plain)
			prefix := filepath.Join(out, name)
			run(oracle, "produce", fmt.Sprint(kind), path, prefix)
			attr, fork := read(prefix+".attr"), read(prefix+".fork")
			if binary.LittleEndian.Uint32(attr[4:]) != kind || !bytes.Equal(read(prefix+".readback"), plain) {
				panic("native producer mismatch")
			}
			evidence.Cases = append(evidence.Cases, sample{name, "AppleFSCompression producer and native kernel readback", kind, plain, attr, fork})
			start, end := binary.LittleEndian.Uint32(fork), binary.LittleEndian.Uint32(fork[4:])
			payload := fork[start:end]
			inlineType := kind - 1
			inlinePlain := plain[:65536]
			if inlineType == 9 {
				inlinePlain = plain[:512]
				payload = append([]byte{0xcc}, inlinePlain...)
			}
			inline := sample{fmt.Sprintf("kernel-%d-%s", inlineType, pattern), "native fork block placed in inline container; independently accepted and read by kernel", inlineType, inlinePlain, append(header(inlineType, len(inlinePlain)), payload...), nil}
			qualifyInstall(oracle, temp, inline)
		}
	}
	plain := []byte("Type1 inline data\x00with binary bytes\xff")
	qualifyInstall(oracle, temp, sample{"kernel-type1", "Apple XNU type1 source layout; independently accepted and read by kernel", 1, plain, append(header(1, len(plain)), plain...), nil})
	qualifyInstall(oracle, temp, sample{"kernel-type1-empty", "XNU type1 empty container; kernel readback", 1, nil, header(1, 0), nil})
	qualifyInstall(oracle, temp, sample{"kernel-type1-independent-fork", "XNU type1 with independently preserved resource fork; kernel readback", 1, plain, append(header(1, len(plain)), plain...), []byte("independent fork")})
	large := bytes.Repeat([]byte{65}, 3786)
	qualifyInstall(oracle, temp, sample{"kernel-type1-boundary", "XNU3802byte maximum compression attribute; kernel readback", 1, large, append(header(1, len(large)), large...), nil})
	for _, kind := range []uint32{9, 13} {
		for _, c := range evidence.Cases {
			if c.Name == fmt.Sprintf("kernel-%d-dense", kind) {
				c.Name = fmt.Sprintf("kernel-%d-independent-fork", kind)
				c.Fork = []byte("independent fork")
				c.Origin = "native inline block and independent resource fork; kernel readback"
				qualifyInstall(oracle, temp, c)
				break
			}
		}
	}
	if *capture {
		f, e := os.Create("testdata/appledouble/native/decmpfs-formats.json.gz")
		must(e)
		z := gzip.NewWriter(f)
		must(json.NewEncoder(z).Encode(evidence))
		must(z.Close())
		must(f.Close())
	}
	fmt.Printf("Qualified %d native compression storage cases\n", len(evidence.Cases))
}
func qualifyInstall(oracle, temp string, s sample) {
	prefix := filepath.Join(out, s.Name)
	save(prefix+".input-attr", s.Attribute)
	fork := "-"
	if s.Fork != nil {
		fork = prefix + ".input-fork"
		save(fork, s.Fork)
	}
	run(oracle, "install", filepath.Join(temp, s.Name), prefix+".input-attr", fork, prefix)
	if !bytes.Equal(read(prefix+".readback"), s.Plain) || !bytes.Equal(read(prefix+".attr"), s.Attribute) {
		panic("native inline mismatch " + s.Name)
	}
	evidence.Cases = append(evidence.Cases, s)
}

//go:build ignore

// Read every byte of the retained native corpus through the portable decoder.
// Run unchanged on Linux, macOS and Windows; neither native APIs nor subprocesses
// participate in this qualification.
package main

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
)

type source struct {
	*os.File
	size    uint64
	maximum int
}

func (s *source) Size() uint64 { return s.size }
func (s *source) ReadAt(p []byte, at int64) (int, error) {
	s.maximum = max(s.maximum, len(p))
	return s.File.ReadAt(p, at)
}

type sample struct {
	Name, SHA256, ForkSHA256 string
	StoredCompressed         bool
	Type                     uint32
	Size                     int64
}
type result struct {
	Name, SHA256 string
	Size         int64
	MaximumRead  int
	Seconds      float64
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func qualify(dir string, c sample) result {
	start := time.Now()
	archive, e := os.Open(filepath.Join(dir, c.Name+".fork.gz"))
	must(e)
	defer archive.Close()
	z, e := gzip.NewReader(archive)
	must(e)
	defer z.Close()
	f, e := os.CreateTemp("", "apfs-compression-fork-")
	must(e)
	defer os.Remove(f.Name())
	defer f.Close()
	hash := sha256.New()
	size, e := io.CopyBuffer(io.MultiWriter(f, hash), z, make([]byte, 65536))
	must(e)
	if hex.EncodeToString(hash.Sum(nil)) != c.ForkSHA256 {
		panic("native fork checksum changed: " + c.Name)
	}
	s := &source{File: f, size: uint64(size)}
	method, e := decmpfs.MethodFor(c.Type)
	must(e)
	h, e := decmpfs.NewHandle(s, uint64(c.Size), method)
	must(e)
	defer h.Close()
	hash.Reset()
	buffer := make([]byte, 65536)
	for at := int64(0); at < c.Size; {
		p := buffer[:min(int64(len(buffer)), c.Size-at)]
		n, e := h.ReadSegmentData(0, p)
		must(e)
		if n != len(p) {
			panic("short logical read: " + c.Name)
		}
		_, e = hash.Write(p)
		must(e)
		at += int64(n)
	}
	if _, e = h.ReadSegmentData(0, buffer[:1]); e != io.EOF {
		panic("incorrect logical end: " + c.Name)
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if digest != c.SHA256 {
		panic("native logical hash mismatch: " + c.Name)
	}
	if s.maximum > 65537 {
		panic("unbounded source request: " + c.Name)
	}
	return result{Name: c.Name, SHA256: digest, Size: c.Size, MaximumRead: s.maximum, Seconds: time.Since(start).Seconds()}
}
func main() {
	const dir = "testdata/appledouble/native/large-compression"
	const out = "artifacts/large-compression-portable"
	must(os.MkdirAll(out, 0755))
	b, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	must(e)
	var corpus struct{ Cases []sample }
	must(json.Unmarshal(b, &corpus))
	if len(corpus.Cases) != 43 {
		panic("incomplete native corpus")
	}
	report := struct {
		OS, Arch string
		Complete bool
		Cases    []result
	}{OS: runtime.GOOS, Arch: runtime.GOARCH}
	defer func() {
		b, e := json.MarshalIndent(report, "", "  ")
		must(e)
		must(os.WriteFile(filepath.Join(out, "report.json"), b, 0644))
	}()
	seen := map[string]bool{}
	for _, c := range corpus.Cases {
		if seen[c.Name] {
			panic("duplicate native case")
		}
		seen[c.Name] = true
		if !c.StoredCompressed {
			if c.Name != "native-4-536870913" {
				panic("unexpected producer-policy control")
			}
			continue
		}
		r := qualify(dir, c)
		report.Cases = append(report.Cases, r)
		fmt.Printf("%s: %d bytes, %.2fs, sha256=%s\n", r.Name, r.Size, r.Seconds, r.SHA256)
	}
	if len(report.Cases) != 42 {
		panic("missing compressed case")
	}
	report.Complete = true
}

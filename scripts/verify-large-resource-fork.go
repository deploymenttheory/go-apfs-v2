//go:build ignore

// Consume real >4 GiB values through carrier and image writers on every host.
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
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing/fstest"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/largefork"
	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

const imageSize int64 = (1 << 32) + (128 << 20)

const maxArchiveBytes int64 = 64 << 20
const heapBudget uint64 = 512 << 20

type fixture struct {
	fstest.MapFS
	value *largefork.Value
}

func (fixture) Readlink(string) (string, error) { return "", fs.ErrInvalid }
func (f fixture) XattrValues(name string) (map[string]appledouble.Value, error) {
	if name == "file" {
		return map[string]appledouble.Value{hostmeta.ResourceForkName: f.value}, nil
	}
	return nil, nil
}

func (f fixture) Metadata(name string) (hostmeta.ImageMetadata, error) {
	info, err := f.Stat(name)
	if err != nil {
		return hostmeta.ImageMetadata{}, err
	}
	mode := uint32(0100644)
	if info.IsDir() {
		mode = 0040755
	}
	tm := time.Unix(1500000000, 123456789).UTC()
	return hostmeta.ImageMetadata{UID: 501, GID: 20, Mode: mode, Times: &hostmeta.FileTimes{Birth: tm, Modify: tm, Access: tm, Change: tm}}, nil
}

type imageResult struct {
	Format, File, SHA256, ForkSHA256 string
	Size                             int64
	Native                           bool
}
type nativeResult struct {
	Size, ReadBytes, Blocks int64
	SameIdentity            bool
	SHA256                  string
}
type command struct {
	Args   []string
	Output string
}
type report struct {
	Revision, GOOS, GOARCH, Go, ExpectedSHA256, Compiler, SDK string
	Sources, Headers                                          map[string]string
	ForkSize, SourceReads                                     int64
	MaxSourceRead                                             int
	AppleDoubleRejected                                       bool
	Images                                                    []imageResult
	Native                                                    []nativeResult
	Commands                                                  []command
	ObservedHeapBytes                                         uint64
}

var evidence report
var output, oracle string

func watchHeap() func() uint64 {
	debug.SetMemoryLimit(256 << 20)
	stop, result := make(chan struct{}), make(chan uint64, 1)
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		var peak uint64
		for {
			var stats runtime.MemStats
			runtime.ReadMemStats(&stats)
			peak = max(peak, stats.HeapAlloc)
			select {
			case <-stop:
				result <- peak
				return
			case <-ticker.C:
			}
		}
	}()
	return func() uint64 { close(stop); return <-result }
}

type archiveBudget struct {
	file      *os.File
	remaining int64
}

func (w *archiveBudget) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, metatransport.ErrLimit
	}
	n, err := w.file.Write(p)
	w.remaining -= int64(n)
	return n, err
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(name string) []byte { b, e := os.ReadFile(name); must(e); return b }
func digest(p []byte) string  { sum := sha256.Sum256(p); return hex.EncodeToString(sum[:]) }
func writeJSON(name string, v any) {
	b, e := json.MarshalIndent(v, "", "  ")
	must(e)
	must(os.WriteFile(name, append(b, '\n'), 0600))
}
func run(args ...string) []byte {
	b, e := exec.Command(args[0], args[1:]...).CombinedOutput()
	evidence.Commands = append(evidence.Commands, command{args, fmt.Sprintf("%s\nerror: %v", b, e)})
	if e != nil {
		panic(fmt.Errorf("%v: %w: %s", args, e, b))
	}
	return b
}
func valueHash(v appledouble.Value) string {
	h := sha256.New()
	n, e := io.CopyBuffer(h, io.NewSectionReader(v, 0, v.Size()), make([]byte, 64<<10))
	must(e)
	if n != v.Size() {
		panic("short full-value digest")
	}
	return hex.EncodeToString(h.Sum(nil))
}
func checkValue(v appledouble.Value) {
	if v == nil || v.Size() != largefork.Size {
		panic("lost 64-bit fork length")
	}
	if valueHash(v) != evidence.ExpectedSHA256 {
		panic("full fork digest mismatch")
	}
	for _, off := range []int64{0, (1 << 32) - 8, 1 << 32, largefork.Size - 1} {
		n := min(int64(17), largefork.Size-off)
		actual, want := make([]byte, n), make([]byte, n)
		_, e := v.ReadAt(actual, off)
		must(e)
		_, e = (&largefork.Value{}).ReadAt(want, off)
		must(e)
		if !bytes.Equal(actual, want) {
			panic("64-bit boundary marker mismatch")
		}
	}
}
func pack(kind, name, payload, metadata string) {
	f, e := os.Create(name)
	must(e)
	if kind == "apfs" {
		tree, e := apfswrite.OpenEntryTreeFromDir(payload, &apfswrite.WalkOptions{MetadataRoot: metadata})
		must(e)
		e = apfswrite.CreateContainer(f, imageSize, &apfswrite.CreateOptions{Root: tree.Root, VolumeName: "LARGEFORK"})
		must(errors.Join(e, tree.Close(), f.Close()))
	} else {
		tree, e := hfsplus.OpenEntryTreeFromDir(payload, &hfsplus.WalkOptions{MetadataRoot: metadata})
		must(e)
		e = hfsplus.CreateImage(f, imageSize, "LARGEFORK", tree.Root, &hfsplus.CreateOptions{CaseInsensitive: true})
		must(errors.Join(e, tree.Close(), f.Close()))
	}
	f, e = os.Open(name)
	must(e)
	var attrs map[string]appledouble.Value
	if kind == "apfs" {
		c, e := apfs.Open(f, nil)
		must(e)
		v, e := c.VolumeBySelector("0")
		must(e)
		attrs, e = v.XattrValues("file")
		must(e)
		checkValue(attrs[hostmeta.ResourceForkName])
		must(c.Close())
	} else {
		v, e := hfsplus.New(f)
		must(e)
		attrs, e = v.XattrValues("file")
		must(e)
		checkValue(attrs[hostmeta.ResourceForkName])
	}
	must(f.Close())
}
func archive(name, destination string) (string, int64) {
	f, e := os.Open(name)
	must(e)
	defer func() { must(f.Close()) }()
	info, e := f.Stat()
	must(e)
	if info.Size() > imageSize {
		panic("image exceeded explicit disk budget")
	}
	out, e := os.Create(destination)
	must(e)
	z := gzip.NewWriter(&archiveBudget{file: out, remaining: maxArchiveBytes})
	hash := sha256.New()
	_, e = io.CopyBuffer(io.MultiWriter(hash, z), f, make([]byte, 64<<10))
	must(errors.Join(e, z.Close(), out.Close()))
	return hex.EncodeToString(hash.Sum(nil)), info.Size()
}
func detach(name string) {
	must(diskimage.RetryDetach(context.Background(), func() (int, error) {
		args := []string{"hdiutil", "detach", name}
		b, e := exec.Command(args[0], args[1:]...).CombinedOutput()
		code := 0
		if e != nil {
			code = -1
			var exit *exec.ExitError
			if errors.As(e, &exit) {
				code = exit.ExitCode()
			}
		}
		evidence.Commands = append(evidence.Commands, command{args, fmt.Sprintf("%s\nexit_code: %d\nerror: %v", b, code, e)})
		return code, e
	}))
}
func nativeImage(name, workspace string) {
	mount := filepath.Join(workspace, "mount")
	must(os.Mkdir(mount, 0700))
	defer func() { must(os.Remove(mount)) }()
	run("hdiutil", "attach", name, "-readonly", "-nobrowse", "-mountpoint", mount)
	defer detach(mount)
	var got nativeResult
	must(json.Unmarshal(run(oracle, "--hash", filepath.Join(mount, "file")), &got))
	checkNative(got)
	evidence.Native = append(evidence.Native, got)
}
func checkNative(got nativeResult) {
	if got.Size != largefork.Size || got.ReadBytes != largefork.Size || !got.SameIdentity || got.SHA256 != evidence.ExpectedSHA256 {
		panic(fmt.Sprintf("native fork differs: %+v", got))
	}
}
func prepareOracle() {
	evidence.Compiler = string(run("xcrun", "clang", "--version"))
	evidence.SDK = strings.TrimSpace(string(run("xcrun", "--show-sdk-version")))
	sdk := strings.TrimSpace(string(run("xcrun", "--show-sdk-path")))
	for _, name := range []string{"sys/stat.h", "sys/xattr.h", "fcntl.h", "unistd.h", "CommonCrypto/CommonDigest.h"} {
		evidence.Headers[name] = digest(read(filepath.Join(sdk, "usr/include", name)))
	}
	source := "testdata/appledouble/native/large-resource-fork.c"
	oracle = filepath.Join(output, "large-fork-oracle")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", oracle)
	for _, arch := range []string{"arm64", "x86_64"} {
		b := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		var ast any
		must(json.Unmarshal(b, &ast))
		calls := map[string]int{}
		var visit func(any)
		visit = func(n any) {
			switch v := n.(type) {
			case []any:
				for _, x := range v {
					visit(x)
				}
			case map[string]any:
				if v["kind"] == "DeclRefExpr" {
					if d, ok := v["referencedDecl"].(map[string]any); ok {
						if name, ok := d["name"].(string); ok {
							calls[name]++
						}
					}
				}
				for _, x := range v {
					visit(x)
				}
			}
		}
		visit(ast)
		for name, count := range map[string]int{"open": 1, "openat": 1, "ftruncate": 1, "pwrite": 3, "pread": 1, "fstat": 2, "CC_SHA256_Init": 1, "CC_SHA256_Update": 1, "CC_SHA256_Final": 1} {
			if calls[name] != count {
				panic("native AST changed: " + name)
			}
		}
		must(os.WriteFile(filepath.Join(output, arch+".ast.json"), b, 0600))
		evidence.Commands[len(evidence.Commands)-1].Output = fmt.Sprintf("AST retained: %d bytes SHA256 %s", len(b), digest(b))
	}
}
func nativeBinding(workspace string) {
	name := filepath.Join(workspace, "native-file")
	var got nativeResult
	must(json.Unmarshal(run(oracle, "--create", name), &got))
	checkNative(got)
	evidence.Native = append(evidence.Native, got)
	file, e := os.OpenFile(name, os.O_RDWR, 0600)
	must(e)
	defer func() { must(file.Close()) }()
	values, e := hostmeta.CaptureXattrValues(context.Background(), file, hostmeta.XattrCaptureLimits{NameBytes: hostmeta.MaxXattrListSize, ValueBytes: 16384, TotalBytes: 32768})
	must(e)
	checkValue(values[hostmeta.ResourceForkName])
	must(os.Rename(name, name+".moved"))
	must(os.WriteFile(name, []byte("replacement"), 0600))
	n, e := hostmeta.ReplaceResourceFork(context.Background(), file, &largefork.Value{})
	must(e)
	if n != largefork.Size {
		panic("native streamed write truncated")
	}
	must(json.Unmarshal(run(oracle, "--hash", name+".moved"), &got))
	checkNative(got)
	evidence.Native = append(evidence.Native, got)
	if string(read(name)) != "replacement" {
		panic("held write followed replacement path")
	}
}
func main() {
	out := flag.String("out", "artifacts/large-resource-fork", "evidence directory")
	foreign := flag.String("foreign", "", "independently verify foreign compressed images on macOS")
	foreignOS := flag.String("foreign-goos", "", "expected foreign host")
	reference := flag.String("reference", "", "matching native Mac report for exact foreign image hashes")
	flag.Parse()
	var e error
	output, e = filepath.Abs(*out)
	must(e)
	must(os.MkdirAll(output, 0700))
	evidence = report{Revision: strings.TrimSpace(string(run("git", "rev-parse", "HEAD"))), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Go: runtime.Version(), ForkSize: largefork.Size, Headers: map[string]string{}}
	stopHeap := watchHeap()
	defer func() {
		evidence.ObservedHeapBytes = stopHeap()
		writeJSON(filepath.Join(output, "report.json"), evidence)
		if evidence.ObservedHeapBytes > heapBudget {
			panic("large-fork qualification exceeded 512 MiB sampled Go heap budget")
		}
	}()
	evidence.Sources, e = evidenceaudit.SourceHashes(os.DirFS("."), []string{"scripts/verify-large-resource-fork.go", "testdata/appledouble/native/large-resource-fork.c", "internal/testutil/largefork/*.go", "internal/testutil/diskimage/*.go", "internal/tools/extract*.go", "internal/hostwalk/*.go", "pkg/metatransport/*.go", "pkg/hostmeta/*.go", "pkg/appledouble/*.go", "pkg/apfswrite/*.go", "pkg/apfs/*.go", "pkg/hfsplus/*.go", "go.mod", "go.sum"})
	must(e)
	evidence.ExpectedSHA256 = valueHash(&largefork.Value{})
	if runtime.GOOS == "darwin" {
		prepareOracle()
	}
	workspace, e := os.MkdirTemp("", "large-resource-fork-")
	must(e)
	defer func() { must(os.RemoveAll(workspace)) }()
	if *foreign != "" {
		if runtime.GOOS != "darwin" {
			panic("foreign verification requires native macOS")
		}
		var prior report
		must(json.Unmarshal(read(filepath.Join(*foreign, "report.json")), &prior))
		if prior.Revision != evidence.Revision || prior.GOOS != *foreignOS || (*foreignOS != "linux" && *foreignOS != "windows") || prior.ExpectedSHA256 != evidence.ExpectedSHA256 || prior.ForkSize != largefork.Size || !prior.AppleDoubleRejected || len(prior.Images) != 2 || len(prior.Sources) != len(evidence.Sources) || prior.SourceReads < 65537 || prior.MaxSourceRead == 0 || prior.MaxSourceRead > 64<<10 || prior.ObservedHeapBytes == 0 || prior.ObservedHeapBytes > heapBudget {
			panic("foreign qualification inventory mismatch")
		}
		var native report
		if *reference != "" {
			must(json.Unmarshal(read(filepath.Join(*reference, "report.json")), &native))
			if native.Revision != evidence.Revision || native.GOOS != "darwin" || len(native.Images) != 2 || len(native.Sources) != len(evidence.Sources) {
				panic("native reference inventory mismatch")
			}
		}
		for name, sum := range evidence.Sources {
			if prior.Sources[name] != sum {
				panic("foreign source mismatch: " + name)
			}
			if *reference != "" && native.Sources[name] != sum {
				panic("native reference source mismatch: " + name)
			}
		}
		for i, item := range prior.Images {
			if item.Format != []string{"apfs", "hfsplus"}[i] || item.File != item.Format+".img.gz" || item.Size != imageSize || item.ForkSHA256 != evidence.ExpectedSHA256 {
				panic("foreign image inventory mismatch")
			}
			if *reference != "" && (!native.Images[i].Native || native.Images[i].Format != item.Format || native.Images[i].SHA256 != item.SHA256 || native.Images[i].Size != item.Size) {
				panic("foreign image differs from native reference")
			}
			f, e := os.Open(filepath.Join(*foreign, item.File))
			must(e)
			z, e := gzip.NewReader(f)
			must(e)
			name := filepath.Join(workspace, item.Format+".img")
			out, e := os.Create(name)
			must(e)
			hash := sha256.New()
			n, e := io.CopyBuffer(io.MultiWriter(out, hash), io.LimitReader(z, imageSize+1), make([]byte, 64<<10))
			must(errors.Join(e, z.Close(), f.Close(), out.Close()))
			if n != imageSize || hex.EncodeToString(hash.Sum(nil)) != item.SHA256 {
				panic("foreign image digest mismatch")
			}
			nativeImage(name, workspace)
			must(os.Remove(name))
			item.Native = true
			evidence.Images = append(evidence.Images, item)
		}
		fmt.Println("Native foreign large-fork verification passed", *foreignOS)
		return
	}
	value := &largefork.Value{}
	volume := fixture{fstest.MapFS{"file": {Data: []byte("payload")}}, value}
	extractor := tools.NewExtractor(volume, filepath.Join(workspace, "payload"))
	extractor.MetadataRoot = filepath.Join(workspace, "metadata")
	extractor.Xattrs = true
	extractor.PreserveMeta = true
	limits := metatransport.DefaultLimits()
	limits.BlobBytes = largefork.Size
	extractor.MetadataLimits = &limits
	must(extractor.ExtractAll())
	fmt.Println("Large-fork carrier published; verifying complete value")
	store, e := metatransport.Open(extractor.Destination, extractor.MetadataRoot, limits)
	must(e)
	manifest, e := store.Load(context.Background())
	must(e)
	found := false
	for _, r := range manifest.Records {
		if r.Original != "file" {
			continue
		}
		if r.AppleDouble != nil {
			panic("out-of-wire fork emitted sidecar")
		}
		attrs, e := store.BorrowRecordAttributes(context.Background(), r)
		must(e)
		checkValue(attrs[hostmeta.ResourceForkName])
		found = true
	}
	if !found {
		panic("carrier file missing")
	}
	must(store.Close())
	n, e := (&appledouble.StreamFile{ResourceFork: value}).EncodeTo(context.Background(), io.Discard, appledouble.DefaultStreamLimits())
	if n != 0 || !errors.Is(e, appledouble.ErrTooLarge) {
		panic("wire overflow not rejected before output")
	}
	evidence.AppleDoubleRejected = true
	evidence.SourceReads = value.Reads
	evidence.MaxSourceRead = value.MaxRead
	if value.Reads == 0 || value.MaxRead > 64<<10 {
		panic("unbounded or unconsumed source")
	}
	for _, kind := range []string{"apfs", "hfsplus"} {
		fmt.Println("Large-fork image:", kind)
		name := filepath.Join(workspace, kind+".img")
		pack(kind, name, extractor.Destination, extractor.MetadataRoot)
		item := imageResult{Format: kind, File: kind + ".img.gz", ForkSHA256: evidence.ExpectedSHA256}
		if runtime.GOOS == "darwin" {
			nativeImage(name, workspace)
			item.Native = true
		}
		item.SHA256, item.Size = archive(name, filepath.Join(output, item.File))
		must(os.Remove(name))
		evidence.Images = append(evidence.Images, item)
	}
	// Remove the carrier before native fork projection: at most one carrier plus
	// one explicitly bounded image, or one native fork, occupies disk at a time.
	must(os.RemoveAll(extractor.MetadataRoot))
	must(os.RemoveAll(extractor.Destination))
	if runtime.GOOS == "darwin" {
		fmt.Println("Large-fork native held-descriptor capture and replacement")
		nativeBinding(workspace)
	}
	fmt.Printf("Large fork: %d real bytes; APFS/HFS+ full hashes and uint32-boundary markers verified on %s/%s\n", largefork.Size, runtime.GOOS, runtime.GOARCH)
}

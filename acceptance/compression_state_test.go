package acceptance

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type compressionStateCase struct {
	Filesystem, Name, State string
	Attribute, Fork, Data   []byte
	Observation             struct {
		Flags     uint32 `json:"flags"`
		Size      int64  `json:"size"`
		ReadErrno int    `json:"read_errno"`
	}
}
type compressionStateCorpus struct {
	Schema              int
	Host, Compiler, SDK string
	Sources, Images     map[string]string
	Cases               []compressionStateCase
}
type compressionStateVolume interface {
	tools.VolumeFS
	hostdata.ImageMetadataFS
	Xattrs(string) (map[string][]byte, error)
}

func compressionStateLoad(t *testing.T) compressionStateCorpus {
	t.Helper()
	f, e := os.Open("../testdata/appledouble/native/compression-state.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var c compressionStateCorpus
	if e = json.NewDecoder(z).Decode(&c); e != nil {
		t.Fatal(e)
	}
	if c.Schema != 1 || len(c.Cases) != 160 || c.Host == "" || c.Compiler == "" || c.SDK == "" {
		t.Fatal("incomplete native corpus")
	}
	for _, path := range []string{"scripts/capture-compression-state.go", "testdata/appledouble/native/compression-state.c", "testdata/appledouble/native/compression-lifecycle.json.gz", "go.mod", "go.sum"} {
		b, e := os.ReadFile("../" + path)
		if e != nil {
			t.Fatal(e)
		}
		if fmt.Sprintf("%x", sha256.Sum256(b)) != c.Sources[path] {
			t.Fatal("stale native provenance", path)
		}
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		if len(c.Sources[arch+"-compression-state.ast.json"]) != 64 {
			t.Fatal("missing AST", arch)
		}
	}
	return c
}
func compressionStateOpen(t *testing.T, path, filesystem string) compressionStateVolume {
	t.Helper()
	if filesystem == "APFS" {
		c, closer, e := apfs.OpenImage(path, nil)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			if e := closer.Close(); e != nil {
				t.Error(e)
			}
		})
		volumes, e := c.Volumes()
		if e != nil || len(volumes) != 1 {
			t.Fatalf("volumes %v: %v", volumes, e)
		}
		return volumes[0]
	}
	reader, offset, closer, e := disk.OpenWithOffset(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := closer.Close(); e != nil {
			t.Error(e)
		}
	})
	v, e := hfsplus.New(io.NewSectionReader(reader, offset, 1<<62))
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func compressionStateCompare(t *testing.T, v compressionStateVolume, want compressionStateCase) {
	t.Helper()
	b, e := v.ReadFile(want.Name)
	if e != nil || !bytes.Equal(b, want.Data) {
		t.Fatalf("data size=%d prefix=%q error=%v; want size=%d prefix=%q", len(b), b[:min(16, len(b))], e, len(want.Data), want.Data[:min(16, len(want.Data))])
	}
	info, e := v.Stat(want.Name)
	if e != nil || info.Size() != want.Observation.Size {
		t.Fatalf("stat %v: %v", info, e)
	}
	m, e := v.Metadata(want.Name)
	if e != nil || m.BSDFlags != want.Observation.Flags {
		t.Fatalf("metadata %+v: %v", m, e)
	}
	attrs, e := v.Xattrs(want.Name)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(attrs[hostdata.DecmpfsName], want.Attribute) || !bytes.Equal(attrs[hostdata.ResourceForkName], want.Fork) {
		t.Fatal("raw compression metadata changed")
	}
}
func TestCompressionStateImages(t *testing.T) {
	c := compressionStateLoad(t)
	out := os.Getenv("APFS_COMPRESSION_STATE_OUTPUT")
	if out == "" {
		out = t.TempDir()
	}
	if e := os.MkdirAll(out, 0700); e != nil {
		t.Fatal(e)
	}
	for _, filesystem := range []string{"APFS", "HFS+"} {
		t.Run(filesystem, func(t *testing.T) {
			nativePath := filepath.Join("../testdata/appledouble/native/compression-state", filesystem+".dmg")
			raw, e := os.ReadFile(nativePath)
			if e != nil {
				t.Fatal(e)
			}
			if fmt.Sprintf("%x", sha256.Sum256(raw)) != c.Images[filesystem+".dmg"] {
				t.Fatal("native image digest")
			}
			native := compressionStateOpen(t, nativePath, filesystem)
			aroot := &apfswrite.Entry{Mode: os.ModeDir | 0755}
			hroot := &hfsplus.Entry{Mode: os.ModeDir | 0755}
			count := 0
			for _, s := range c.Cases {
				if s.Filesystem != filesystem {
					continue
				}
				count++
				t.Run("native/"+s.Name, func(t *testing.T) { compressionStateCompare(t, native, s) })
				flags := s.Observation.Flags
				data := s.Data
				if flags&hostdata.UFCompressed != 0 {
					data = nil
				}
				attrs := map[string][]byte{hostdata.DecmpfsName: s.Attribute}
				hattrs := map[string][]byte{hostdata.DecmpfsName: s.Attribute}
				if len(s.Fork) > 0 {
					attrs[hostdata.ResourceForkName] = s.Fork
				}
				aroot.Children = append(aroot.Children, &apfswrite.Entry{Name: s.Name, Mode: 0644, BSDFlags: &flags, Data: data, Xattrs: attrs})
				hroot.Children = append(hroot.Children, &hfsplus.Entry{Name: s.Name, Mode: 0644, BSDFlags: &flags, Data: data, Xattrs: hattrs, ResourceFork: s.Fork})
			}
			if count != 80 {
				t.Fatal("native case inventory", count)
			}
			path := filepath.Join(out, filesystem+".dmg")
			f, e := os.Create(path)
			if e != nil {
				t.Fatal(e)
			}
			if filesystem == "APFS" {
				e = apfswrite.CreateContainer(f, 64<<20, &apfswrite.CreateOptions{Root: aroot})
			} else {
				e = hfsplus.CreateImage(f, 64<<20, "CompressionState", hroot, nil)
			}
			closeErr := f.Close()
			if e != nil || closeErr != nil {
				t.Fatal(e, closeErr)
			}
			generated := compressionStateOpen(t, path, filesystem)
			for _, s := range c.Cases {
				if s.Filesystem != filesystem {
					continue
				}
				t.Run("written/"+s.Name, func(t *testing.T) { compressionStateCompare(t, generated, s) })
			}
			payload, metadata := filepath.Join(t.TempDir(), "payload"), filepath.Join(t.TempDir(), "metadata")
			extractor := tools.NewExtractor(native, payload)
			extractor.Context = t.Context()
			extractor.MetadataRoot, extractor.Xattrs, extractor.PreserveMeta = metadata, true, true
			if e = extractor.ExtractAll(); e != nil {
				t.Fatal(e)
			}
			carrierDir := filepath.Join(out, "carrier")
			if e = os.MkdirAll(carrierDir, 0700); e != nil {
				t.Fatal(e)
			}
			carrierPath := filepath.Join(carrierDir, filesystem+".dmg")
			f, e = os.Create(carrierPath)
			if e != nil {
				t.Fatal(e)
			}
			if filesystem == "APFS" {
				tree, openErr := apfswrite.OpenEntryTreeFromDir(payload, &apfswrite.WalkOptions{Context: t.Context(), MetadataRoot: metadata, Xattrs: true})
				if openErr != nil {
					f.Close()
					t.Fatal(openErr)
				}
				e = apfswrite.CreateContainer(f, 64<<20, &apfswrite.CreateOptions{Root: tree.Root})
				if closeErr := tree.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			} else {
				tree, openErr := hfsplus.OpenEntryTreeFromDir(payload, &hfsplus.WalkOptions{Context: t.Context(), MetadataRoot: metadata, Xattrs: true})
				if openErr != nil {
					f.Close()
					t.Fatal(openErr)
				}
				e = hfsplus.CreateImage(f, 64<<20, "CompressionState", tree.Root, nil)
				if closeErr := tree.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			closeErr = f.Close()
			if e != nil || closeErr != nil {
				t.Fatal(e, closeErr)
			}
			carried := compressionStateOpen(t, carrierPath, filesystem)
			for _, s := range c.Cases {
				if s.Filesystem != filesystem {
					continue
				}
				t.Run("carrier/"+s.Name, func(t *testing.T) { compressionStateCompare(t, carried, s) })
			}
		})
	}
}

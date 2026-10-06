//go:build ignore

// Reuse capture-name-collation.go's complete native validators, then exercise
// the public image readers. This test is intentionally invoked as named files.
package main

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readComparisonCapture(t *testing.T, path string) capture {
	t.Helper()
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var c capture
	if e = json.NewDecoder(z).Decode(&c); e != nil {
		t.Fatal(e)
	}
	return c
}

func TestNativeNameImageReaders(t *testing.T) {
	original, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Error(err)
		}
	})
	root, e := filepath.Abs("..")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chdir(root); e != nil {
		t.Fatal(e)
	}
	base := os.Getenv("APFS_NAME_IMAGE_ARTIFACTS")
	if base == "" {
		t.Fatal("APFS_NAME_IMAGE_ARTIFACTS must contain allthree native producer artifacts")
	}
	checked := 0
	for _, profile := range []struct {
		major    int
		artifact string
	}{{15, "name-collation-macos-15"}, {26, "name-collation-macos-latest"}, {27, "name-collation-xcode-27"}} {
		t.Run(fmt.Sprint(profile.major), func(t *testing.T) {
			dir := filepath.Join(base, profile.artifact)
			fresh := readComparisonCapture(t, filepath.Join(dir, "native.json.gz"))
			prior := readComparisonCapture(t, fmt.Sprintf("testdata/appledouble/native/name-collation-macos%d.json.gz", profile.major))
			if e := compareStable(prior, fresh); e != nil {
				t.Fatal(e)
			}
			for source, want := range fresh.Sources {
				path := filepath.Join(dir, source)
				if source == "native-binary" {
					path = filepath.Join(dir, "probe")
				}
				b, e := os.ReadFile(path)
				if e != nil {
					b, e = os.ReadFile(source)
				}
				if e != nil || sum(b) != want {
					t.Fatalf("source %s mismatch: %v", source, e)
				}
			}
			for _, v := range fresh.Volumes {
				t.Run(v.Kind, func(t *testing.T) {
					image := filepath.Join(dir, strings.ReplaceAll(v.Kind, "+", "plus")+".dmg")
					f, e := os.Open(image)
					if e != nil {
						t.Fatal(e)
					}
					h := sha256.New()
					if _, e = io.Copy(h, f); e != nil {
						t.Fatal(e)
					}
					if e = f.Close(); e != nil {
						t.Fatal(e)
					}
					if hex.EncodeToString(h.Sum(nil)) != v.ImageSHA256 {
						t.Fatal("native image hash mismatch")
					}
					var read func(string) ([]byte, error)
					var closer io.Closer
					if strings.HasPrefix(v.Kind, "APFS") {
						c, cl, e := apfs.OpenImage(image, nil)
						if e != nil {
							t.Fatal(e)
						}
						closer = cl
						volumes, e := c.Volumes()
						if e != nil || len(volumes) != 1 {
							t.Fatal("native APFS volume inventory", e)
						}
						if volumes[0].FileSystemBTree.UseCaseFolding == v.Native.Sensitive {
							t.Fatal("APFS case flag")
						}
						read = volumes[0].ReadFile
					} else {
						r, offset, cl, e := disk.OpenWithOffset(image)
						if e != nil {
							t.Fatal(e)
						}
						closer = cl
						volume, e := hfsplus.New(io.NewSectionReader(r, offset, 1<<40))
						if e != nil {
							t.Fatal(e)
						}
						if volume.CaseSensitive() != v.Native.Sensitive {
							t.Fatal("HFS case flag")
						}
						read = volume.ReadFile
					}
					defer func() {
						if e := closer.Close(); e != nil {
							t.Error(e)
						}
					}()
					for _, c := range v.Native.Cases {
						for _, q := range []struct {
							name    string
							present bool
							label   string
						}{{c.Created, c.CreateErrno == 0, "created"}, {c.Queried, c.LookupErrno == 0, "queried"}} {
							name, e := hex.DecodeString(q.name)
							if e != nil {
								t.Fatal(e)
							}
							data, e := read("collation/" + c.ID + "/" + string(name))
							if q.present {
								if e != nil || len(data) != 0 {
									t.Fatalf("%s/%s native emptyfile unreadable: bytes%d error%v", c.ID, q.label, len(data), e)
								}
							} else if !errors.Is(e, fs.ErrNotExist) {
								t.Fatalf("%s/%s native nonexistent file: %v", c.ID, q.label, e)
							}
							checked++
						}
					}
				})
			}
		})
	}
	if checked != 90072 {
		t.Fatalf("reader observations %d want90072", checked)
	}
}

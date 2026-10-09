//go:build ignore

// Reuse capture-name-collation.go's complete native validators, then exercise
// the public image readers. This test is intentionally invoked as named files.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

func decodeComparisonCapture(raw []byte) (capture, error) {
	var c capture
	z, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return c, err
	}
	plain, err := io.ReadAll(z)
	if err = errors.Join(err, z.Close()); err != nil {
		return c, err
	}
	err = json.Unmarshal(plain, &c)
	return c, err
}

func readComparisonCapture(t *testing.T, path string, expected ...int) capture {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := decodeComparisonCapture(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(expected) > 0 {
		if err := captureprovenance.VerifyExecution(t.Context(), filepath.Dir(path)); err != nil {
			t.Fatal(err)
		}
		if err := captureprovenance.Verify(os.DirFS("."), c.Sources); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := captureprovenance.VerifyReference(os.DirFS("."), c.Sources); err != nil {
			t.Fatal(err)
		}
	}
	major := 0
	for _, supported := range []int{15, 26, 27} {
		if filepath.Base(path) == fmt.Sprintf("name-collation-macos%d.json.gz", supported) {
			major = supported
		}
	}
	if len(expected) > 0 {
		major = expected[0]
	}
	if err = validateComparisonProfile(c, major); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestComparisonCaptureEnvelope(t *testing.T) {
	raw, err := os.ReadFile("../testdata/appledouble/native/name-collation-macos27.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	c, err := decodeComparisonCapture(raw)
	if err != nil || c.Schema != 1 {
		t.Fatal("valid native capture", err)
	}
	if _, err = decodeComparisonCapture(raw[:len(raw)-1]); err == nil {
		t.Fatal("accepted truncated gzip checksum")
	}
	corrupt := append([]byte(nil), raw...)
	corrupt[len(corrupt)-8] ^= 1
	if _, err = decodeComparisonCapture(corrupt); err == nil {
		t.Fatal("accepted corrupt gzip checksum")
	}
	plain, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	z := gzip.NewWriter(&out)
	if _, err = z.Write(append(plain, []byte("{}")...)); err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = decodeComparisonCapture(out.Bytes()); err == nil {
		t.Fatal("accepted trailing JSON")
	}
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
			fresh := readComparisonCapture(t, filepath.Join(dir, "native.json.gz"), profile.major)
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

func validateComparisonProfile(c capture, expected int) error {
	profile, err := osversion.ParseProductVersion(c.Host)
	if err != nil {
		return err
	}
	if _, err = osversion.ProfileForMacOS(profile); err != nil {
		return err
	}
	if expected != 0 && int(profile.Major) != expected {
		return fmt.Errorf("native macOS%d does not match expected macOS%d", profile.Major, expected)
	}
	return nil
}
func TestComparisonProfileIdentity(t *testing.T) {
	// Named-file Go tests start in scripts; provenance paths use the repo root.
	t.Chdir("..")
	c := readComparisonCapture(t, "testdata/appledouble/native/name-collation-macos27.json.gz")
	for _, wrong := range []int{15, 26} {
		if validateComparisonProfile(c, wrong) == nil {
			t.Fatal("accepted mislabeled native profile", wrong)
		}
	}
	if err := validateComparisonProfile(c, 0); err != nil {
		t.Fatal(err)
	}
	c.Host = "ProductName: macOS\nProductVersion: 26.6.2\nBuildVersion: native"
	if validateComparisonProfile(c, 27) == nil {
		t.Fatal("accepted macOS26 evidence as27")
	}
	for _, host := range []string{"", "ProductVersion: 14.0"} {
		c.Host = host
		if validateComparisonProfile(c, 0) == nil {
			t.Fatal("accepted invalid native host")
		}
	}
}

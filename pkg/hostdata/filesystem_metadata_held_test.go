package hostdata

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFilesystemMetadataBorrowedLifetime(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "native", true: "carrier"}[foreign], func(t *testing.T) {
			_, root, dir := newMetadataTestView(t, true)
			file, err := os.Open(filepath.Join(dir, "input"))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			v, err := filesystemMetadataForFile(context.Background(), file, func(*os.File) (bool, error) { return foreign, nil })
			if err != nil {
				t.Fatal(err)
			}
			if v.UsesAppleDouble() != foreign {
				t.Fatal("wrong storage selection")
			}
			if v.CaseInsensitiveNames() != (runtime.GOOS == "windows" && !foreign) {
				t.Fatal("wrong name policy")
			}
			if foreign {
				seed, err := readMetadataViewSeed()
				if err != nil {
					t.Fatal(err)
				}
				if err = root.WriteFile("._input", seed, 0600); err != nil {
					t.Fatal(err)
				}
				if n, p, err := v.Size(context.Background(), ResourceForkName); err != nil || !p || n != 12 {
					t.Fatal(n, p, err)
				}
			} else {
				v.ops.size = func(f *os.File, name string) (int, bool, error) {
					if f != file || name != "attribute" {
						t.Fatal("held identity lost")
					}
					return 123, true, nil
				}
				if n, p, err := v.Size(context.Background(), "attribute"); err != nil || !p || n != 123 {
					t.Fatal(n, p, err)
				}
			}
			if err = v.Close(); err != nil {
				t.Fatal(err)
			}
			if err = v.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = file.Stat(); err != nil {
				t.Fatal("view closed caller's descriptor", err)
			}
			if _, _, err = v.Size(context.Background(), "attribute"); !errors.Is(err, os.ErrClosed) {
				t.Fatal(err)
			}
		})
	}
}

func TestFilesystemMetadataHeldFailures(t *testing.T) {
	ctx := context.Background()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := FilesystemMetadataForFile(canceled, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := FilesystemMetadataForFile(ctx, nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	_, _, dir := newMetadataTestView(t, true)
	file, err := os.Open(filepath.Join(dir, "input"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err = filesystemMetadataForFile(ctx, file, func(*os.File) (bool, error) { return false, io.ErrUnexpectedEOF }); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	canceled, cancel = context.WithCancel(ctx)
	if _, err = filesystemMetadataForFile(canceled, file, func(*os.File) (bool, error) { cancel(); return false, nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = filesystemMetadataForFile(ctx, file, func(*os.File) (bool, error) {
		if err := os.Rename(file.Name(), filepath.Join(dir, "moved")); err != nil {
			t.Fatal(err)
		}
		return true, nil
	}); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err = os.WriteFile(file.Name(), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = filesystemMetadataForFile(ctx, file, func(*os.File) (bool, error) { return true, nil }); !errors.Is(err, ErrMetadataIdentity) {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = FilesystemMetadataForFile(ctx, file); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

func TestFilesystemMetadataSizeFailures(t *testing.T) {
	v, root, _ := newMetadataTestView(t, true)
	ctx := context.Background()
	if n, p, err := v.Size(ctx, "absent"); err != nil || p || n != 0 {
		t.Fatal(n, p, err)
	}
	if _, _, err := v.Size(ctx, ""); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if err := root.WriteFile("._input", []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, p, err := v.Size(ctx, "absent"); err != nil || p {
		t.Fatal(p, err)
	}
	seed, err := readMetadataViewSeed()
	if err != nil {
		t.Fatal(err)
	}
	if err = root.WriteFile("._input", seed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, p, err := v.Size(ctx, "absent"); err != nil || p {
		t.Fatal(p, err)
	}
	v.ops.sidecar = func(*os.Root, string) (*os.File, error) { return nil, os.ErrPermission }
	if _, _, err = v.Size(ctx, "attribute"); !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err = v.Size(canceled, "attribute"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestFilesystemMetadataRelativeHeldName(t *testing.T) {
	_, _, dir := newMetadataTestView(t, true)
	t.Chdir(dir)
	file, err := os.Open("input")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	view, err := filesystemMetadataForFile(context.Background(), file, func(*os.File) (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err = view.Close(); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if _, err = filesystemMetadataForFile(context.Background(), directory, func(*os.File) (bool, error) { return true, nil }); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
}

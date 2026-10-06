package hostdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestReplacementContextCancellation(t *testing.T) {
	source, err := os.CreateTemp(t.TempDir(), "source")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err = source.WriteString("original"); err != nil {
		t.Fatal(err)
	}
	for _, rooted := range []bool{false, true} {
		t.Run(map[bool]string{false: "path", true: "root"}[rooted], func(t *testing.T) {
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if rooted {
				r, e := PrepareReplacementAtContext(ctx, source, root, ".")
				if r != nil || !errors.Is(e, context.Canceled) {
					t.Fatal(r, e)
				}
			} else {
				r, e := PrepareReplacementContext(ctx, source, dir)
				if r != nil || !errors.Is(e, context.Canceled) {
					t.Fatal(r, e)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatal(entries, err)
			}
			if rooted {
				r, e := PrepareReplacementAtContext(t.Context(), source, root, ".")
				if e != nil {
					t.Fatal(e)
				}
				defer r.Close()
				if e = r.RestoreMetadataContext(ctx); !errors.Is(e, context.Canceled) {
					t.Fatal(e)
				}
				if e = r.RestoreMetadataContext(t.Context()); e != nil {
					t.Fatal(e)
				}
			} else {
				r, e := PrepareReplacementContext(t.Context(), source, dir)
				if e != nil {
					t.Fatal(e)
				}
				defer r.Close()
				if e = r.RestoreMetadataContext(ctx); !errors.Is(e, context.Canceled) {
					t.Fatal(e)
				}
				if e = r.RestoreMetadataContext(t.Context()); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
	if b, err := os.ReadFile(source.Name()); err != nil || string(b) != "original" {
		t.Fatal(string(b), err)
	}
}
func TestReplacementCleanupErrors(t *testing.T) {
	first, second := errors.New("permission cleanup"), errors.New("remove cleanup")
	calls := 0
	err := cleanupReplacement(func() error { calls++; return first }, func() error { calls++; return &os.PathError{Op: "remove", Path: "private", Err: os.ErrNotExist} }, func() error { calls++; return second })
	if calls != 3 || !errors.Is(err, first) || !errors.Is(err, second) || errors.Is(err, os.ErrNotExist) {
		t.Fatal(calls, err)
	}
}
func TestReplacementContextSteps(t *testing.T) {
	fault := errors.New("native call failed")
	ctx, cancel := context.WithCancel(t.Context())
	if err := replacementStep(ctx, func() error { cancel(); return fault }); !errors.Is(err, fault) || !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	called := false
	if err := replacementStep(ctx, func() error { called = true; return nil }); !errors.Is(err, context.Canceled) || called {
		t.Fatal(called, err)
	}
	if _, err := replacementValue(ctx, func() (int, error) { called = true; return 3, nil }); !errors.Is(err, context.Canceled) || called {
		t.Fatal(called, err)
	}
	for _, stop := range []string{"preflight", "clone", "open", "metadata"} {
		t.Run(stop, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if stop == "preflight" {
				cancel()
			}
			var held *os.File
			cloneCalls := 0
			f, err := prepareReplacementUsingContext(ctx, func() error {
				cloneCalls++
				if stop == "clone" {
					cancel()
				}
				return errors.ErrUnsupported
			}, func(e error) bool { return errors.Is(e, errors.ErrUnsupported) }, func(bool) (*os.File, error) {
				var e error
				held, e = os.Create(filepath.Join(t.TempDir(), "stage"))
				if stop == "open" {
					cancel()
				}
				return held, e
			}, func(*os.File) error {
				if stop == "metadata" {
					cancel()
				}
				return nil
			})
			if f != nil || !errors.Is(err, context.Canceled) {
				t.Fatal(f, err)
			}
			if stop == "preflight" && cloneCalls != 0 {
				t.Fatal("clone after cancellation")
			}
			if held != nil {
				if _, e := held.Stat(); !errors.Is(e, os.ErrClosed) {
					t.Fatal("staging handle leaked", e)
				}
			}
		})
	}
}
func TestReplacementBackupBeyondLegacyLimits(t *testing.T) {
	for _, input := range [][]byte{
		append(backupRecord(4, 8, ":large-sparse:$DATA", nil), backupExtent(1<<34, "x")...),
		backupRecord(4, 0, ":large:$DATA", bytes.Repeat([]byte{0xa5}, (8<<20)+1)),
		backupRecord(2, 0, "", bytes.Repeat([]byte{0x37}, (8<<20)+1)),
		bytes.Repeat(backupRecord(4, 0, ":many:$DATA", nil), 65537),
	} {
		var output bytes.Buffer
		if err := filterReplacementStreamsContext(t.Context(), bytes.NewReader(input), &output); err != nil || !bytes.Equal(input, output.Bytes()) {
			t.Fatal("stream limit/byte drift", len(input), err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := filterReplacementStreamsContext(ctx, bytes.NewReader(nil), io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

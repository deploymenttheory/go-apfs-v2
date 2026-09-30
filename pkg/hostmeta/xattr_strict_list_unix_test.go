//go:build darwin || linux

package hostmeta

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func strictListRangeError() error { return unix.ERANGE }

func TestStrictXattrListHost(t *testing.T) {
	for _, kind := range []string{"file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			if kind == "file" {
				if e := os.WriteFile(path, []byte("payload"), 0600); e != nil {
					t.Fatal(e)
				}
			} else {
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
			}
			f, e := os.Open(path)
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			strictSetXattr(t, path, "user.z", nil)
			strictSetXattr(t, path, "user.a", []byte{1})
			names, e := ListXattrNames(f, MaxXattrListSize)
			if e != nil {
				t.Fatal(e)
			}
			// Independent pathname query against the same stable fixture; no filtering.
			b := make([]byte, MaxXattrListSize)
			n, e := unix.Llistxattr(path, b)
			if e != nil {
				t.Fatal(e)
			}
			var want []string
			for start, i := 0, 0; i < n; i++ {
				if b[i] == 0 {
					want = append(want, string(b[start:i]))
					start = i + 1
				}
			}
			if !reflect.DeepEqual(names, want) || !slices.Contains(names, "user.z") || !slices.Contains(names, "user.a") {
				t.Fatal(names, want)
			}
			budget := 0
			for _, name := range names {
				budget += len(name) + 1
			}
			if got, e := ListXattrNames(f, budget); e != nil || !reflect.DeepEqual(got, names) {
				t.Fatal(got, e)
			}
			if got, e := ListXattrNames(f, budget-1); got != nil || !errors.Is(e, ErrXattrTooLarge) {
				t.Fatal(got, e)
			}
			moved := path + "-moved"
			if e := os.Rename(path, moved); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(path, []byte("decoy"), 0600); e != nil {
				t.Fatal(e)
			}
			strictSetXattr(t, path, "user.decoy", []byte{2})
			if got, e := ListXattrNames(f, budget); e != nil || !reflect.DeepEqual(got, names) {
				t.Fatal("followed pathname", got, e)
			}
			if kind == "file" {
				link := path + "-alias"
				if e := os.Link(moved, link); e != nil {
					t.Fatal(e)
				}
				strictSetXattr(t, link, "user.alias", []byte{3})
				if got, e := ListXattrNames(f, MaxXattrListSize); e != nil || !slices.Contains(got, "user.alias") {
					t.Fatal(got, e)
				}
				if b, e := io.ReadAll(f); e != nil || string(b) != "payload" {
					t.Fatal("offset/data changed", string(b), e)
				}
			}
			t.Logf("%s native names=%q budget=%d; held identity retained", kind, names, budget)
		})
	}
	if n, e := listVisibleXattrFD(-1, 100); n != nil || e == nil {
		t.Fatal(n, e)
	}
	// Pipes have no descriptor-backed xattr namespace; never turn that into empty.
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	if n, e := ListXattrNames(r, 100); n != nil || e == nil {
		t.Fatal(n, e)
	}
}

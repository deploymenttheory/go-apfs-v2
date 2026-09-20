package hostmeta

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReplacementDarwinACLFlagsAndBirthTime(t *testing.T) {
	replacementVariants(t, func(t *testing.T, prepare func(*os.File, string) (*testedReplacement, error)) {
		source := replacementSource(t, 0751)
		if output, err := exec.Command("/bin/chmod", "+a", "everyone allow read", source.Name()).CombinedOutput(); err != nil {
			t.Fatalf("chmod ACL: %v: %s", err, output)
		}
		if err := unix.Fchflags(int(source.Fd()), unix.UF_HIDDEN); err != nil {
			t.Fatal(err)
		}
		before, err := source.Stat()
		if err != nil {
			t.Fatal(err)
		}
		parent := t.TempDir()
		if output, err := exec.Command("/bin/chmod", "+a", "everyone allow read,file_inherit,directory_inherit", parent).CombinedOutput(); err != nil {
			t.Fatalf("parent ACL: %v: %s", err, output)
		}
		r, err := prepare(source, parent)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if _, err := r.File.WriteAt([]byte("changed"), 0); err != nil {
			t.Fatal(err)
		}
		if err := r.RestoreMetadata(); err != nil {
			t.Fatal(err)
		}
		after, err := r.File.Stat()
		if err != nil {
			t.Fatal(err)
		}
		old, new := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
		if old.Birthtimespec != new.Birthtimespec || old.Flags != new.Flags {
			t.Fatalf("birth time or flags changed: %#v -> %#v", old, new)
		}
		acl := func(path string) []byte {
			out, err := exec.Command("/bin/ls", "-lde", path).CombinedOutput()
			if err != nil {
				t.Fatalf("read ACL: %v: %s", err, out)
			}
			_, entries, _ := bytes.Cut(out, []byte{'\n'})
			return entries
		}
		if got, want := acl(r.File.Name()), acl(source.Name()); !bytes.Equal(got, want) || len(got) == 0 {
			t.Fatalf("ACL = %q; want %q", got, want)
		}

	})
}

func TestReplacementDarwinRejectsProtectedFile(t *testing.T) {
	source := replacementSource(t, 0600)
	if err := unix.Fchflags(int(source.Fd()), unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Chflags(source.Name(), 0) })
	path := filepath.Join(t.TempDir(), "replacement")
	if _, err := PrepareReplacement(source, filepath.Dir(path)); !errors.Is(err, ErrUnsupportedReplacement) {
		t.Fatalf("protected file: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement created: %v", err)
	}
}

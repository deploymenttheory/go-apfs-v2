//go:build darwin || linux

package hostmeta

import (
	"bytes"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReplacementPreservesXattrsAndOwnership(t *testing.T) {
	source := replacementSource(t, 0751)
	attrs := map[string][]byte{"user.small": []byte("value"), "user.empty": {}, "user.large": bytes.Repeat([]byte{42}, 4000)}
	for name, value := range attrs {
		if err := unix.Fsetxattr(int(source.Fd()), name, value, 0); err != nil {
			t.Fatal(err)
		}
	}
	before, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	r, err := PrepareReplacement(source, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.File.WriteAt([]byte("new"), 0); err != nil {
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
	if old.Uid != new.Uid || old.Gid != new.Gid {
		t.Fatal("ownership changed")
	}
	for name, want := range attrs {
		value := make([]byte, len(want)+1)
		n, err := unix.Fgetxattr(int(r.File.Fd()), name, value)
		if err != nil || !bytes.Equal(value[:n], want) {
			t.Fatalf("%s = %q, %v", name, value[:n], err)
		}
	}
	if got, err := os.ReadFile(source.Name()); err != nil || !bytes.HasPrefix(got, []byte("original")) {
		t.Fatalf("source changed: %q, %v", got, err)
	}
}

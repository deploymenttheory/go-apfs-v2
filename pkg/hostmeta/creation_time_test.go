package hostmeta

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestSetCreationTimeInvalidFiles(t *testing.T) {
	when := time.Unix(946684800, 123456789)
	if err := SetCreationTime(nil, when); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil file: %v", err)
	}
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := SetCreationTime(dir, when); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("directory: %v", err)
	}
	file, err := os.Create(filepath.Join(t.TempDir(), "closed"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := SetCreationTime(file, when); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed file: %v", err)
	}
}

func TestSetCreationTimeUnsupportedHost(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Darwin supports creation-time updates")
	}
	file := replacementSource(t, 0640)
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := SetCreationTime(file, time.Unix(946684800, 123456789)); !errors.Is(err, ErrCreationTimeUnsupported) {
		t.Fatalf("unsupported host: %v", err)
	}
	after, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("unsupported update changed the source")
	}
}

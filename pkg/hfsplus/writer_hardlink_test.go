package hfsplus

import (
	"bytes"
	"testing"
)

// TestWriteHardLinks round-trips several names for one file: the content must
// be stored once, and every name must read it back.
func TestWriteHardLinks(t *testing.T) {
	content := []byte("shared content, stored once\n")
	other := []byte("a different file\n")

	root := &Entry{Children: []*Entry{
		{Name: "a.txt", Mode: 0o644, Data: content, LinkGroup: 1},
		{Name: "b.txt", Mode: 0o644, Data: content, LinkGroup: 1},
		{Name: "c.txt", Mode: 0o644, Data: content, LinkGroup: 1},
		{Name: "plain.txt", Mode: 0o644, Data: other},
	}}

	w := &memWriterAt{}
	if err := CreateImage(w, 0, "LINKS", root, nil); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}

	v, err := New(bytes.NewReader(w.b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		got, err := v.ReadFile(name)
		if err != nil {
			t.Errorf("ReadFile(%s): %v", name, err)
			continue
		}
		if !bytes.Equal(got, content) {
			t.Errorf("%s = %q, want %q", name, got, content)
		}
		info, err := v.Stat(name)
		if err != nil {
			t.Errorf("Stat(%s): %v", name, err)
			continue
		}
		if info.Size() != int64(len(content)) {
			t.Errorf("%s: size = %d, want %d", name, info.Size(), len(content))
		}
	}

	if got, err := v.ReadFile("plain.txt"); err != nil || !bytes.Equal(got, other) {
		t.Errorf("plain.txt = %q, err=%v", got, err)
	}

	// The private metadata directory must not appear in a listing: it is
	// volume housekeeping, not a directory entry a caller should walk into.
	entries, err := v.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() == metadataDirName {
			t.Error("the private metadata directory is visible in the root listing")
		}
	}
}

// TestWriteHardLinksStoreContentOnce is the point of the feature: three names
// for a megabyte must cost a megabyte, not three.
func TestWriteHardLinksStoreContentOnce(t *testing.T) {
	big := bytes.Repeat([]byte("0123456789ABCDEF"), 64*1024) // 1 MiB

	linked := &Entry{Children: []*Entry{
		{Name: "a.bin", Mode: 0o644, Data: big, LinkGroup: 7},
		{Name: "b.bin", Mode: 0o644, Data: big, LinkGroup: 7},
		{Name: "c.bin", Mode: 0o644, Data: big, LinkGroup: 7},
	}}
	copies := &Entry{Children: []*Entry{
		{Name: "a.bin", Mode: 0o644, Data: big},
		{Name: "b.bin", Mode: 0o644, Data: big},
		{Name: "c.bin", Mode: 0o644, Data: big},
	}}

	build := func(root *Entry) int {
		w := &memWriterAt{}
		if err := CreateImage(w, 0, "SIZE", root, nil); err != nil {
			t.Fatalf("CreateImage: %v", err)
		}
		return len(w.b)
	}

	linkedSize, copiesSize := build(linked), build(copies)
	if linkedSize >= copiesSize-int(len(big)) {
		t.Errorf("linked image is %d bytes and the copied one %d; the content was not shared",
			linkedSize, copiesSize)
	}
}

// TestWriteHardLinkAttributes checks that attributes follow the content rather
// than a name. A reader resolving any name lands on the indirect node, so that
// is where they have to live.
func TestWriteHardLinkAttributes(t *testing.T) {
	attrs := map[string][]byte{"com.example.test": []byte("value42")}
	root := &Entry{Children: []*Entry{
		{Name: "a.txt", Mode: 0o644, Data: []byte("x\n"), Xattrs: attrs, LinkGroup: 3},
		{Name: "b.txt", Mode: 0o644, Data: []byte("x\n"), Xattrs: attrs, LinkGroup: 3},
	}}

	w := &memWriterAt{}
	if err := CreateImage(w, 0, "LINKATTR", root, nil); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}
	v, err := New(bytes.NewReader(w.b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, name := range []string{"a.txt", "b.txt"} {
		got, err := v.Xattrs(name)
		if err != nil {
			t.Errorf("Xattrs(%s): %v", name, err)
			continue
		}
		if string(got["com.example.test"]) != "value42" {
			t.Errorf("%s attributes = %v", name, got)
		}
	}
}

// TestWriteSingleLinkGroupIsNotALink checks a group of one stays an ordinary
// file: a walker only assigns a group when it saw several names, but a caller
// building a tree by hand might not.
func TestWriteSingleLinkGroupIsNotALink(t *testing.T) {
	root := &Entry{Children: []*Entry{
		{Name: "only.txt", Mode: 0o644, Data: []byte("alone\n"), LinkGroup: 9},
	}}
	w := &memWriterAt{}
	if err := CreateImage(w, 0, "ONE", root, nil); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}
	v, err := New(bytes.NewReader(w.b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got, err := v.ReadFile("only.txt"); err != nil || string(got) != "alone\n" {
		t.Errorf("only.txt = %q, err=%v", got, err)
	}
	entries, err := v.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("root has %d entries, want 1: a lone group should not create a private directory", len(entries))
	}
}

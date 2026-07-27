// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// TestCreateContainerXattrRoundTrip writes extended attributes and reads them
// back through pkg/apfs. Until now the writer emitted only the one attribute it
// uses itself for symbolic-link targets, so every attribute in a source tree
// was dropped.
func TestCreateContainerXattrRoundTrip(t *testing.T) {
	want := map[string][]byte{
		"com.apple.quarantine":  []byte("0081;00000000;;"),
		"com.apple.metadata:_x": bytes.Repeat([]byte{0xfe}, 300),
		"user.empty":            {},
		"user.one":              {0x01},
		// The largest value the format embeds, to pin the boundary.
		"user.largest": bytes.Repeat([]byte("x"), 3804),
	}

	vol := openVolume(t, &apfswrite.CreateOptions{
		VolumeName: "XATTR",
		Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
			{Name: "file.txt", Data: []byte("content\n"), Xattrs: want},
			{Name: "plain.txt", Data: []byte("no attributes\n")},
		}},
	})

	got, err := vol.Xattrs("file.txt")
	if err != nil {
		t.Fatalf("Xattrs: %v", err)
	}
	for name, value := range want {
		read, ok := got[name]
		if !ok {
			t.Errorf("%s missing from the volume", name)
			continue
		}
		if !bytes.Equal(read, value) {
			t.Errorf("%s: read %d bytes, want %d", name, len(read), len(value))
		}
	}

	// A file given none must have none, so an attribute cannot leak between
	// entries through the shared record builder.
	plain, err := vol.Xattrs("plain.txt")
	if err != nil {
		t.Fatalf("Xattrs(plain.txt): %v", err)
	}
	if len(plain) != 0 {
		t.Errorf("a file with no attributes has %v", plain)
	}
}

// TestCreateContainerXattrsOnEveryEntryKind checks attributes survive on a
// directory and a symbolic link too, not just a regular file. A symbolic link
// is the interesting one: its target is itself stored as an attribute, so the
// writer has to emit both without them colliding.
func TestCreateContainerXattrsOnEveryEntryKind(t *testing.T) {
	marker := []byte("marker")

	vol := openVolume(t, &apfswrite.CreateOptions{
		VolumeName: "KINDS",
		Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
			{Name: "file.txt", Data: []byte("content\n"), Xattrs: map[string][]byte{"user.on_file": marker}},
			{Name: "link", Mode: os.ModeSymlink, Data: []byte("file.txt"), Xattrs: map[string][]byte{"user.on_link": marker}},
			{Name: "dir", Mode: os.ModeDir, Xattrs: map[string][]byte{"user.on_dir": marker}, Children: []*apfswrite.Entry{
				{Name: "nested.txt", Data: []byte("nested\n")},
			}},
		}},
	})

	for path, name := range map[string]string{
		"file.txt": "user.on_file",
		"link":     "user.on_link",
		"dir":      "user.on_dir",
	} {
		attrs, err := vol.Xattrs(path)
		if err != nil {
			t.Errorf("Xattrs(%s): %v", path, err)
			continue
		}
		if !bytes.Equal(attrs[name], marker) {
			t.Errorf("%s: %s = %q, want %q", path, name, attrs[name], marker)
		}
	}

	// The link must still resolve: its own target attribute is intact.
	target, err := vol.Readlink("link")
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if target != "file.txt" {
		t.Errorf("link target = %q, want file.txt", target)
	}
}

// TestCreateContainerSetsAttributeDrivenInodeFlags checks the inode flags that
// must agree exactly with which attributes are present. A checker compares each
// flag against its attribute and complains either way, so they can be neither
// set optimistically nor left alone.
func TestCreateContainerSetsAttributeDrivenInodeFlags(t *testing.T) {
	const (
		hasSecurityEA = 0x00000040
		hasFinderInfo = 0x00000100
		noRsrcFork    = 0x00008000
	)

	vol := openVolume(t, &apfswrite.CreateOptions{
		VolumeName: "FLAGS",
		Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
			{Name: "plain.txt", Data: []byte("plain\n")},
			{Name: "acl.txt", Data: []byte("acl\n"), Xattrs: map[string][]byte{
				"com.apple.system.Security": []byte("acl bytes"),
			}},
			{Name: "finder.txt", Data: []byte("finder\n"), Xattrs: map[string][]byte{
				"com.apple.FinderInfo": make([]byte, 32),
			}},
			{Name: "both.txt", Data: []byte("both\n"), Xattrs: map[string][]byte{
				"com.apple.system.Security": []byte("acl bytes"),
				"com.apple.FinderInfo":      make([]byte, 32),
				"user.plain":                []byte("ignored by the flags"),
			}},
		}},
	})

	cases := map[string]uint64{
		"plain.txt":  0,
		"acl.txt":    hasSecurityEA,
		"finder.txt": hasFinderInfo,
		"both.txt":   hasSecurityEA | hasFinderInfo,
	}
	for path, want := range cases {
		entry, err := vol.FileEntryByPath(path)
		if err != nil {
			t.Fatalf("FileEntryByPath(%s): %v", path, err)
		}
		flags := entry.Inode.Flags

		if got := flags & (hasSecurityEA | hasFinderInfo); got != want {
			t.Errorf("%s: attribute flags = %#x, want %#x", path, got, want)
		}
		// Every one of these has no resource fork, and must say so: a checker
		// reads the flag's absence as a claim that a fork exists.
		if flags&noRsrcFork == 0 {
			t.Errorf("%s: does not claim INODE_NO_RSRC_FORK", path)
		}
	}
}

// TestCreateContainerRejectsUnwritableXattrs checks the cases that cannot be
// written fail loudly rather than being dropped or truncated.
func TestCreateContainerRejectsUnwritableXattrs(t *testing.T) {
	cases := []struct {
		name     string
		xattrs   map[string][]byte
		contains string
	}{
		{
			"a value too large to embed",
			map[string][]byte{"user.big": bytes.Repeat([]byte("x"), 3805)},
			"need a data stream",
		},
		{
			// fsck_apfs: "com.apple.ResourceFork is expected to be stream
			// based". Embedding one produces an image macOS calls corrupt.
			"a resource fork, which must be stream based",
			map[string][]byte{"com.apple.ResourceFork": []byte("fork bytes")},
			"must be stored as a data stream",
		},
		{
			// apfsck: "is not compressed but has decmpfs xattr". A decmpfs
			// attribute declares content this writer does not produce.
			"a decmpfs attribute, which declares compressed content",
			map[string][]byte{"com.apple.decmpfs": []byte("fpmc____________")},
			"stores content uncompressed",
		},
		{
			"the reserved symlink attribute",
			map[string][]byte{"com.apple.fs.symlink": []byte("elsewhere")},
			"the writer emits itself",
		},
		{
			"an empty name",
			map[string][]byte{"": []byte("value")},
			"empty name",
		},
		{
			"a name containing NUL",
			map[string][]byte{"user.a\x00b": []byte("value")},
			"contains a NUL",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := apfswrite.CreateContainer(&memImage{}, 32*1024*1024, &apfswrite.CreateOptions{
				VolumeName: "REJECT",
				Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
					{Name: "file.txt", Data: []byte("content\n"), Xattrs: tc.xattrs},
				}},
			})
			if err == nil {
				t.Fatal("CreateContainer accepted it")
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Errorf("error = %q, want it to mention %q", err, tc.contains)
			}
		})
	}
}

// TestCreateContainerXattrsAreDeterministic checks attributes do not disturb
// reproducibility. They arrive in a map, whose iteration order is random, so
// the records must be sorted before they are written.
func TestCreateContainerXattrsAreDeterministic(t *testing.T) {
	opts := func() *apfswrite.CreateOptions {
		return &apfswrite.CreateOptions{
			VolumeName: "DETERMINISM",
			Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
				{Name: "file.txt", Data: []byte("content\n"), Xattrs: map[string][]byte{
					"user.a": []byte("1"), "user.b": []byte("2"), "user.c": []byte("3"),
					"user.d": []byte("4"), "user.e": []byte("5"), "user.f": []byte("6"),
				}},
			}},
		}
	}

	first := buildImage(t, opts())
	for range 5 {
		if !bytes.Equal(first, buildImage(t, opts())) {
			t.Fatal("two builds with the same attributes differ; map order is reaching the image")
		}
	}
}

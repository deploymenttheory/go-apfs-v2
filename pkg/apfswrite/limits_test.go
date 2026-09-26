// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// The tests in this file measure the writer's capacity limits rather than
// assume them. Each one searches for the boundary, asserts what it observes
// today, and reports the value as a LIMIT line (test output and, under GitHub
// Actions, the step summary). When a limit is lifted its test is updated to
// assert the new behaviour.

var limitSummaryHeaderWritten bool

// reportLimit records a measured limit.
func reportLimit(t *testing.T, name string, format string, args ...any) {
	t.Helper()
	value := fmt.Sprintf(format, args...)
	t.Logf("LIMIT %s = %s", name, value)

	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	if !limitSummaryHeaderWritten {
		fmt.Fprintf(f, "\n### apfswrite measured limits (%s/%s)\n", runtime.GOOS, runtime.GOARCH)
		limitSummaryHeaderWritten = true
	}
	fmt.Fprintf(f, "- `%s`: %s\n", name, value)
}

// flatTree returns a root holding n files named by name(i), each with a few
// bytes of distinct content.
func flatTree(n int, name func(i int) string) *apfswrite.Entry {
	children := make([]*apfswrite.Entry, n)
	for i := range children {
		children[i] = &apfswrite.Entry{
			Name: name(i),
			Data: []byte(fmt.Sprintf("file %d\n", i)),
		}
	}
	return &apfswrite.Entry{Children: children}
}

// build writes a container for root and returns the image, or the writer's
// error.
func build(root *apfswrite.Entry, snapshots []apfswrite.SnapshotSpec) (*memImage, error) {
	img := &memImage{}
	err := apfswrite.CreateContainer(img, 0, &apfswrite.CreateOptions{
		VolumeName: "Limits",
		Root:       root,
		Snapshots:  snapshots,
	})
	return img, err
}

// readsBack opens img with the reader and reports the first way in which its
// contents differ from root. Unlike walkAndAssert it returns the problem, so a
// caller can search for the point at which images stop being readable.
func readsBack(img *memImage, root *apfswrite.Entry) error {
	container, err := apfs.Open(img, &apfs.OpenOptions{})
	if err != nil {
		return fmt.Errorf("open container: %w", err)
	}
	volumes, err := container.Volumes()
	if err != nil {
		return fmt.Errorf("volumes: %w", err)
	}
	if len(volumes) != 1 {
		return fmt.Errorf("volume count = %d, want 1", len(volumes))
	}
	want := collectWants(root)
	seen := 0
	err = fs.WalkDir(volumes[0], ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		w, ok := want[p]
		if !ok {
			return fmt.Errorf("unexpected path %q", p)
		}
		seen++
		if w.isDir {
			return nil
		}
		f, err := volumes[0].Open(p)
		if err != nil {
			return fmt.Errorf("open %q: %w", p, err)
		}
		defer f.Close()
		got, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("read %q: %w", p, err)
		}
		if sha256.Sum256(got) != sha256.Sum256(w.data) {
			return fmt.Errorf("content of %q differs", p)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if seen != len(want) {
		return fmt.Errorf("walk visited %d paths, want %d", seen, len(want))
	}
	return nil
}

// largestAccepted binary-searches [lo, hi] for the largest n that accepts(n)
// reports true for. accepts(lo) must be true and accepts(hi) false.
func largestAccepted(t *testing.T, lo, hi int, accepts func(n int) bool) int {
	t.Helper()
	if !accepts(lo) {
		t.Fatalf("expected %d to be accepted", lo)
	}
	if accepts(hi) {
		t.Fatalf("expected %d to be rejected; the limit may have been lifted", hi)
	}
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		if accepts(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo
}

// TestLimitFSTreeFileCount measures how many small, shortly named files a
// single flat directory can hold before the writer refuses the file-system
// tree. This is the shape an outside review reported failing at about 850.
func TestLimitFSTreeFileCount(t *testing.T) {
	if testing.Short() {
		t.Skip("searches thousands of files")
	}
	name := func(i int) string { return fmt.Sprintf("file%08d", i) } // 12 bytes
	var lastErr error
	n := largestAccepted(t, 1, 20000, func(n int) bool {
		_, err := build(flatTree(n, name), nil)
		if err != nil {
			lastErr = err
		}
		return err == nil
	})

	root := flatTree(n, name)
	img, err := build(root, nil)
	if err != nil {
		t.Fatalf("rebuild at %d: %v", n, err)
	}
	if err := readsBack(img, root); err != nil {
		t.Fatalf("largest accepted image (%d files) does not read back: %v", n, err)
	}
	_, err = build(flatTree(n+1, name), nil)
	if err == nil || !strings.Contains(err.Error(), "file-system tree needs") {
		t.Fatalf("at %d files: err = %v, want the file-system tree leaf limit", n+1, err)
	}
	reportLimit(t, "fs-tree small files (12-byte names)", "%d files; %d rejected with %q", n, n+1, lastErr)
}

// TestLimitFSTreeLongNames repeats the file-count search with 255-byte names.
// Directory-entry keys then approach 270 bytes, and the file-system tree's
// index root holds one such key per leaf, so the root fills long before the
// 64-leaf cap. It checks every image the writer accepts for readability: before
// the index size was checked, 166 such files produced an image whose index root
// had silently overrun its block and which could not be read back.
func TestLimitFSTreeLongNames(t *testing.T) {
	if testing.Short() {
		t.Skip("builds hundreds of images")
	}
	name := func(i int) string {
		prefix := fmt.Sprintf("%08d", i)
		return prefix + strings.Repeat("n", 255-len(prefix))
	}
	for n := 1; n <= 5000; n++ {
		root := flatTree(n, name)
		img, err := build(root, nil)
		if err != nil {
			if !strings.Contains(err.Error(), "file-system tree index") {
				t.Fatalf("at %d files: err = %v, want the index-root size limit", n, err)
			}
			reportLimit(t, "fs-tree long names (255-byte names)", "%d files; %d rejected with %q", n-1, n, err)
			return
		}
		if err := readsBack(img, root); err != nil {
			reportLimit(t, "fs-tree long names (255-byte names)", "%d files accepted but unreadable: %v", n, err)
			t.Fatalf("writer accepted %d long-named files but produced an unreadable image: %v", n, err)
		}
	}
	t.Fatalf("5000 long-named files were all accepted; the limit may have been lifted")
}

// TestLimitSnapshotNonEmptyFiles measures how many non-empty files a volume
// can hold and still take a snapshot. Each such file owns one extentref record,
// and snapshots are refused once those records outgrow a single leaf.
func TestLimitSnapshotNonEmptyFiles(t *testing.T) {
	name := func(i int) string { return fmt.Sprintf("file%08d", i) }
	snaps := snapshotNames(1)
	var lastErr error
	n := largestAccepted(t, 1, 2000, func(n int) bool {
		_, err := build(flatTree(n, name), snaps)
		if err != nil {
			lastErr = err
		}
		return err == nil
	})

	root := flatTree(n, name)
	img, err := build(root, snaps)
	if err != nil {
		t.Fatalf("rebuild at %d: %v", n, err)
	}
	if err := readsBack(img, root); err != nil {
		t.Fatalf("largest accepted snapshot image (%d files) does not read back: %v", n, err)
	}
	if !strings.Contains(lastErr.Error(), "2-level extentref tree") {
		t.Fatalf("rejection is %q, want the extentref snapshot limit", lastErr)
	}
	reportLimit(t, "snapshot non-empty files", "%d files; %d rejected with %q", n, n+1, lastErr)

	// Without the snapshot the same file count is accepted, so the snapshot is
	// what imposes this limit.
	if _, err := build(flatTree(n+1, name), nil); err != nil {
		t.Fatalf("%d files without a snapshot: %v", n+1, err)
	}
}

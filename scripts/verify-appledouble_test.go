//go:build ignore

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSourceHashesRetainsNestedRegressionFixtures(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "codec.go")
	seed := filepath.Join(root, "testdata", "fuzz", "FuzzFilesystemRemove", "regression")
	if err := os.MkdirAll(filepath.Dir(seed), 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{source, seed} {
		if err := os.WriteFile(name, []byte("abc"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	hashes, err := sourceHashes([]string{root, source})
	if err != nil {
		t.Fatal(err)
	}
	const abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if len(hashes) != 2 || hashes[filepath.ToSlash(source)] != abc || hashes[filepath.ToSlash(seed)] != abc {
		t.Fatalf("source and nested regression must both be hashed exactly: %v", hashes)
	}
	if err := os.WriteFile(seed, []byte("changed"), 0644); err != nil {
		t.Fatal(err)
	}
	changed, err := sourceHashes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if changed[filepath.ToSlash(seed)] == hashes[filepath.ToSlash(seed)] || changed[filepath.ToSlash(source)] != abc {
		t.Fatalf("nested fixture change not reflected independently: %v", changed)
	}
}

func TestSourceHashesRejectsMissingEvidence(t *testing.T) {
	if hashes, err := sourceHashes([]string{filepath.Join(t.TempDir(), "missing")}); err == nil || hashes != nil {
		t.Fatalf("missing evidence must fail: %v, %v", hashes, err)
	}
}

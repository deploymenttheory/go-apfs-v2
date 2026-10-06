//go:build ignore

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestComparisonGateRejectsIncompleteTranscripts(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"skip", `{"Action":"skip","Test":"required"}`},
		{"fail", `{"Action":"fail","Test":"required"}`},
		{"unfinished", `{"Action":"pass","Test":"required"}`},
		{"invalid", `{`},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "input.jsonl")
			if err := os.WriteFile(path, []byte(tc.body+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := transcripts([]string{path}, filepath.Join(dir, "out.jsonl")); err == nil {
				t.Fatal("accepted incomplete qualification")
			}
		})
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "input.jsonl")
	body := "{\"Action\":\"pass\",\"Test\":\"required\"}\n{\"Action\":\"pass\"}\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	n, names, err := transcripts([]string{path}, filepath.Join(dir, "out.jsonl"))
	if err != nil || n != 1 || !names["required"] {
		t.Fatalf("n=%d names=%v err=%v", n, names, err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "out.jsonl"))
	if err != nil || string(got) != body {
		t.Fatalf("raw transcript altered: %q %v", got, err)
	}
}

func TestComparisonGateCoverageMerge(t *testing.T) {
	const block = "github.com/deploymenttheory/go-apfs-v2/pkg/apfs/example.go:1.1,2.1"
	for _, tc := range []struct{ name, first, second string }{
		{"header", "mode: set\n", "mode: atomic\n"},
		{"fields", "mode: atomic\nbad\n", "mode: atomic\n"},
		{"negative-count", "mode: atomic\n" + block + " -1 0\n", "mode: atomic\n"},
		{"negative-hits", "mode: atomic\n" + block + " 1 -1\n", "mode: atomic\n"},
		{"changed-statements", "mode: atomic\n" + block + " 1 0\n", "mode: atomic\n" + block + " 2 1\n"},
		{"invalid-count", "mode: atomic\n" + block + " x 0\n", "mode: atomic\n"},
		{"invalid-hits", "mode: atomic\n" + block + " 1 x\n", "mode: atomic\n"},
		{"missing-location", "mode: atomic\nmissing 1 1\n", "mode: atomic\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			var paths []string
			for i, body := range []string{tc.first, tc.second} {
				p := filepath.Join(dir, []string{"a", "b"}[i])
				paths = append(paths, p)
				if err := os.WriteFile(p, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := mergeProfiles(paths, filepath.Join(dir, "out")); err == nil {
				t.Fatal("accepted corrupt coverage")
			}
		})
	}
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "a"), filepath.Join(dir, "b")}
	for i, p := range paths {
		hits := "0"
		if i == 1 {
			hits = "1"
		}
		if err := os.WriteFile(p, []byte("mode: atomic\n"+block+" 3 "+hits+"\n"+block+"0 0 0\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "out")
	totals, err := mergeProfiles(paths, out)
	if err != nil || totals["pkg/apfs/example.go"] != (count{3, 3}) {
		t.Fatalf("totals=%v err=%v", totals, err)
	}
	b, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(b), block+" 3 1") {
		t.Fatalf("merged output=%q err=%v", b, err)
	}
}

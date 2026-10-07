//go:build ignore

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func nativeBodies(t *testing.T) (functionManifest, map[string][]byte) {
	t.Helper()
	dir := filepath.Join("..", pinned)
	if _, err := os.Stat(dir); err != nil {
		dir = pinned
	}
	raw, err := os.ReadFile(filepath.Join(dir, "functions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m functionManifest
	if err = json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	sources := map[string][]byte{}
	for _, f := range m.Entries {
		if _, ok := sources[f.File]; ok {
			continue
		}
		raw, err = os.ReadFile(filepath.Join(dir, f.File+".gz"))
		if err != nil {
			t.Fatal(err)
		}
		z, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(z)
		if err != nil {
			t.Fatal(err)
		}
		if err = z.Close(); err != nil {
			t.Fatal(err)
		}
		sources[f.File] = b
	}
	return m, sources
}
func TestPinnedPolicyBodies(t *testing.T) {
	m, sources := nativeBodies(t)
	unit, ranges, err := translationUnit(m, sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 30 {
		t.Fatal(len(ranges))
	}
	for _, f := range m.Entries {
		body := sources[f.File][f.Start:f.End]
		if !bytes.Contains(unit, body) {
			t.Fatal("changed source body", f.Name)
		}
		if f.Brace > 0 {
			r := ranges[f.Name]
			if unit[r.Start] != '{' || unit[r.End] != '}' {
				t.Fatal("incorrect body bounds", f.Name)
			}
		}
	}
	cases := []struct {
		name   string
		change func(*functionManifest)
	}{
		{"schema", func(m *functionManifest) { m.Schema = 2 }},
		{"release", func(m *functionManifest) { m.Release = "other" }},
		{"missing", func(m *functionManifest) { m.Entries = m.Entries[:30] }},
		{"duplicate", func(m *functionManifest) { m.Entries[1] = m.Entries[0] }},
		{"empty name", func(m *functionManifest) { m.Entries[1].Name = "" }},
		{"negative", func(m *functionManifest) { m.Entries[1].Start = -1 }},
		{"reversed", func(m *functionManifest) { m.Entries[1].End = m.Entries[1].Start }},
		{"outside", func(m *functionManifest) { m.Entries[1].End = 1 << 30 }},
		{"hash", func(m *functionManifest) { m.Entries[1].SHA256 = strings.Repeat("0", 64) }},
		{"signature", func(m *functionManifest) { m.Entries[1].Name = "wrong" }},
		{"brace", func(m *functionManifest) { m.Entries[1].Brace++ }},
		{"brace before", func(m *functionManifest) { m.Entries[1].Brace = m.Entries[1].Start - 1 }},
		{"brace after", func(m *functionManifest) { m.Entries[1].Brace = m.Entries[1].End }},
		{"missing context", func(m *functionManifest) { m.Entries[0].Name = "other" }},
		{"context body", func(m *functionManifest) { m.Entries[1].Brace = 0 }},
		{"truncated", func(m *functionManifest) {
			f := &m.Entries[1]
			f.End--
			f.SHA256 = digest(sources[f.File][f.Start:f.End])
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			copyM := m
			copyM.Entries = append([]fragment(nil), m.Entries...)
			c.change(&copyM)
			if _, _, err := translationUnit(copyM, sources); err == nil {
				t.Fatal("accepted malformed full-body evidence")
			}
		})
	}
}
func TestFullBodyASTQualification(t *testing.T) {
	expected := map[string]bodyRange{"policy": {10, 20}}
	compound := astNode{Kind: "CompoundStmt", Inner: []astNode{{Kind: "ReturnStmt", Inner: []astNode{{Kind: "IntegerLiteral"}}}}}
	compound.Range.Begin.Offset = 10
	compound.Range.End.Offset = 20
	function := astNode{Kind: "FunctionDecl", Name: "policy", Inner: []astNode{compound}}
	root := astNode{Kind: "TranslationUnitDecl", Inner: []astNode{{Kind: "FunctionDecl", Name: "policy"}, function}}
	got, err := qualifyAST(root, expected)
	if err != nil || got["policy"] != 2 {
		t.Fatal(got, err)
	}
	for _, c := range []struct {
		name string
		root astNode
	}{
		{"header only", astNode{Kind: "FunctionDecl", Name: "policy"}},
		{"wrong function", astNode{Kind: "FunctionDecl", Name: "other", Inner: []astNode{compound}}},
		{"duplicate", astNode{Inner: []astNode{function, function}}},
		{"empty", astNode{Kind: "FunctionDecl", Name: "policy", Inner: []astNode{{Kind: "CompoundStmt"}}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := qualifyAST(c.root, expected); err == nil {
				t.Fatal("accepted incomplete body")
			}
		})
	}
	empty := compound
	empty.Inner = nil
	function.Inner = []astNode{empty}
	if _, err := qualifyAST(function, expected); err == nil {
		t.Fatal("accepted empty matching body")
	}
}
func TestSDKDependencyPaths(t *testing.T) {
	got := dependencyPaths("output.o: /SDK/one.h \\\n /SDK/has\\ space/two.h\tfile.h")
	want := []string{"/SDK/one.h", "/SDK/has space/two.h", "file.h"}
	if len(got) != len(want) {
		t.Fatal(got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatal(got)
		}
	}
	if len(dependencyPaths("target: \n\t")) != 0 {
		t.Fatal("empty dependency list")
	}
}

//go:build ignore

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These are malformed-input tests for the harness, not native behavior fixtures.
func TestInventoryRejectsMalformedCaptures(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(original) == "scripts" {
		if err = os.Chdir(".."); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Chdir(original); err != nil {
				t.Error(err)
			}
		})
	}
	expected, _, err := readSpec("testdata/appledouble/native/pathname-authorization-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	makeCapture := func() captureRecord {
		c := captureRecord{Schema: 1, Expected: len(expected)}
		for _, spec := range expected {
			r := record{ID: spec.ID, Family: spec.Family, Profile: spec.Profile, Operation: spec.Operation, Route: spec.Route, Qualification: "captured", Cleanup: true, User: strings.Repeat("00", 16), Group: strings.Repeat("00", 16), Result: result{Groups: []uint32{20}}}
			for _, name := range []string{"root", "a", "a/b", "a/b/file", "a/b/stage", "a/c", "a/c/file"} {
				r.Before = append(r.Before, entry{Name: name, State: state{Captured: true}})
			}
			c.Cases = append(c.Cases, r)
		}
		return c
	}
	if err := inventory(makeCapture(), expected); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*captureRecord)
	}{
		{"missing", func(c *captureRecord) { c.Cases = c.Cases[1:] }},
		{"duplicate", func(c *captureRecord) { c.Cases[1] = c.Cases[0] }},
		{"unknown", func(c *captureRecord) { c.Cases[0].ID = "unknown" }},
		{"operation", func(c *captureRecord) { c.Cases[0].Operation = "invented" }},
		{"route", func(c *captureRecord) { c.Cases[0].Route = "invented" }},
		{"profile", func(c *captureRecord) { c.Cases[0].Profile = "invented" }},
		{"partial", func(c *captureRecord) { c.Unavailable = 1 }},
		{"cleanup", func(c *captureRecord) { c.Cases[0].Cleanup = false }},
		{"setup", func(c *captureRecord) { c.Cases[0].Result.SetupErr = 13 }},
		{"control", func(c *captureRecord) { c.Cases[0].Control.Errno = 13 }},
		{"missing-node", func(c *captureRecord) { c.Cases[0].Before = c.Cases[0].Before[1:] }},
		{"duplicate-node", func(c *captureRecord) { c.Cases[0].Before[1] = c.Cases[0].Before[0] }},
		{"unknown-node", func(c *captureRecord) { c.Cases[0].Before[0].Name = "unknown" }},
		{"uncaptured-security", func(c *captureRecord) { c.Cases[0].Before[0].State.Captured = false }},
		{"invalid-uuid", func(c *captureRecord) { c.Cases[0].User = "00" }},
		{"uncaptured-process", func(c *captureRecord) { c.Cases[0].Result.ProcessErr = 1 }},
		{"uncaptured-groups", func(c *captureRecord) { c.Cases[0].Result.Groups = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := makeCapture()
			tc.edit(&c)
			if err := inventory(c, expected); err == nil {
				t.Fatal("malformed capture accepted")
			}
		})
	}
}

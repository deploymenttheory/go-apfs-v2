//go:build ignore

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"testing"
)

func TestNativeCrashCleanupPartialOrder(t *testing.T) {
	decode := func(raw string) map[string]any {
		var e map[string]any
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			t.Fatal(err)
		}
		return e
	}
	fault := func() map[string]any {
		return decode(`{"thread":"caller","operation":"fstatfs","fork":false,"argument":0,"result":-1,"errno":5,"injected":true}`)
	}
	closeCaller := func() map[string]any {
		return decode(`{"thread":"caller","operation":"close","fork":false,"argument":0,"result":0,"errno":0,"injected":false}`)
	}
	syncFork := func() map[string]any {
		return decode(`{"thread":"worker","operation":"fsync","fork":true,"argument":0,"result":0,"errno":0,"injected":false}`)
	}
	closeFork := func() map[string]any {
		return decode(`{"thread":"worker","operation":"close","fork":true,"argument":0,"result":0,"errno":0,"injected":false}`)
	}
	native := trial{ProcessSignal: 11, Fault: "fstatfs"}
	for _, events := range [][]map[string]any{{fault(), closeCaller(), syncFork(), closeFork()}, {fault(), syncFork(), closeCaller(), closeFork()}, {fault(), syncFork(), closeFork(), closeCaller()}, {fault(), syncFork(), closeFork()}} {
		got, e := normalizeCrashTrace(native, events)
		if e != nil || len(got) != 2 || got[1]["operation"] != "qualified-signal-11-cleanup" {
			t.Fatal(got, e)
		}
	}
	invalid := map[string][]map[string]any{
		"missing-fault": {syncFork(), closeFork()}, "duplicate-fault": {fault(), fault(), syncFork(), closeFork()}, "missing-sync": {fault(), closeFork()}, "missing-close": {fault(), syncFork()}, "duplicate-worker": {fault(), syncFork(), closeFork(), closeFork()}, "duplicate-caller": {fault(), closeCaller(), closeCaller(), syncFork(), closeFork()},
	}
	for name, events := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, e := normalizeCrashTrace(native, events); e == nil {
				t.Fatal("accepted unqualified trace")
			}
		})
	}
	for _, edit := range []struct {
		field string
		value any
	}{{"thread", "worker"}, {"result", float64(0)}, {"errno", float64(1)}, {"injected", false}} {
		event := fault()
		event[edit.field] = edit.value
		if _, e := normalizeCrashTrace(native, []map[string]any{event, syncFork(), closeFork()}); e == nil {
			t.Fatal("invalid volume fault accepted", edit)
		}
	}
	for _, edit := range []struct {
		field string
		value any
	}{{"argument", float64(1)}, {"result", float64(-1)}, {"errno", float64(5)}, {"injected", true}, {"extra", true}, {"fork", false}, {"thread", "unknown"}, {"operation", "close"}} {
		event := syncFork()
		event[edit.field] = edit.value
		if _, e := normalizeCrashTrace(native, []map[string]any{fault(), event, closeFork()}); e == nil {
			t.Fatal("invalid worker cleanup accepted", edit)
		}
	}
	for _, edit := range []struct {
		field string
		value any
	}{{"operation", "fsync"}, {"fork", true}} {
		event := closeCaller()
		event[edit.field] = edit.value
		if _, e := normalizeCrashTrace(native, []map[string]any{fault(), event, syncFork(), closeFork()}); e == nil {
			t.Fatal("invalid caller cleanup accepted", edit)
		}
	}
	for _, c := range []trial{{ProcessSignal: 9, Fault: "fstatfs"}, {ProcessSignal: 11, Fault: "pread"}} {
		if _, e := normalizeCrashTrace(c, []map[string]any{fault(), syncFork(), closeFork()}); e == nil {
			t.Fatal("unqualified process failure accepted")
		}
	}
}

func TestNativeOperationProfileSelection(t *testing.T) {
	for _, c := range []struct{ host, want string }{
		{"ProductName:\tmacOS\nProductVersion:\t26.6.2\nBuildVersion:\t25G83\n", "compression-operation-macos26.json.gz"},
		{"ProductVersion: 27.0.1\n", "compression-operation.json.gz"},
		{"ProductVersion: 26\n", "compression-operation-macos26.json.gz"},
		{"ProductVersion: 15.7.1\n", "compression-operation-macos15.json.gz"},
	} {
		got, e := operationBaseline(c.host)
		if e != nil || got != "testdata/appledouble/native/"+c.want {
			t.Fatal(got, e)
		}
	}
	for _, host := range []string{"", "ProductVersion:", "ProductVersion: 260.1", "ProductVersion: 28.0", "BuildVersion: 26A434", "ProductVersion: 27.0 unexpected"} {
		if got, e := operationBaseline(host); e == nil {
			t.Fatal("accepted unqualified profile", host, got)
		}
	}
}

func TestNativeOperationCompleteProfiles(t *testing.T) {
	for _, path := range []string{"testdata/appledouble/native/compression-operation.json.gz", "testdata/appledouble/native/compression-operation-macos26.json.gz", "testdata/appledouble/native/compression-operation-macos15.json.gz"} {
		t.Run(path, func(t *testing.T) {
			f, e := os.Open("../" + path)
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			z, e := gzip.NewReader(f)
			if e != nil {
				t.Fatal(e)
			}
			defer z.Close()
			var corpus capture
			if e = json.NewDecoder(z).Decode(&corpus); e != nil {
				t.Fatal(e)
			}
			selected, e := operationBaseline(corpus.Host)
			if e != nil || selected != path || corpus.Schema != 1 || len(corpus.Cases) != 330 {
				t.Fatal("incomplete/misidentified native profile", selected, e)
			}
			for i, c := range corpus.Cases {
				original, e := comparison(c)
				if e != nil {
					t.Fatalf("case %d: %v", i, e)
				}
				var state map[string]any
				if e = json.Unmarshal(c.Observation, &state); e != nil {
					t.Fatal(e)
				}
				state["unqualified_state_change"] = true
				c.Observation, e = json.Marshal(state)
				if e != nil {
					t.Fatal(e)
				}
				changed, e := comparison(c)
				if e != nil || bytes.Equal(original, changed) {
					t.Fatal("comparison lost native state", i, e)
				}
			}
		})
	}
}

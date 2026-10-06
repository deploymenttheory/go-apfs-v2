//go:build ignore

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

// Explicit development qualification of the local native profile. The CI gate
// separately requires all twelve images from each of three actual producer OSes.
func TestLocalHFSSpecialWriter(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Fatal("native macOS development control required")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	out := os.Getenv("FILESYSTEM_HFS_SPECIAL_LOCAL_OUTPUT")
	if out == "" {
		t.Fatal("explicit retained local output is required")
	}
	if err = os.MkdirAll(out, 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	host, err := command(ctx, "sw_vers")
	if err != nil {
		t.Fatal(err)
	}
	target, err := osversion.ParseProductVersion(string(host))
	if err != nil {
		t.Fatal(err)
	}
	source := readComparisonCapture(t, fmt.Sprintf("testdata/appledouble/native/name-collation-macos%d.json.gz", target.Major))
	oracle, _ := compileWriterOracle(t, ctx, out, "name-writer-readback.c")
	preflight, _ := compileWriterOracle(t, ctx, out, "name-writer-preflight.c")
	count := 0
	for _, volume := range source.Volumes {
		if volume.Kind != "HFS+" && volume.Kind != "HFSX" {
			continue
		}
		image := produceHFSNameImage(t, out, target.Major, volume)
		validateWriterImageManifest(t, image, volume)
		var table strings.Builder
		for _, c := range append(append([]nameWriterRecord{}, image.Cases...), image.ExtraCases...) {
			fmt.Fprintf(&table, "%s\t%s\t%s\n", c.ID, c.Created, c.Queried)
		}
		stem := strings.ReplaceAll(image.Kind, "+", "plus")
		cases := filepath.Join(out, stem+".tsv")
		if err = os.WriteFile(cases, []byte(table.String()), 0644); err != nil {
			t.Fatal(err)
		}
		imagePath := filepath.Join(out, image.File)
		mountedWriterVolume(t, ctx, out, stem, imagePath, true, func(mount string) {
			raw := runWriterNative(t, ctx, filepath.Join(out, stem+"-native.json"), oracle, mount, cases)
			validateWriterReadback(t, raw, image)
		})
		raw, err := os.ReadFile(imagePath)
		if err != nil || sum(raw) != image.SHA256 {
			t.Fatal("native special readback modified image", err)
		}
		var checks []nameWriterCheck
		var input strings.Builder
		for _, check := range image.Checks {
			if strings.HasPrefix(check.ID, "special-") {
				checks = append(checks, check)
				fmt.Fprintf(&input, "%s\t%s\t%s\t%s\n", check.ID, check.Kind, check.First, check.Second)
			}
		}
		preflightCases := filepath.Join(out, stem+"-preflight.tsv")
		if err = os.WriteFile(preflightCases, []byte(input.String()), 0644); err != nil {
			t.Fatal(err)
		}
		scratch := filepath.Join(out, stem+"-preflight.dmg")
		format := "HFS+"
		if image.Kind == "HFSX" {
			format = "Case-sensitive HFS+"
		}
		if _, err = command(ctx, "hdiutil", "create", "-size", "64m", "-fs", format, "-volname", "SpecialNames", scratch); err != nil {
			t.Fatal(err)
		}
		mountedWriterVolume(t, ctx, out, stem+"-preflight", scratch, false, func(mount string) {
			raw := runWriterNative(t, ctx, filepath.Join(out, stem+"-preflight.json"), preflight, mount, preflightCases)
			validateWriterPreflight(t, raw, image.Kind, checks)
		})
		count += len(image.ExtraCases)
	}
	if count != 22 {
		t.Fatal("incomplete local native HFS special-name inventory")
	}
}

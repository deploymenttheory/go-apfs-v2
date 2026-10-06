//go:build ignore

package main

import (
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
)

func validReportingTranscript(pkg string) string {
	return fmt.Sprintf("{\"Action\":\"start\",\"Package\":%q}\n{\"Action\":\"run\",\"Package\":%q,\"Test\":\"TestRequired\"}\n{\"Action\":\"pass\",\"Package\":%q,\"Test\":\"TestRequired\"}\n{\"Action\":\"pass\",\"Package\":%q}\n", reportingModule+pkg, reportingModule+pkg, reportingModule+pkg, reportingModule+pkg)
}

func TestCIReportingTranscriptRequiresEveryCompletedPackage(t *testing.T) {
	good := validReportingTranscript("p") + validReportingTranscript("q")
	if n, err := validateReportingTranscript([]byte(good), []string{"p", "q"}); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	for name, bad := range map[string]string{
		"missing": validReportingTranscript("p"), "empty": "", "malformed": "{\n", "skip": strings.Replace(good, `"Action":"run"`, `"Action":"skip"`, 1), "failure": strings.Replace(good, `"Action":"pass"`, `"Action":"fail"`, 1),
		"unknown-package": strings.ReplaceAll(good, reportingModule+"q", reportingModule+"other"), "duplicate-package": good + validReportingTranscript("p"),
		"unfinished-test": strings.Replace(good, `"Action":"pass","Package":"`+reportingModule+`p","Test":"TestRequired"`, `"Action":"output","Package":"`+reportingModule+`p","Test":"TestRequired"`, 1),
		"missing-run":     strings.Replace(good, `"Action":"run"`, `"Action":"output"`, 1), "missing-start": strings.Replace(good, `"Action":"start"`, `"Action":"output"`, 1), "unknown-action": strings.Replace(good, `"Action":"run"`, `"Action":"invented"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateReportingTranscript([]byte(bad), []string{"p", "q"}); err == nil {
				t.Fatal("accepted incomplete test evidence")
			}
		})
	}
	if _, err := validateReportingTranscript([]byte(good), []string{"p", "p"}); err == nil {
		t.Fatal("duplicate expected package")
	}
	if _, err := validateReportingTranscript(nil, nil); err == nil {
		t.Fatal("empty expected inventory")
	}
}

func TestCIReportingCoverageRequiresAllProductionFiles(t *testing.T) {
	sources := fstest.MapFS{"p/a.go": {Data: []byte("package p")}, "p/b.go": {Data: []byte("package p")}, "p/a_test.go": {Data: []byte("package p")}}
	const a = reportingModule + "p/a.go:1.1,2.1"
	const b = reportingModule + "p/b.go:1.1,2.1"
	good := "mode: atomic\n" + a + " 100 1\n" + b + " 100 1\n"
	files, pkgs, err := validateReportingCoverage(sources, []byte(good), []string{"p"})
	if err != nil || len(files) != 2 || pkgs["p"] != (reportingCount{200, 200}) {
		t.Fatal(files, pkgs, err)
	}
	for name, bad := range map[string]string{
		"mode": strings.Replace(good, "atomic", "set", 1), "missing-file": "mode: atomic\n" + a + " 1 1\n", "empty-file": strings.Replace(good, b+" 100 1", b+" 0 0", 1),
		"low-file": "mode: atomic\n" + a + " 95 1\n" + reportingModule + "p/a.go:3.1,4.1 5 0\n" + b + " 10000 1\n",
		"negative": strings.Replace(good, "100 1", "-1 1", 1), "bad-statements": strings.Replace(good, "100 1", "x 1", 1), "negative-hits": strings.Replace(good, "100 1", "100 -1", 1), "bad-hits": strings.Replace(good, "100 1", "100 x", 1),
		"duplicate": good + a + " 100 1\n", "unknown-file": good + reportingModule + "p/other.go:1.1,2.1 1 1\n", "location": strings.Replace(good, a, "invalid", 1), "fields": good + "invalid\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := validateReportingCoverage(sources, []byte(bad), []string{"p"}); err == nil {
				t.Fatal("accepted missing or below-threshold source")
			}
		})
	}
	if _, _, err := validateReportingCoverage(sources, []byte(good), []string{"p", "p"}); err == nil {
		t.Fatal("duplicate coverage inventory")
	}
	if _, _, err := validateReportingCoverage(sources, []byte(good), []string{"missing"}); err == nil {
		t.Fatal("missing source package")
	}
}

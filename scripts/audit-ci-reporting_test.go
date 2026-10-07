//go:build ignore

package main

import (
	"bytes"
	"errors"
	"go.yaml.in/yaml/v3"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

func TestReportingGoBoundaries(t *testing.T) {
	tests := []struct {
		name, source string
		findings     int
	}{
		{"constructor", `package p;import "os/exec";func f(){exec.Command("x").Run()}`, 1},
		{"aliased_method_value", `package p;import e "os/exec";var launch=e.CommandContext`, 1},
		{"literal", `package p;import "os/exec";var c=&exec.Cmd{}`, 1},
		{"dot", `package p;import . "os/exec";var c=Command("x")`, 1},
		{"process", `package p;import "os";var f=os.StartProcess`, 1},
		{"syscall", `package p;import "syscall";var f=syscall.ForkExec`, 1},
		{"unix", `package p;import "golang.org/x/sys/unix";var f=unix.Exec`, 1},
		{"wait_is_not_spawn", `package p;import "golang.org/x/sys/unix";var f=unix.Wait4`, 0},
		{"exiterror", `package p;import "os/exec";var e *exec.ExitError`, 0},
		{"comments", `package p; // exec.Command("x").Run()`, 0},
		{"shadow", `package p;import "os/exec";func f(){exec:=struct{Command func()}{};exec.Command()}`, 0},
		{"runner", `package p;import "example/internal/testutil/cirunner";func f(){c:=cirunner.Command("x");c.Run()}`, 0},
		{"escape", `package p;import "example/internal/testutil/cirunner";func f(){c:=cirunner.Command("x");c.Cmd.Run()}`, 1},
		{"alias_escape", `package p;import r "example/internal/testutil/cirunner";func f(){c:=r.CommandContext(ctx,"x");alias:=c;_=(alias).Cmd}`, 1},
		{"typed_parameter", `package p;import "example/internal/testutil/cirunner";func f(c *cirunner.Cmd){c.Cmd.Start()}`, 1},
		{"typed_variable", `package p;import "example/internal/testutil/cirunner";var c *cirunner.Cmd;func f(){_ = c.Cmd}`, 1},
		{"unrelated_cmd", `package p;import "example/internal/testutil/cirunner";func f(c Other){c.Cmd.Run()}`, 0},
		{"var_constructor", `package p;import "example/internal/testutil/cirunner";var c=cirunner.Command("x");func f(){c.Cmd.Output()}`, 1},
		{"other_call", `package p;func f(){c:=other();c.Cmd.Run()}`, 0},
		{"other_selector", `package p;import "example/internal/testutil/cirunner";func f(){c:=other.Command("x");c.Cmd.Run()}`, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got reportingAudit
			if err := auditReportingGo("scripts/check.go", []byte(test.source), &got); err != nil {
				t.Fatal(err)
			}
			if got.GoFiles != 1 || len(got.Findings) != test.findings {
				t.Fatalf("got %+v", got)
			}
			for _, finding := range got.Findings {
				if finding.Path != "scripts/check.go" || finding.Line < 1 {
					t.Fatal(finding)
				}
			}
		})
	}
	for _, name := range []string{"internal/testutil/cirunner/command.go", "internal/testutil/cirunner/command_test.go"} {
		var result reportingAudit
		if err := auditReportingGo(name, []byte(`package p;import "os/exec";var c=exec.Command`), &result); err != nil || len(result.Findings) != 0 || !reflect.DeepEqual(result.CoreRunnerFiles, []string{name}) {
			t.Fatal(result, err)
		}
	}
	var result reportingAudit
	if err := auditReportingGo("scripts/bad.go", []byte("! invalid Go"), &result); err == nil {
		t.Fatal("invalid Go accepted")
	}
}

const reportingValidWorkflow = `name: example
jobs:
  check:
    steps:
      - uses: actions/checkout@v7
      - uses: ./.github/actions/setup-ci-runner
      - run: |
          apfs-ci-runner --suite unit --timeout 1m -- go test ./...
      - if: always()
        uses: actions/upload-artifact@v7
        with:
          path: artifacts/ci-observability/
          if-no-files-found: error
          include-hidden-files: true
  external:
    uses: example/repo/.github/workflows/job.yml@v1
  local:
    uses: ./.github/workflows/other.yml
`

func TestReportingWorkflowBoundaries(t *testing.T) {
	tests := []struct {
		name, old, new string
		findings       int
	}{
		{"valid", "", "", 0},
		{"direct", "apfs-ci-runner --suite unit --timeout 1m -- ", "", 1},
		{"no_setup", "uses: ./.github/actions/setup-ci-runner", "uses: some/setup@v1", 1},
		{"conditional_setup", "uses: ./.github/actions/setup-ci-runner", "uses: ./.github/actions/setup-ci-runner\n        if: runner.os == 'macOS'", 1},
		{"ignored_setup_failure", "uses: ./.github/actions/setup-ci-runner", "uses: ./.github/actions/setup-ci-runner\n        continue-on-error: true", 1},
		{"conditional_upload", "if: always()", "if: always() && runner.os == 'macOS'", 1},
		{"hidden_sources_omitted", "include-hidden-files: true", "include-hidden-files: false", 1},
		{"hidden_sources_default", "include-hidden-files: true", "", 1},
		{"missing_artifact_accepted", "if-no-files-found: error", "if-no-files-found: warn", 1},
		{"ignored_upload_failure", "if: always()", "if: always()\n        continue-on-error: '${{ true }}'", 1},
		{"wrong_artifact", "path: artifacts/ci-observability/", "path: artifacts/other/", 1},
		{"expression_always", "if: always()", "if: '${{ always() }}'", 0},
		{"explicit_false", "if: always()", "if: always()\n        continue-on-error: false", 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := reportingValidWorkflow
			if test.old != "" {
				body = strings.Replace(body, test.old, test.new, 1)
			}
			var got reportingAudit
			if err := auditReportingWorkflow(".github/workflows/test.yml", []byte(body), &got); err != nil {
				t.Fatal(err)
			}
			if got.Workflows != 1 || got.Workloads != 1 || len(got.Findings) != test.findings || len(got.ReusableWorkflows) != 1 || len(got.ExternalActions) < 3 {
				t.Fatalf("got %+v", got)
			}
		})
	}
	for _, body := range []string{"[", "", "name: x", "jobs: []", "jobs:\n  x:\n    steps: &s []\n  y:\n    steps: *s", "jobs: {}\njobs: {}", strings.Replace(reportingValidWorkflow, "go test ./...", "go test '\"", 1)} {
		var result reportingAudit
		if err := auditReportingWorkflow("broken.yml", []byte(body), &result); err == nil {
			t.Fatalf("accepted malformed or ambiguous workflow %q", body)
		}
	}
	// An upload before the workload cannot retain that workload's diagnostics.
	before := `jobs:
  check:
    steps:
      - uses: ./.github/actions/setup-ci-runner
      - uses: actions/upload-artifact@v7
        if: always()
        with: {path: artifacts/ci-observability, if-no-files-found: error, include-hidden-files: true}
      - run: apfs-ci-runner --suite unit -- go test ./...
  empty: {}
`
	var result reportingAudit
	if err := auditReportingWorkflow("before.yml", []byte(before), &result); err != nil || len(result.Findings) != 1 {
		t.Fatal(result, err)
	}
}
func TestReportingShellBoundaries(t *testing.T) {
	tests := []struct {
		body       string
		count, bad int
	}{
		{"go test ./...", 1, 1},
		{`echo "$(go test ./...)"`, 1, 1},
		{"echo `go test ./...`", 1, 1},
		{`echo '$(go test ./...)'`, 0, 0},
		{`echo "\$(go test ./...)"`, 0, 0},
		{`bash -c 'go test ./...'`, 1, 1},
		{`eval "go test ./..."`, 1, 1},
		{`bash -c 'apfs-ci-runner -- go test ./...'`, 1, 0},
		{`bash -c 'go test "'`, 0, 1},
		{`echo "$(go test ./...)"; go vet ./...`, 2, 2},

		{"# go test ./...\necho 'go test ./...'\nprintf 'go build'\necho go test ./...", 0, 0},
		{"apfs-ci-runner --suite unit -- go test ./... | tee file", 1, 0},
		{"GOOS=windows apfs-ci-runner --suite unit -- go build ./...", 1, 0},
		{"env GOOS=windows apfs-ci-runner --suite unit -- go build ./...", 1, 0},
		{"apfs-ci-runner --suite unit -- go test ./...; go vet ./...", 2, 1},
		{"apfs-ci-runner --suite unit -- go test ./... && go run x.go", 2, 1},
		{"if true; then go test ./...; fi", 1, 1},
		{"apfs-ci-runner --suite unit -- \\\n go test ./...", 1, 0},
		{"apfs-ci-runner --suite unit -- 'go' test ./...", 1, 0},
		{"unrelated apfs-ci-runner -- go test ./...", 1, 1},
		{"apfs-ci-runner -- go test ./...\ngo tool cover", 2, 1},
		{"go env GOOS", 0, 0},
		{"apfs-ci-runner --suite \"a\\\"b\" -- go test ./...", 1, 0},
		{"echo 'multiline\nrecipe'; go test ./...", 1, 1},
		{"echo $(go test ./...)", 1, 1},
		{"g\\o test ./...", 1, 1},
	}
	for _, test := range tests {
		t.Run(test.body, func(t *testing.T) {
			tokens, err := reportingShellTokens(test.body)
			if err != nil {
				t.Fatal(err)
			}
			count, bad := auditReportingShell(tokens)
			if count != test.count || len(bad) != test.bad {
				t.Fatalf("tokens=%+v count=%d findings=%+v", tokens, count, bad)
			}
		})
	}
	for _, body := range []string{"go test '", "go test \\", "go test \""} {
		if _, err := reportingShellTokens(body); err == nil {
			t.Fatal("invalid shell accepted")
		}
	}
}
func reportingFixture() fstest.MapFS {
	return fstest.MapFS{
		"scripts/test.go":                      {Data: []byte("package main")},
		"internal/testutil/helper/helper.go":   {Data: []byte("package helper")},
		"internal/a/a_test.go":                 {Data: []byte("package a")},
		"internal/a/production.go":             {Data: []byte("not scoped Go")},
		"pkg/a/a_test.go":                      {Data: []byte("package a")},
		"pkg/a/production.go":                  {Data: []byte("not scoped Go")},
		"acceptance/support.go":                {Data: []byte("package acceptance")},
		"cmd/root_test.go":                     {Data: []byte("package cmd")},
		"artifacts/reference_test.go":          {Data: []byte("! archived source")},
		"root_test.go":                         {Data: []byte("package root")},
		".git/not_source_test.go":              {Data: []byte("! excluded")},
		"vendor/thirdparty/not_source_test.go": {Data: []byte("! excluded")},
		"scripts/fixture.txt":                  {Data: []byte("not Go")},
		".github/workflows/test.yml":           {Data: []byte(reportingValidWorkflow)},
	}
}

type reportingFailFS struct {
	fs.FS
	name string
	err  error
}

func (f reportingFailFS) Open(name string) (fs.File, error) {
	if name == f.name {
		return nil, f.err
	}
	return f.FS.Open(name)
}
func TestReportingInventoryAndErrors(t *testing.T) {
	if yamlField(nil, "x") != nil {
		t.Fatal("nil field")
	}

	result, err := auditReportingFS(reportingFixture())
	if err != nil || result.GoFiles != 7 || result.Workflows != 1 || result.Workloads != 1 || len(result.Findings) != 0 {
		t.Fatal(result, err)
	}
	fault := errors.New("inventory failure")
	for _, name := range []string{".", "scripts", "scripts/test.go", ".github/workflows/test.yml"} {
		_, err := auditReportingFS(reportingFailFS{reportingFixture(), name, fault})
		if !errors.Is(err, fault) {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"scripts/test.go", ".github/workflows/test.yml"} {
		source := reportingFixture()
		source[name].Data = []byte("!")
		if _, err := auditReportingFS(source); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
}

type reportingFailWriter struct{}

func (reportingFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestReportingCLI(t *testing.T) {
	root := t.TempDir()
	for name, file := range reportingFixture() {
		target := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, file.Data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	report := filepath.Join(t.TempDir(), "nested", "report.json")
	var output bytes.Buffer
	if err := runReportingAudit([]string{"-root", root, "-report", report}, &output); err != nil {
		t.Fatal(err)
	}
	retained, err := os.ReadFile(report)
	if err != nil || !bytes.Equal(retained, output.Bytes()) {
		t.Fatal("artifact differs from output", err)
	}
	if err := runReportingAudit([]string{"-root", root}, reportingFailWriter{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"-bad"}, {"unexpected"}, {"-root", filepath.Join(root, "missing")}, {"-root", root, "-report", filepath.Join(report, "bad")}, {"-root", root, "-report", filepath.Dir(report)}} {
		if err := runReportingAudit(args, io.Discard); err == nil {
			t.Fatal("invalid invocation passed", args)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "scripts", "test.go"), []byte(`package p;import "os/exec";var c=exec.Command`), 0644); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := runReportingAudit([]string{"-root", root}, &output); err == nil || !strings.Contains(output.String(), "raw os/exec") {
		t.Fatal("audit failure not retained", err)
	}
}

func TestNameMatrixPrerequisiteReporting(t *testing.T) {
	b, err := os.ReadFile("../.github/workflows/name-comparison.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Name, Uses, Run, If string
				With                map[string]string
			}
		}
	}
	if err = yaml.Unmarshal(b, &workflow); err != nil {
		t.Fatal(err)
	}
	job, ok := workflow.Jobs["qualify-matrix"]
	if !ok {
		t.Fatal("missing full matrix gate")
	}
	setup, guard, upload := -1, -1, -1
	for i, s := range job.Steps {
		if s.Uses == "./.github/actions/setup-ci-runner" {
			setup = i
		}
		if strings.Contains(s.Run, "$NATIVE_READERS") {
			guard = i
			if !strings.Contains(s.Run, "apfs-ci-runner --suite name-comparison/qualify-matrix/prerequisites") || !strings.Contains(s.Run, `test "$PRODUCERS" = success`) || !strings.Contains(s.Run, `test "$PORTABLE_READERS" = success`) || !strings.Contains(s.Run, `test "$NATIVE_READERS" = success`) {
				t.Fatal("dependency failures must remain strict and reported")
			}
		}
		if strings.HasPrefix(s.Uses, "actions/upload-artifact@") && s.With["path"] == "artifacts/ci-observability/" && s.If == "always()" && s.With["if-no-files-found"] == "error" {
			upload = i
		}
	}
	if setup < 0 || guard <= setup || upload <= guard {
		t.Fatal("prerequisite failure bypasses retained reporting", setup, guard, upload)
	}
}

//go:build ignore

// Audit repository-owned CI process entry points. This is a static inventory,
// not an interpreter for dynamically generated shell or third-party actions.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"
)

type reportingFinding struct {
	Path   string
	Line   int
	Reason string
}
type reportingBoundary struct {
	Path, Job, Action string
	Line              int
}
type reportingAudit struct {
	GoFiles           int
	Workflows         int
	Workloads         int
	CoreRunnerFiles   []string
	ExcludedTrees     []string
	ExternalActions   []reportingBoundary
	ReusableWorkflows []reportingBoundary
	Findings          []reportingFinding
}

func main() {
	if err := runReportingAudit(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func runReportingAudit(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("audit-ci-reporting", flag.ContinueOnError)
	flags.SetOutput(output)
	root := flags.String("root", ".", "repository root")
	report := flags.String("report", "", "optional complete JSON audit artifact")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	result, err := auditReportingFS(os.DirFS(*root))
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if *report != "" {
		if err := os.MkdirAll(filepath.Dir(*report), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(*report, b, 0644); err != nil {
			return err
		}
	}
	if _, err := output.Write(b); err != nil {
		return err
	}
	if len(result.Findings) > 0 {
		return fmt.Errorf("CI reporting audit found %d bypasses", len(result.Findings))
	}
	return nil
}
func auditReportingFS(source fs.FS) (reportingAudit, error) {
	var result reportingAudit
	for _, root := range []string{"scripts", "internal", "pkg", ".github/workflows"} {
		if _, err := fs.Stat(source, root); err != nil {
			return result, fmt.Errorf("audit root %s: %w", root, err)
		}
	}
	err := fs.WalkDir(source, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" || name == "artifacts" {
				result.ExcludedTrees = append(result.ExcludedTrees, name)
				return fs.SkipDir
			}
			return nil
		}
		workflow := strings.HasPrefix(name, ".github/workflows/") && (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml"))
		goFile := strings.HasSuffix(name, ".go") && (strings.HasPrefix(name, "scripts/") || strings.HasPrefix(name, "acceptance/") || strings.HasPrefix(name, "internal/testutil/") || strings.HasSuffix(name, "_test.go"))
		if !workflow && !goFile {
			return nil
		}
		b, err := fs.ReadFile(source, name)
		if err != nil {
			return err
		}
		if workflow {
			return auditReportingWorkflow(name, b, &result)
		}
		return auditReportingGo(name, b, &result)
	})
	if err != nil {
		return result, fmt.Errorf("audit repository: %w", err)
	}

	return result, nil
}
func auditReportingGo(name string, b []byte, result *reportingAudit) error {
	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, name, b, 0)
	if err != nil {
		return err
	}
	result.GoFiles++
	if strings.HasPrefix(name, "internal/testutil/cirunner/") {
		result.CoreRunnerFiles = append(result.CoreRunnerFiles, name)
		return nil
	}
	// Resolve declaration identity without importing host-specific packages.
	// Syntax is validated above; the ordinary build/test gates remain responsible
	// for semantic errors. This avoids conflating unrelated local Cmd variables.
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	checker := types.Config{Error: func(error) {}}
	_, _ = checker.Check("audit", positions, []*ast.File{file}, info)
	imports := map[string]string{}
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return err
		}
		alias := path.Base(p)
		if imp.Name != nil {
			alias = imp.Name.Name
		}
		imports[alias] = p
		if alias == "." && (p == "os/exec" || strings.HasSuffix(p, "/cirunner")) {
			result.Findings = append(result.Findings, reportingFinding{name, positions.Position(imp.Pos()).Line, "dot process import bypasses qualified constructor audit"})
		}
	}
	isRunnerType := func(expr ast.Expr) bool {
		if star, ok := expr.(*ast.StarExpr); ok {
			expr = star.X
		}
		sel, ok := expr.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && sel.Sel.Name == "Cmd" && strings.HasSuffix(imports[id.Name], "/cirunner")
	}
	owned := map[types.Object]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		if field, ok := n.(*ast.Field); ok && isRunnerType(field.Type) {
			for _, id := range field.Names {
				owned[info.ObjectOf(id)] = true
			}
		}
		return true
	})
	var isRunner func(ast.Expr) bool
	isRunner = func(expr ast.Expr) bool {
		switch v := expr.(type) {
		case *ast.Ident:
			return info.ObjectOf(v) != nil && owned[info.ObjectOf(v)]
		case *ast.ParenExpr:
			return isRunner(v.X)
		case *ast.CallExpr:
			sel, ok := v.Fun.(*ast.SelectorExpr)
			if !ok {
				return false
			}
			id, ok := sel.X.(*ast.Ident)
			return ok && strings.HasSuffix(imports[id.Name], "/cirunner") && (sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext")
		}
		return false
	}
	// Propagate constructor and variable aliases independent of source order.
	for changed := true; changed; {
		changed = false
		ast.Inspect(file, func(n ast.Node) bool {
			var lhs []ast.Expr
			var rhs []ast.Expr
			switch v := n.(type) {
			case *ast.AssignStmt:
				lhs, rhs = v.Lhs, v.Rhs
			case *ast.ValueSpec:
				rhs = v.Values
				for _, id := range v.Names {
					lhs = append(lhs, id)
					if isRunnerType(v.Type) && !owned[info.ObjectOf(id)] {
						owned[info.ObjectOf(id)] = true
						changed = true
					}
				}
			}
			for i, right := range rhs {
				if i >= len(lhs) || !isRunner(right) {
					continue
				}
				id, ok := lhs[i].(*ast.Ident)
				if ok && info.ObjectOf(id) != nil && !owned[info.ObjectOf(id)] {
					owned[info.ObjectOf(id)] = true
					changed = true
				}
			}
			return true
		})
	}
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		reason := ""
		if id, ok := sel.X.(*ast.Ident); ok {
			p := imports[id.Name]
			if object := info.ObjectOf(id); object != nil {
				if _, imported := object.(*types.PkgName); !imported {
					p = ""
				}
			}
			if p == "os/exec" && slices.Contains([]string{"Command", "CommandContext", "Cmd"}, sel.Sel.Name) {
				reason = "raw os/exec constructor or command type outside shared runner"
			}
			if (p == "os" && sel.Sel.Name == "StartProcess") || ((p == "syscall" || p == "golang.org/x/sys/unix") && slices.Contains([]string{"Exec", "ForkExec", "StartProcess"}, sel.Sel.Name)) {
				reason = "raw process launch outside shared runner"
			}
		}
		if sel.Sel.Name == "Cmd" && isRunner(sel.X) {
			reason = "embedded raw command escapes shared runner lifecycle"
		}
		if reason != "" {
			result.Findings = append(result.Findings, reportingFinding{name, positions.Position(sel.Pos()).Line, reason})
		}
		return true
	})
	return nil
}
func yamlField(n *yaml.Node, key string) *yaml.Node {
	if n == nil {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
func yamlValue(n *yaml.Node, key string) string {
	v := yamlField(n, key)
	if v == nil {
		return ""
	}
	return v.Value
}
func alwaysReporting(v string) bool {
	v = strings.TrimSpace(v)
	v = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(v, "${{"), "}}"))
	return v == "always()"
}
func auditReportingWorkflow(name string, b []byte, result *reportingAudit) error {
	var document yaml.Node
	if err := yaml.Unmarshal(b, &document); err != nil {
		return err
	}
	if err := reportingYAMLShape(&document); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	result.Workflows++
	if len(document.Content) != 1 {
		return fmt.Errorf("%s: expected workflow document", name)
	}
	jobs := yamlField(document.Content[0], "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return fmt.Errorf("%s: jobs mapping missing", name)
	}
	for i := 0; i < len(jobs.Content); i += 2 {
		jobName, job := jobs.Content[i].Value, jobs.Content[i+1]
		steps := yamlField(job, "steps")
		if steps == nil {
			if uses := yamlValue(job, "uses"); uses != "" {
				if strings.HasPrefix(uses, "./") {
					result.ReusableWorkflows = append(result.ReusableWorkflows, reportingBoundary{name, jobName, uses, job.Line})
				} else {
					result.ExternalActions = append(result.ExternalActions, reportingBoundary{name, jobName, uses, job.Line})
				}
			}
			continue
		}
		setup := false
		workloads := 0
		lastWork := -1
		upload := -1
		for j, step := range steps.Content {
			uses := yamlValue(step, "uses")
			if uses == "./.github/actions/setup-ci-runner" {
				if yamlValue(step, "if") == "" && slices.Contains([]string{"", "false"}, yamlValue(step, "continue-on-error")) {
					setup = true
				}
			}
			if uses != "" && !strings.HasPrefix(uses, "./") {
				result.ExternalActions = append(result.ExternalActions, reportingBoundary{name, jobName, uses, step.Line})
			}
			if strings.HasPrefix(uses, "actions/upload-artifact@") {
				with := yamlField(step, "with")
				for _, p := range strings.Fields(yamlValue(with, "path")) {
					if strings.HasPrefix(p, "artifacts/") && yamlValue(with, "include-hidden-files") != "true" {
						result.Findings = append(result.Findings, reportingFinding{name, step.Line, "owned evidence upload must retain hidden provenance sources"})
						break
					}
				}
			}
			if strings.HasPrefix(uses, "actions/upload-artifact@") && alwaysReporting(yamlValue(step, "if")) && slices.Contains([]string{"", "false"}, yamlValue(step, "continue-on-error")) {
				with := yamlField(step, "with")
				for _, p := range strings.Fields(yamlValue(with, "path")) {
					if strings.TrimSuffix(p, "/") == "artifacts/ci-observability" && yamlValue(with, "if-no-files-found") == "error" {
						upload = j
					}
				}
			}
			run := yamlField(step, "run")
			if run == nil {
				continue
			}
			tokens, err := reportingShellTokens(run.Value)
			if err != nil {
				return fmt.Errorf("%s:%d: %w", name, run.Line, err)
			}
			count, findings := auditReportingShell(tokens)
			workloads += count
			result.Workloads += count
			if count > 0 {
				lastWork = j
				if !setup {
					result.Findings = append(result.Findings, reportingFinding{name, step.Line, "workload requires unconditional earlier shared-runner setup"})
				}
			}
			for _, finding := range findings {
				finding.Path = name
				finding.Line += run.Line
				result.Findings = append(result.Findings, finding)
			}
		}
		if workloads > 0 && upload <= lastWork {
			result.Findings = append(result.Findings, reportingFinding{name, job.Line, "workload job requires later always() diagnostics upload with missing files treated as error"})
		}
	}
	return nil
}

type reportingShellToken struct {
	Text      string
	Line      int
	Separator bool
	Embedded  bool
}

// Tokenize literal shell words without executing expansions. A quoted recipe is
// one word; actual go commands, including quoted command names, remain visible.
func reportingShellTokens(body string) ([]reportingShellToken, error) {
	var tokens []reportingShellToken
	line := 0
	for i := 0; i < len(body); {
		c := body[i]
		if c == '\\' && i+1 < len(body) && body[i+1] == '\n' {
			i += 2
			line++
			continue
		}
		if c == '\n' || strings.ContainsRune(";|&()`", rune(c)) {
			tokens = append(tokens, reportingShellToken{Text: string(c), Line: line, Separator: true})
			i++
			if c == '\n' {
				line++
			}
			continue
		}
		if unicode.IsSpace(rune(c)) {
			i++
			continue
		}
		if c == '#' {
			for i < len(body) && body[i] != '\n' {
				i++
			}
			continue
		}
		start := line
		embedded := false
		var word strings.Builder
		for i < len(body) {
			c = body[i]
			if unicode.IsSpace(rune(c)) || strings.ContainsRune(";|&()`", rune(c)) {
				break
			}
			if c == '\'' || c == '"' {
				quote := c
				i++
				closed := false
				for i < len(body) {
					c = body[i]
					i++
					if c == quote {
						closed = true
						break
					}
					if c == '\\' && quote == '"' && i < len(body) {
						word.WriteByte(body[i])
						i++
						continue
					}
					if quote == '"' && (c == '`' || (c == '$' && i < len(body) && body[i] == '(')) {
						embedded = true
					}
					word.WriteByte(c)
					if c == '\n' {
						line++
					}
				}
				if !closed {
					return nil, errors.New("unterminated shell quote")
				}
				continue
			}
			if c == '\\' {
				i++
				if i == len(body) {
					return nil, errors.New("unfinished shell escape")
				}
				if body[i] == '\n' {
					line++
					i++
					continue
				}
				c = body[i]
			}
			word.WriteByte(c)
			i++
		}
		tokens = append(tokens, reportingShellToken{Text: word.String(), Line: start, Embedded: embedded})
	}
	return tokens, nil
}
func auditReportingShell(tokens []reportingShellToken) (int, []reportingFinding) {
	count := 0
	var findings []reportingFinding
	segment := 0
	for i, t := range tokens {
		if t.Separator {
			segment = i + 1
			continue
		}
		if t.Embedded || (i > segment && (tokens[i-1].Text == "eval" || (tokens[i-1].Text == "-c" && i > segment+1 && slices.Contains([]string{"sh", "bash", "zsh", "pwsh", "powershell"}, tokens[i-2].Text)))) {
			nested, err := reportingShellTokens(t.Text)
			if err != nil {
				findings = append(findings, reportingFinding{Line: t.Line, Reason: "unparseable executable shell expansion"})
			} else {
				nestedCount, nestedFindings := auditReportingShell(nested)
				count += nestedCount
				for _, finding := range nestedFindings {
					finding.Line += t.Line
					findings = append(findings, finding)
				}
			}
			continue
		}
		if t.Text != "go" ||
			i+1 == len(tokens) || !slices.Contains([]string{"test", "run", "build", "vet", "tool"}, tokens[i+1].Text) {
			continue
		}
		// Ignore literal arguments to echo/printf, not nested executable recipes.
		first := segment
		for first < i && (strings.Contains(tokens[first].Text, "=") || slices.Contains([]string{"then", "do", "if", "!", "env", "sudo"}, tokens[first].Text)) {
			first++
		}
		if first < i && slices.Contains([]string{"echo", "printf"}, tokens[first].Text) {
			continue
		}
		count++
		wrapped := false
		for k := first; k < i && k == first; k++ {
			if tokens[k].Text == "apfs-ci-runner" {
				for m := k + 1; m < i; m++ {
					if tokens[m].Text == "--" && m+1 == i {
						wrapped = true
					}
				}
			}
		}
		if !wrapped {
			findings = append(findings, reportingFinding{Line: t.Line, Reason: "Go workload bypasses apfs-ci-runner"})
		}
	}
	return count, findings
}

func reportingYAMLShape(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode {
		return errors.New("YAML aliases require explicit expanded workflow steps")
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i].Value
			if seen[key] {
				return fmt.Errorf("duplicate YAML key %q", key)
			}
			seen[key] = true
		}
	}
	for _, child := range n.Content {
		if err := reportingYAMLShape(child); err != nil {
			return err
		}
	}
	return nil
}

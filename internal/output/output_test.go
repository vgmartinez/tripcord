package output

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vgmartinez/tripcord/internal/model"
)

func TestGoldenFormats(t *testing.T) {
	t.Parallel()
	for _, format := range []Format{FormatJSON, FormatSARIF, FormatText, FormatGHA, FormatMD} {
		t.Run(string(format), func(t *testing.T) {
			t.Parallel()
			got := render(t, format, findings())
			assertGolden(t, string(format)+".golden", got)
			if format == FormatSARIF {
				validateSARIF(t, got)
			}
		})
	}
}

func TestFindingsAreSortedDeterministically(t *testing.T) {
	t.Parallel()
	left := render(t, FormatJSON, findings())
	rightFindings := findings()
	rightFindings[0], rightFindings[1] = rightFindings[1], rightFindings[0]
	right := render(t, FormatJSON, rightFindings)
	if left != right {
		t.Fatalf("output differs by input order:\n%s\n---\n%s", left, right)
	}
}

func TestSARIFUsesRepoRelativeURIs(t *testing.T) {
	t.Parallel()
	got := render(t, FormatSARIF, findings())
	if !strings.Contains(got, `"uri": "configs/hook.json"`) {
		t.Fatalf("SARIF did not contain a repo-relative URI: %s", got)
	}
	if strings.Contains(got, "/work/repo/") {
		t.Fatalf("SARIF leaked absolute repository path: %s", got)
	}
}

func TestGHAEscaping(t *testing.T) {
	t.Parallel()
	finding := findings()[0]
	finding.Title = "bad%:\r\nmessage"
	finding.Location.Path = "dir/a:b,c.json"
	got := render(t, FormatGHA, []model.Finding{finding})
	for _, want := range []string{"file=dir/a%3Ab%2Cc.json", "bad%25:%0D%0Amessage"} {
		if !strings.Contains(got, want) {
			t.Fatalf("GHA output missing %q: %s", want, got)
		}
	}
}

func TestMarkdownEscapesExcerptAndNeverAddsSecret(t *testing.T) {
	t.Parallel()
	finding := findings()[0]
	const redacted = "sk-***REDACTED***abcd `<img src=x onerror=alert(1)>`"
	const rawSecret = "sk-live-secret-value"
	finding.Evidence = []model.Evidence{{Config: "cursor:repo:configs/hook.json", Excerpt: redacted}}

	for _, format := range []Format{FormatJSON, FormatSARIF, FormatText, FormatGHA, FormatMD} {
		got := render(t, format, []model.Finding{finding})
		if strings.Contains(got, rawSecret) {
			t.Fatalf("%s leaked an unredacted secret: %s", format, got)
		}
		if format == FormatMD {
			for _, unsafe := range []string{"`<img", "<img"} {
				if strings.Contains(got, unsafe) {
					t.Fatalf("markdown contains unsafe excerpt content %q: %s", unsafe, got)
				}
			}
			if !strings.Contains(got, "sk-***REDACTED***abcd") {
				t.Fatalf("markdown omitted redacted excerpt: %s", got)
			}
		}
	}
}

func TestSinkRejectsUnsupportedTargetsAndWritesAfterFlush(t *testing.T) {
	t.Parallel()
	var buffer bytes.Buffer
	if _, err := NewStdoutSink(FormatJSON, &buffer, Options{}); err == nil {
		t.Fatal("stdout JSON sink was accepted")
	}
	sink, err := NewFileSink(FormatJSON, &buffer, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(findings()[0]); err == nil {
		t.Fatal("write after flush was accepted")
	}
}

func render(t *testing.T, format Format, input []model.Finding) string {
	t.Helper()
	var buffer bytes.Buffer
	target := TargetStdout
	if format == FormatJSON || format == FormatSARIF {
		target = TargetFile
	}
	sink, err := NewSink(format, target, &buffer, Options{RepoRoot: "/work/repo"})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range input {
		if err := sink.Write(finding); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Flush(); err != nil {
		t.Fatal(err)
	}
	return buffer.String()
}

func findings() []model.Finding {
	line := 7
	return []model.Finding{
		{
			Schema:     model.SchemaFinding,
			Rule:       "TC-CFG-010",
			Title:      "Plugin executes arbitrary code",
			Severity:   model.SeverityHigh,
			Decision:   model.DecisionDeny,
			Confidence: 0.95,
			Evidence: []model.Evidence{{
				Config:  "cursor:repo:configs/hook.json",
				Excerpt: "plugin: ./plugins/unreviewed.js",
			}},
			Location:    model.Location{Harness: model.HarnessCursor, Scope: model.ScopeRepo, Path: "/work/repo/configs/hook.json", Line: &line},
			Refs:        []string{"https://example.invalid/rules/TC-CFG-010"},
			Fix:         "Remove the plugin or review and pin it.",
			Fingerprint: "tcf_0123456789abcdef",
		},
		{
			Schema:     model.SchemaFinding,
			Rule:       "TC-CFG-002",
			Title:      "Task runs on folder open",
			Severity:   model.SeverityMedium,
			Decision:   model.DecisionWarn,
			Confidence: 0.8,
			Evidence: []model.Evidence{{
				Event:   "evt_folder_open",
				Excerpt: "runOn: folderOpen",
			}},
			Location:    model.Location{Harness: model.SurfaceVSCode, Scope: model.ScopeRepo, Path: "configs/tasks.json"},
			Refs:        []string{"https://example.invalid/rules/TC-CFG-002"},
			Fix:         "Remove runOn: folderOpen.",
			Fingerprint: "tcf_fedcba9876543210",
		},
	}
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join(outputTestdataDir(t), name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("%s mismatch\n--- got ---\n%s--- want ---\n%s", name, got, want)
	}
}

func validateSARIF(t *testing.T, raw string) {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile(filepath.Join(outputTestdataDir(t), "sarif-2.1.0.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := jsonschema.UnmarshalJSON(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatal(err)
	}
}

func outputTestdataDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "testdata")
}

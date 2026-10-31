package output

import (
	"bytes"
	"encoding/json"
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
	for _, format := range []Format{FormatJSON, FormatJSONL, FormatSARIF, FormatText, FormatGHA, FormatMD} {
		t.Run(string(format), func(t *testing.T) {
			t.Parallel()
			got := render(t, format, findings())
			if format == FormatJSONL {
				if got != render(t, FormatJSON, findings()) {
					t.Fatal("jsonl output differs from json")
				}
				return
			}
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

	for _, format := range []Format{FormatJSON, FormatJSONL, FormatSARIF, FormatText, FormatGHA, FormatMD} {
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

func TestWriteAfterFlush(t *testing.T) {
	t.Parallel()
	var buffer bytes.Buffer
	sink, err := NewStdoutSink(FormatJSONL, &buffer, Options{})
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

func TestSelectSinkJSONL(t *testing.T) {
	t.Parallel()
	want := render(t, FormatJSONL, findings())
	for _, outputPath := range []string{"", "-"} {
		t.Run("stdout "+outputPath, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			handle, err := SelectSink("jsonl", outputPath, &stdout, Options{RepoRoot: "/work/repo"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := handle.Close(); err != nil {
					t.Error(err)
				}
			})
			writeFindings(t, handle, findings())
			if stdout.String() != want {
				t.Fatalf("stdout = %s", stdout.String())
			}
		})
	}

	t.Run("file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "findings.jsonl")
		var stdout bytes.Buffer
		handle, err := SelectSink("jsonl", path, &stdout, Options{RepoRoot: "/work/repo"})
		if err != nil {
			t.Fatal(err)
		}
		writeFindings(t, handle, findings())
		if err := handle.Close(); err != nil {
			t.Fatal(err)
		}
		if stdout.Len() != 0 {
			t.Fatalf("file route wrote stdout: %s", stdout.String())
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("file = %s", got)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("file mode = %o", info.Mode().Perm())
		}
	})

	t.Run("json alias uses stdout", func(t *testing.T) {
		t.Parallel()
		var stdout bytes.Buffer
		handle, err := SelectSink("json", "", &stdout, Options{RepoRoot: "/work/repo"})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := handle.Close(); err != nil {
				t.Error(err)
			}
		}()
		writeFindings(t, handle, findings())
		if stdout.String() != want {
			t.Fatalf("json alias stdout = %s", stdout.String())
		}
	})
}

func TestNonRepoLocationGoldens(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		format  Format
		input   []model.Finding
		options Options
		logical bool
	}{
		{name: "sarif-user", format: FormatSARIF, input: []model.Finding{userFinding()}},
		{name: "sarif-managed", format: FormatSARIF, input: []model.Finding{managedFinding()}},
		{name: "gha-user", format: FormatGHA, input: []model.Finding{userFinding()}},
		{name: "gha-managed", format: FormatGHA, input: []model.Finding{managedFinding()}},
		{
			name:    "sarif-logical",
			format:  FormatSARIF,
			input:   []model.Finding{userFinding(), managedFinding()},
			options: Options{NonRepoSARIF: SARIFNonRepoLogical},
			logical: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := renderWith(t, tc.format, tc.input, tc.options)
			assertGolden(t, tc.name+".golden", got)
			if strings.Contains(got, "file://") || strings.Contains(got, "/home/") || strings.Contains(got, "file=") || strings.Contains(got, `claude//`) || strings.Contains(got, `etc//`) {
				t.Fatalf("location leaked a file annotation or an unnormalized path:\n%s", got)
			}
			if tc.format != FormatSARIF {
				return
			}
			validateSARIF(t, got)
			assertSARIFLocations(t, got, tc.logical)
		})
	}
}

func TestSARIFURIBaseIsDefault(t *testing.T) {
	t.Parallel()
	explicit := renderWith(t, FormatSARIF, []model.Finding{userFinding()}, Options{NonRepoSARIF: SARIFNonRepoURIBase})
	if explicit != renderWith(t, FormatSARIF, []model.Finding{userFinding()}, Options{}) {
		t.Fatal("explicit uri-base form differs from the default")
	}
	if DefaultSARIFNonRepoLocation != SARIFNonRepoURIBase {
		t.Fatalf("default SARIF location = %s", DefaultSARIFNonRepoLocation)
	}
	got := renderWith(t, FormatSARIF, []model.Finding{userFinding(), managedFinding()}, Options{})
	validateSARIF(t, got)
	for _, want := range []string{`"USERHOME"`, `"MANAGED"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("combined SARIF missing %s\n%s", want, got)
		}
	}
	assertSARIFLocations(t, got, false)
}

func TestGHASeverityCommands(t *testing.T) {
	t.Parallel()
	cases := []struct {
		severity model.Severity
		command  string
	}{
		{severity: model.SeverityCritical, command: "error"},
		{severity: model.SeverityHigh, command: "error"},
		{severity: model.SeverityMedium, command: "warning"},
		{severity: model.SeverityLow, command: "notice"},
	}
	for _, tc := range cases {
		t.Run(string(tc.severity), func(t *testing.T) {
			t.Parallel()
			finding := findings()[0]
			finding.Severity = tc.severity
			got := render(t, FormatGHA, []model.Finding{finding})
			if !strings.HasPrefix(got, "::"+tc.command+" ") {
				t.Fatalf("command = %s", got)
			}
			if strings.Contains(got, "info") {
				t.Fatalf("severity info appeared in %s", got)
			}
		})
	}
}

func TestGHANonRepoEscaping(t *testing.T) {
	t.Parallel()
	finding := userFinding()
	finding.Location.Line = nil
	finding.Location.Path = "~/a%b,\r\n.json"
	got := renderWith(t, FormatGHA, []model.Finding{finding}, Options{})
	if strings.Contains(got, "file=") || strings.Contains(got, "\r") || strings.Count(got, "\n") != 1 {
		t.Fatalf("annotation = %q", got)
	}
	for _, want := range []string{"title=~/a%25b%2C%0D%0A.json", "a%25b,%0D%0A.json"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}
}

func TestRelativeLocationURIs(t *testing.T) {
	t.Parallel()
	user := locate(model.Location{Scope: model.ScopeUser, Path: `~\.claude//settings.json`}, "")
	if user.kind != locUser || user.path != "~/.claude/settings.json" || user.uri != ".claude/settings.json" || user.baseID != URIBaseUserHome {
		t.Fatalf("user location = %+v", user)
	}
	managed := locate(model.Location{Scope: model.ScopeManaged, Path: `/etc//cursor/hooks.json`}, "")
	if managed.kind != locManaged || managed.path != "/etc/cursor/hooks.json" || managed.uri != "etc/cursor/hooks.json" || managed.baseID != URIBaseManaged {
		t.Fatalf("managed location = %+v", managed)
	}
	outside := locate(model.Location{Scope: model.ScopeRepo, Path: "/other/file"}, "/work/repo")
	if outside.kind != locNone {
		t.Fatalf("repo path outside the root = %+v", outside)
	}
}

func TestRejectsUnknownSARIFLocationMode(t *testing.T) {
	t.Parallel()
	var buffer bytes.Buffer
	_, err := NewStdoutSink(FormatText, &buffer, Options{NonRepoSARIF: "absolute"})
	if err == nil {
		t.Fatal("unknown SARIF location mode was accepted")
	}
}

func render(t *testing.T, format Format, input []model.Finding) string {
	t.Helper()
	return renderWith(t, format, input, Options{RepoRoot: "/work/repo"})
}

func renderWith(t *testing.T, format Format, input []model.Finding, options Options) string {
	t.Helper()
	var buffer bytes.Buffer
	sink, err := NewStdoutSink(format, &buffer, options)
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

func writeFindings(t *testing.T, sink Sink, input []model.Finding) {
	t.Helper()
	for _, finding := range input {
		if err := sink.Write(finding); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Flush(); err != nil {
		t.Fatal(err)
	}
}

func userFinding() model.Finding {
	line := 3
	return model.Finding{
		Schema:     model.SchemaFinding,
		Rule:       "TC-CFG-001",
		Title:      "Hook downloads code",
		Severity:   model.SeverityCritical,
		Decision:   model.DecisionDeny,
		Confidence: 0.9,
		Evidence: []model.Evidence{{
			Config:  "claude:user:~/.claude/settings.json",
			Excerpt: "SessionStart hook",
		}},
		Location: model.Location{
			Harness: model.HarnessClaude,
			Scope:   model.ScopeUser,
			Path:    `~\.claude//settings.json`,
			Line:    &line,
		},
		Refs:        []string{"https://example.invalid/rules/TC-CFG-001"},
		Fix:         "Remove the hook.",
		Fingerprint: "tcf_1111111111111111",
	}
}

func managedFinding() model.Finding {
	return model.Finding{
		Schema:     model.SchemaFinding,
		Rule:       "TC-CFG-006",
		Title:      "Hook points outside the repository",
		Severity:   model.SeverityLow,
		Decision:   model.DecisionAudit,
		Confidence: 0.4,
		Evidence: []model.Evidence{{
			Config:  "cursor:managed:/etc/cursor/hooks.json",
			Excerpt: "managed hook",
		}},
		Location: model.Location{
			Harness: model.HarnessCursor,
			Scope:   model.ScopeManaged,
			Path:    `/etc//cursor/hooks.json`,
		},
		Refs:        []string{"https://example.invalid/rules/TC-CFG-006"},
		Fix:         "Point the hook at a versioned script.",
		Fingerprint: "tcf_2222222222222222",
	}
}

func assertSARIFLocations(t *testing.T, raw string, logical bool) {
	t.Helper()
	var log struct {
		Runs []struct {
			OriginalURIBaseIDs map[string]map[string]any `json:"originalUriBaseIds"`
			Results            []struct {
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					Physical *struct {
						Artifact struct {
							URI       string `json:"uri"`
							URIBaseID string `json:"uriBaseId"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
					Logical []struct {
						FullyQualifiedName string `json:"fullyQualifiedName"`
					} `json:"logicalLocations"`
				} `json:"locations"`
				Properties struct {
					Tripcord struct {
						Scope string `json:"scope"`
						Path  string `json:"path"`
					} `json:"tripcord"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(raw), &log); err != nil {
		t.Fatal(err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d", len(log.Runs))
	}
	run := log.Runs[0]
	if logical && len(run.OriginalURIBaseIDs) != 0 {
		t.Fatalf("logical fallback declared uri bases: %+v", run.OriginalURIBaseIDs)
	}
	for id, base := range run.OriginalURIBaseIDs {
		if _, ok := base["uri"]; ok {
			t.Fatalf("%s declared a uri: %+v", id, base)
		}
	}
	if len(run.Results) == 0 {
		t.Fatal("no results")
	}
	for _, result := range run.Results {
		if result.Properties.Tripcord.Scope == "" || result.Properties.Tripcord.Path == "" {
			t.Fatalf("missing tripcord properties: %+v", result.Properties)
		}
		if !strings.Contains(result.Message.Text, result.Properties.Tripcord.Path) {
			t.Fatalf("message %q does not contain %q", result.Message.Text, result.Properties.Tripcord.Path)
		}
		if len(result.Locations) != 1 {
			t.Fatalf("locations = %+v", result.Locations)
		}
		if logical {
			if result.Locations[0].Physical != nil || len(result.Locations[0].Logical) != 1 {
				t.Fatalf("logical location = %+v", result.Locations[0])
			}
			if result.Locations[0].Logical[0].FullyQualifiedName != result.Properties.Tripcord.Path {
				t.Fatalf("logical path = %s", result.Locations[0].Logical[0].FullyQualifiedName)
			}
			continue
		}
		if result.Locations[0].Physical == nil {
			t.Fatal("missing physical location")
		}
		artifact := result.Locations[0].Physical.Artifact
		if artifact.URI == "" || artifact.URIBaseID == "" || strings.HasPrefix(artifact.URI, "/") || strings.Contains(artifact.URI, ":") {
			t.Fatalf("artifact URI = %+v", artifact)
		}
	}
}

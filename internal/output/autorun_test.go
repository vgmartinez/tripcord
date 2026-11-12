package output

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

func autorunHooks() []AutorunHook {
	return []AutorunHook{
		{Harness: "claude", Path: ".claude/settings.json", Line: 6, Event: "SessionStart", Command: "./scripts/setup.sh", Target: "scripts/setup.sh"},
		{Harness: "claude", Path: "plugins/p/hooks/hooks.json", Line: 1, Event: "modules", Command: "./register.tsx", Target: "plugins/p/hooks/register.tsx"},
		{Harness: "cursor", Path: ".cursor/hooks.json", Event: "sessionStart", Command: "node .cursor/hooks/start.mjs", Target: ".cursor/hooks/start.mjs"},
	}
}

func renderAutorun(t *testing.T, format Format, input []model.Finding, hooks []AutorunHook, options Options) string {
	t.Helper()
	var buffer bytes.Buffer
	sink, err := NewStdoutSink(format, &buffer, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetAutorunHooks(sink, hooks); err != nil {
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

func readGolden(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(outputTestdataDir(t), name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestAutorunGoldens pins the inventory in JSON, SARIF, and both text
// views. Each golden is the existing golden for the same findings plus
// the inventory: JSON gains lines after the findings, SARIF gains
// notifications and no result, and text gains lines.
func TestAutorunGoldens(t *testing.T) {
	t.Parallel()
	verbose := testOptions()
	verbose.Verbose = true
	compact := testOptions()
	compact.ShowAutorun = true
	cases := []struct {
		golden  string
		format  Format
		options Options
		base    string
	}{
		{golden: "json-autorun.golden", format: FormatJSON, options: testOptions(), base: "json.golden"},
		{golden: "sarif-autorun.golden", format: FormatSARIF, options: testOptions(), base: "sarif.golden"},
		{golden: "text-autorun.golden", format: FormatText, options: compact, base: "text.golden"},
		{golden: "text-verbose-autorun.golden", format: FormatText, options: verbose},
	}
	for _, tc := range cases {
		t.Run(tc.golden, func(t *testing.T) {
			t.Parallel()
			got := renderAutorun(t, tc.format, sealAll(t, findings()), autorunHooks(), tc.options)
			assertGolden(t, tc.golden, got)
			if tc.base == "" {
				return
			}
			base := readGolden(t, tc.base)
			switch tc.format {
			case FormatJSON:
				validateFindingLines(t, base)
				if !strings.HasPrefix(got, base) {
					t.Fatalf("JSON does not keep the finding lines first:\n%s", got)
				}
			case FormatSARIF:
				validateSARIF(t, got)
				var a, b struct {
					Runs []struct {
						Results json.RawMessage `json:"results"`
					} `json:"runs"`
				}
				if err := json.Unmarshal([]byte(got), &a); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal([]byte(base), &b); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(a.Runs[0].Results, b.Runs[0].Results) {
					t.Fatal("the inventory changed the SARIF results")
				}
			case FormatText:
				for _, line := range strings.Split(strings.TrimSuffix(base, "\n"), "\n") {
					if !strings.Contains(got, line+"\n") {
						t.Fatalf("text lost the line %q:\n%s", line, got)
					}
				}
			}
		})
	}
}

// TestAutorunAbsentWhereNotShown checks the formats and views that do
// not carry the inventory: compact scan text, Markdown, and GitHub
// Actions output are byte for byte what they are without it.
func TestAutorunAbsentWhereNotShown(t *testing.T) {
	t.Parallel()
	for _, format := range []Format{FormatText, FormatMD, FormatGHA} {
		without := renderWith(t, format, sealAll(t, findings()), testOptions())
		with := renderAutorun(t, format, sealAll(t, findings()), autorunHooks(), testOptions())
		if with != without {
			t.Fatalf("%s changed:\n%s", format, with)
		}
	}
}

// TestAutorunEmptyLeavesReportUnchanged checks that an empty inventory
// leaves every format exactly as before, including a SARIF run with no
// invocations.
func TestAutorunEmptyLeavesReportUnchanged(t *testing.T) {
	t.Parallel()
	for _, format := range []Format{FormatJSON, FormatSARIF, FormatText, FormatGHA, FormatMD} {
		options := testOptions()
		options.ShowAutorun = true
		with := renderAutorun(t, format, sealAll(t, findings()), nil, options)
		if want := renderWith(t, format, sealAll(t, findings()), testOptions()); with != want {
			t.Fatalf("%s changed with an empty inventory:\n%s", format, with)
		}
	}
	if got := renderAutorun(t, FormatJSON, nil, nil, testOptions()); got != "" {
		t.Fatalf("empty JSON report = %q", got)
	}
}

// TestAutorunSanitizedAndRedacted checks that inventory fields go
// through the redactor and each format's escaping: a credential in the
// command never appears, and a terminal escape in a path is escaped.
func TestAutorunSanitizedAndRedacted(t *testing.T) {
	t.Parallel()
	hooks := []AutorunHook{{
		Harness: "claude",
		Path:    ".claude/settings.json\x1b]8;;https://evil.invalid\x1b\\",
		Line:    2,
		Event:   "SessionStart",
		Command: "./scripts/setup.sh --token=CNRYAUTORUN7Q2W",
		Target:  "scripts/setup.sh\n[fake] HIGH TC-CFG-001",
	}}
	verbose := testOptions()
	verbose.Verbose = true
	compact := testOptions()
	compact.ShowAutorun = true
	for name, out := range map[string]string{
		"json":         renderAutorun(t, FormatJSON, nil, hooks, testOptions()),
		"sarif":        renderAutorun(t, FormatSARIF, nil, hooks, testOptions()),
		"text":         renderAutorun(t, FormatText, nil, hooks, compact),
		"text verbose": renderAutorun(t, FormatText, nil, hooks, verbose),
	} {
		if strings.Contains(out, "CNRYAUTORUN7Q2W") {
			t.Errorf("%s leaked the credential:\n%s", name, out)
		}
		if strings.Contains(out, "\x1b") {
			t.Errorf("%s kept a raw escape:\n%q", name, out)
		}
		if strings.Contains(out, "\n[fake]") {
			t.Errorf("%s let a field start a new line:\n%s", name, out)
		}
	}
}

package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

func TestDiagnosticsAreReportedAndRedacted(t *testing.T) {
	t.Parallel()
	token := "ghp_" + strings.Repeat("b", 36)
	diag := Diagnostic{
		Harness: "claude",
		Scope:   "user",
		Path:    "~/.claude/settings.json",
		Message: "bad " + token + " \x1b",
	}
	for _, format := range []Format{FormatJSON, FormatMD, FormatSARIF, FormatText, FormatGHA} {
		t.Run(string(format), func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			sink, err := NewStdoutSink(format, &buf, Options{Redactor: DefaultRedactor})
			if err != nil {
				t.Fatal(err)
			}
			if err := SetDiagnostics(sink, []Diagnostic{diag}); err != nil {
				t.Fatal(err)
			}
			if err := sink.Flush(); err != nil {
				t.Fatal(err)
			}
			got := buf.String()
			if strings.Contains(got, token) || strings.Contains(got, "\x1b") {
				t.Fatalf("%s leaked a secret or a control:\n%s", format, got)
			}
			if !strings.Contains(got, "~/.claude/settings.json") || !strings.Contains(got, "REDACTED") {
				t.Fatalf("%s dropped the diagnostic:\n%s", format, got)
			}
			switch format {
			case FormatJSON:
				if !strings.Contains(got, `"schema":"tripcord.diagnostic/v1"`) || !strings.Contains(got, `"incomplete":true`) {
					t.Fatalf("json = %s", got)
				}
			case FormatMD:
				if !strings.Contains(got, "The scan is incomplete.") {
					t.Fatalf("markdown = %s", got)
				}
			case FormatSARIF:
				if !strings.Contains(got, `"executionSuccessful": false`) || !strings.Contains(got, `"toolExecutionNotifications"`) {
					t.Fatalf("sarif = %s", got)
				}
				validateSARIF(t, got)
			case FormatText:
				if !strings.Contains(got, "diagnostic: ") || !strings.Contains(got, "scan incomplete") {
					t.Fatalf("text = %s", got)
				}
			case FormatGHA:
				if !strings.Contains(got, "::error::") {
					t.Fatalf("gha = %s", got)
				}
			default:
				t.Fatalf("unhandled format %s", format)
			}
		})
	}
}

func TestConfigKeyDoesNotLeakAcrossFormats(t *testing.T) {
	t.Parallel()
	finding := findings()[0]
	finding.Evidence = []model.Evidence{{
		Config: &model.ConfigRef{ID: "claude:user:~/.claude/settings.json", Key: `["hook","Stop","","command","~/bin/x.sh"]`},
	}}
	for _, format := range []Format{FormatJSON, FormatMD, FormatSARIF, FormatText, FormatGHA} {
		t.Run(string(format), func(t *testing.T) {
			t.Parallel()
			got := render(t, format, []model.Finding{finding})
			for _, forbidden := range []string{"/Users/vicuserzz", "?sig=", "secret-query"} {
				if strings.Contains(got, forbidden) {
					t.Fatalf("%s leaked %q: %s", format, forbidden, got)
				}
			}
			if strings.Contains(got, "\x1b") {
				t.Fatalf("%s leaked control: %s", format, got)
			}
		})
	}
}

package claude

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
	"github.com/vgmartinez/tripcord/internal/rules"
)

var allFormats = []output.Format{output.FormatJSON, output.FormatJSONL, output.FormatSARIF, output.FormatText, output.FormatGHA, output.FormatMD}

// A credential in a free-text "key: value" inside a hook command never
// reaches the payload, the key, or any rendered format, even with an
// output redactor that changes nothing: the source side alone keeps it
// out.
func TestHookColonCredentialNeverRendered(t *testing.T) {
	t.Parallel()
	for command, secret := range map[string]string{
		`echo "db password: PXC9" > .env`: "PXC9",
		"echo password: PXC17 > f":        "PXC17",
		"sh -c 'echo token: PXC16'":       "PXC16",
		"http h x-api-key:PXC13":          "PXC13",
	} {
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			got := discoverSettings(t, hookSettings(t, command))
			item := got.Items[0]
			if bytes.Contains(item.Payload, []byte(secret)) {
				t.Fatalf("payload leaks %s: %s", secret, item.Payload)
			}
			payloadCommand, _ := payloadField(t, item, "command")
			key, _ := payloadField(t, item, "key")
			if strings.Contains(key, secret) {
				t.Fatalf("key leaks %s: %s", secret, key)
			}
			finding := hookFinding(t, item, key, payloadCommand)
			for _, format := range allFormats {
				for name, redactor := range map[string]func(string) string{
					"default":     output.DefaultRedactor,
					"passthrough": func(s string) string { return s },
				} {
					rendered := render(t, format, finding, redactor)
					if strings.Contains(rendered, secret) {
						t.Errorf("%s with %s redactor leaks %s:\n%s", format, name, secret, rendered)
					}
					if !strings.Contains(rendered, "REDACTED") {
						t.Errorf("%s with %s redactor dropped the command:\n%s", format, name, rendered)
					}
				}
			}
		})
	}
}

// A credential glued to docker's -e flag in a hook command is redacted
// on the shared tool-flag path. The value must not survive into the
// payload, the item key, the evidence key, a diagnostic, or any report.
func TestHookDockerGluedPrivateKeyNeverRendered(t *testing.T) {
	t.Parallel()
	const secret = "QG01X"
	const command = "docker run -ePRIVATE_KEY=" + secret + " img"
	got := discoverSettings(t, hookSettings(t, command))
	if len(got.Items) != 1 {
		t.Fatalf("items = %+v diagnostics %q", got.Items, got.Diagnostics)
	}
	item := got.Items[0]
	if bytes.Contains(item.Payload, []byte(secret)) {
		t.Fatalf("payload leaks %s: %s", secret, item.Payload)
	}
	for _, diagnostic := range got.Diagnostics {
		if strings.Contains(diagnostic, secret) {
			t.Fatalf("diagnostic leaks %s: %s", secret, diagnostic)
		}
	}
	payloadCommand, _ := payloadField(t, item, "command")
	key, _ := payloadField(t, item, "key")
	if strings.Contains(key, secret) {
		t.Fatalf("key leaks %s: %s", secret, key)
	}
	if evidence := rules.ConfigEvidenceKey(item); evidence == "" || strings.Contains(evidence, secret) {
		t.Fatalf("evidence key = %q", evidence)
	}
	finding := hookFinding(t, item, key, payloadCommand)
	formats := []output.Format{output.FormatJSON, output.FormatMD, output.FormatSARIF, output.FormatText, output.FormatGHA}
	for _, format := range formats {
		for name, redactor := range map[string]func(string) string{
			"default":     output.DefaultRedactor,
			"passthrough": func(s string) string { return s },
		} {
			rendered := render(t, format, finding, redactor)
			if strings.Contains(rendered, secret) {
				t.Errorf("%s with %s redactor leaks %s:\n%s", format, name, secret, rendered)
			}
			if !strings.Contains(rendered, "REDACTED") {
				t.Errorf("%s with %s redactor dropped the command:\n%s", format, name, rendered)
			}
		}
	}
}

func hookFinding(t *testing.T, item model.ConfigItem, key, command string) model.Finding {
	t.Helper()
	id, err := item.ID()
	if err != nil {
		t.Fatal(err)
	}
	finding := model.Finding{
		Schema:     model.SchemaFinding,
		Rule:       "TC-CFG-010",
		Title:      "Hook runs " + command,
		Severity:   model.SeverityHigh,
		Decision:   model.DecisionWarn,
		Confidence: 0.9,
		Evidence: []model.Evidence{{
			Config:  &model.ConfigRef{ID: id, Key: key},
			Excerpt: command,
		}},
		Location: model.Location{Harness: item.Harness, Scope: item.Scope, Path: item.Path},
		Refs:     []string{"https://example.invalid/rules/TC-CFG-010"},
		Fix:      "Review " + command,
	}
	fp, err := model.Fingerprint(finding.Rule, finding.Location, finding.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	finding.Fingerprint = fp
	if err := finding.Validate(); err != nil {
		t.Fatal(err)
	}
	return finding
}

func render(t *testing.T, format output.Format, finding model.Finding, redactor func(string) string) string {
	t.Helper()
	var buffer bytes.Buffer
	sink, err := output.NewStdoutSink(format, &buffer, output.Options{Redactor: redactor, RepoRoot: "/work/repo", ToolVersion: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(finding); err != nil {
		t.Fatal(err)
	}
	if err := sink.Flush(); err != nil {
		t.Fatal(err)
	}
	return buffer.String()
}

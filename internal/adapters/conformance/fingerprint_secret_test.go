package conformance

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/fpkey"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
	"github.com/vgmartinez/tripcord/internal/rules"
)

// secretVariant is one definition of the "app" MCP server. Variants in a
// group differ only in a secret value that redaction removes.
type secretVariant struct {
	name string
	args []any
}

func envFlagArgs(privateKey, pass string) []any {
	return []any{"run", "-i", "--rm", "-e", "PRIVATE_KEY=" + privateKey, "-ePASS=" + pass, "ghcr.io/vgmartinez/app-mcp:1.2.0"}
}

func bearerTailArgs(apiKey, bearer string) []any {
	return []any{"run", "-i", "--rm", "-eAPI_KEY=" + apiKey + " Bearer " + bearer, "ghcr.io/vgmartinez/app-mcp:1.2.0"}
}

var secretVariantGroups = []struct {
	name     string
	variants []secretVariant
	secrets  []string
}{
	{
		name: "-e PRIVATE_KEY=X -ePASS=Y",
		variants: []secretVariant{
			{"base", envFlagArgs("zsX01q", "zsY01q")},
			{"PRIVATE_KEY differs", envFlagArgs("zsX02q", "zsY01q")},
			{"PASS differs", envFlagArgs("zsX01q", "zsY02q")},
		},
		secrets: []string{"zsX01q", "zsX02q", "zsY01q", "zsY02q"},
	},
	{
		name: "zsW07q bearer tail",
		variants: []secretVariant{
			{"base", bearerTailArgs("zsW06q", "zsW07q")},
			{"bearer differs", bearerTailArgs("zsW06q", "zsW08q")},
			{"API_KEY differs", bearerTailArgs("zsW05q", "zsW07q")},
		},
		secrets: []string{"zsW05q", "zsW06q", "zsW07q", "zsW08q"},
	},
}

// writeAppServer writes the "app" server, command docker with args, in
// every MCP config format the adapters read.
func writeAppServer(t *testing.T, root, home string, args []any) {
	t.Helper()
	server := map[string]any{"command": "docker", "args": args}
	encode := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	mcpServers := encode(map[string]any{"mcpServers": map[string]any{"app": server}})
	kittest.WriteFile(t, filepath.Join(root, ".mcp.json"), mcpServers)
	kittest.WriteFile(t, filepath.Join(root, ".cursor", "mcp.json"), mcpServers)
	kittest.WriteFile(t, filepath.Join(root, ".gemini", "settings.json"), mcpServers)
	kittest.WriteFile(t, filepath.Join(root, ".vscode", "mcp.json"), encode(map[string]any{"servers": map[string]any{"app": server}}))
	kittest.WriteFile(t, filepath.Join(root, ".codex", "config.toml"), "[mcp_servers.app]\ncommand = \"docker\"\nargs = "+encode(args)+"\n")
	kittest.WriteFile(t, filepath.Join(root, "opencode.json"), encode(map[string]any{"mcp": map[string]any{"app": map[string]any{"type": "local", "command": append([]any{"docker"}, args...)}}}))
	kittest.WriteFile(t, filepath.Join(home, ".copilot", "mcp-config.json"), mcpServers)
	kittest.WriteFile(t, filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), mcpServers)
}

// appServers discovers args in a fresh repository and home with
// fingerprint key k (nil selects s1) and returns the "app" MCP item of
// each adapter.
func appServers(t *testing.T, args []any, k *fpkey.Key) map[model.Harness]model.ConfigItem {
	t.Helper()
	root, home := t.TempDir(), t.TempDir()
	writeAppServer(t, root, home, args)
	got := discoverAll(t, root, allAdaptersWithKey(home, true, k))
	out := map[model.Harness]model.ConfigItem{}
	for _, items := range got.byAdapter {
		for _, item := range items {
			if item.Kind != model.ConfigKindMCPServer {
				continue
			}
			if _, dup := out[item.Harness]; dup {
				t.Fatalf("%s: more than one MCP item", item.Harness)
			}
			out[item.Harness] = item
		}
	}
	return out
}

// withoutKey is the payload without its evidence key: what a reader of
// the item sees apart from the key.
func withoutKey(t *testing.T, item model.ConfigItem) string {
	t.Helper()
	payload := kittest.Payload(t, item)
	delete(payload, "key")
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestMCPFingerprintTracksSecretValue checks that, with a fingerprint
// key (k1), the same MCP server with a different secret value gets a
// different fingerprint in every adapter, while the sanitized payload, the evidence key, and every
// report format carry none of the secrets. The payloads are identical
// across variants, so only the discriminator over removed values can
// tell them apart.
func TestMCPFingerprintTracksSecretValue(t *testing.T) {
	t.Parallel()
	harnesses := []model.Harness{
		model.HarnessClaude, model.HarnessCodex, model.HarnessCursor, model.HarnessCopilot,
		model.HarnessGemini, model.HarnessOpenCode, model.HarnessWindsurf, model.SurfaceVSCode,
	}
	rule := &rules.Rule{ID: "TC-TEST-005", Title: "secret variants", Fix: "none", Severity: model.SeverityHigh}
	for _, group := range secretVariantGroups {
		t.Run(group.name, func(t *testing.T) {
			t.Parallel()
			key := testKey(t)
			found := make([]map[model.Harness]model.ConfigItem, len(group.variants))
			for i, v := range group.variants {
				found[i] = appServers(t, v.args, key)
			}
			again := appServers(t, group.variants[0].args, key)
			var findings []model.Finding
			for _, harness := range harnesses {
				fps := map[string]string{}
				for i, v := range group.variants {
					item, ok := found[i][harness]
					if !ok {
						t.Fatalf("%s %s: no MCP item", harness, v.name)
					}
					for _, secret := range group.secrets {
						if strings.Contains(string(item.Payload), secret) {
							t.Fatalf("%s %s: payload leaks %q: %s", harness, v.name, secret, item.Payload)
						}
						if key := rules.ConfigEvidenceKey(item); strings.Contains(key, secret) {
							t.Fatalf("%s %s: evidence key leaks %q: %s", harness, v.name, secret, key)
						}
					}
					if !strings.Contains(string(item.Payload), kit.Redacted) {
						t.Fatalf("%s %s: nothing redacted: %s", harness, v.name, item.Payload)
					}
					if i > 0 && withoutKey(t, item) != withoutKey(t, found[0][harness]) {
						t.Fatalf("%s %s: sanitized payload differs from base:\n%s\n%s", harness, v.name, withoutKey(t, item), withoutKey(t, found[0][harness]))
					}
					finding, err := rules.Match{Rule: rule, Item: item}.Finding(model.SeverityHigh, model.DecisionWarn)
					if err != nil {
						t.Fatal(err)
					}
					if prev, dup := fps[finding.Fingerprint]; dup {
						t.Fatalf("%s: %s and %s share fingerprint %s", harness, prev, v.name, finding.Fingerprint)
					}
					fps[finding.Fingerprint] = v.name
					findings = append(findings, finding)
				}
				base, err := rules.Match{Rule: rule, Item: found[0][harness]}.Finding(model.SeverityHigh, model.DecisionWarn)
				if err != nil {
					t.Fatal(err)
				}
				rerun, err := rules.Match{Rule: rule, Item: again[harness]}.Finding(model.SeverityHigh, model.DecisionWarn)
				if err != nil {
					t.Fatal(err)
				}
				if base.Fingerprint != rerun.Fingerprint {
					t.Fatalf("%s: same config, fingerprints %s and %s", harness, base.Fingerprint, rerun.Fingerprint)
				}
			}
			for _, format := range []string{"json", "md", "sarif", "text", "gha"} {
				var buf bytes.Buffer
				handle, err := output.SelectSink(format, "", &buf, output.Options{Redactor: output.DefaultRedactor, RepoRoot: t.TempDir(), ToolVersion: "test"})
				if err != nil {
					t.Fatal(err)
				}
				for _, f := range findings {
					if err := handle.Write(f); err != nil {
						t.Fatal(err)
					}
				}
				if err := handle.Flush(); err != nil {
					t.Fatal(err)
				}
				report := buf.String()
				if !strings.Contains(report, "TC-TEST-005") {
					t.Fatalf("%s report has no finding:\n%s", format, report)
				}
				for _, secret := range group.secrets {
					if strings.Contains(report, secret) {
						t.Fatalf("%s output leaks %q:\n%s", format, secret, report)
					}
				}
			}
		})
	}
}

// TestMCPFingerprintS1KeepsShape is TestMCPFingerprintTracksSecretValue
// with no fingerprint key (s1): the variants of a group remove secrets of
// the same shape at the same positions, so every adapter gives them one
// fingerprint, and nothing in the payload, the evidence key, or any
// report format carries a secret.
func TestMCPFingerprintS1KeepsShape(t *testing.T) {
	t.Parallel()
	harnesses := []model.Harness{
		model.HarnessClaude, model.HarnessCodex, model.HarnessCursor, model.HarnessCopilot,
		model.HarnessGemini, model.HarnessOpenCode, model.HarnessWindsurf, model.SurfaceVSCode,
	}
	rule := &rules.Rule{ID: "TC-TEST-005", Title: "secret variants", Fix: "none", Severity: model.SeverityHigh}
	for _, group := range secretVariantGroups {
		t.Run(group.name, func(t *testing.T) {
			t.Parallel()
			var findings []model.Finding
			found := make([]map[model.Harness]model.ConfigItem, len(group.variants))
			for i, v := range group.variants {
				found[i] = appServers(t, v.args, nil)
			}
			for _, harness := range harnesses {
				var want string
				for i, v := range group.variants {
					item, ok := found[i][harness]
					if !ok {
						t.Fatalf("%s %s: no MCP item", harness, v.name)
					}
					key := rules.ConfigEvidenceKey(item)
					for _, secret := range group.secrets {
						if strings.Contains(string(item.Payload), secret) || strings.Contains(key, secret) {
							t.Fatalf("%s %s: payload or key leaks %q: %s", harness, v.name, secret, item.Payload)
						}
					}
					finding, err := rules.Match{Rule: rule, Item: item}.Finding(model.SeverityHigh, model.DecisionWarn)
					if err != nil {
						t.Fatal(err)
					}
					if mode := model.FingerprintMode(finding.Evidence); mode != "s1" {
						t.Fatalf("%s %s: fingerprint mode %q, want s1: %s", harness, v.name, mode, key)
					}
					if i == 0 {
						want = finding.Fingerprint
					} else if finding.Fingerprint != want {
						t.Fatalf("%s: %s fingerprint %s, base %s: same shape and position must match in s1", harness, v.name, finding.Fingerprint, want)
					}
					findings = append(findings, finding)
				}
			}
			for _, format := range []string{"json", "md", "sarif", "text", "gha"} {
				var buf bytes.Buffer
				handle, err := output.SelectSink(format, "", &buf, output.Options{Redactor: output.DefaultRedactor, RepoRoot: t.TempDir(), ToolVersion: "test"})
				if err != nil {
					t.Fatal(err)
				}
				for _, f := range findings {
					if err := handle.Write(f); err != nil {
						t.Fatal(err)
					}
				}
				if err := handle.Flush(); err != nil {
					t.Fatal(err)
				}
				for _, secret := range group.secrets {
					if strings.Contains(buf.String(), secret) {
						t.Fatalf("%s output leaks %q:\n%s", format, secret, buf.String())
					}
				}
			}
		})
	}
}

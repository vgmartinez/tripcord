package conformance

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/fpkey"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
	"github.com/vgmartinez/tripcord/internal/rules"
)

// These tests pin the two fingerprint modes across every adapter that
// reads MCP servers:
//
//   - k1 (fingerprint key set): the same MCP server with a different
//     secret gets a different fingerprint.
//   - s1 (no key): the same MCP server with a rotated secret keeps its
//     fingerprint, and entries identical after sanitizing are told
//     apart only by their ordinal.
//
// In both, no secret and no key reaches a payload, an evidence key, or
// any output format.

var (
	k1Discriminator = regexp.MustCompile(`^sig:k1:[0-9a-f]{16}#[0-9]+$`)
	// s1Discriminator is field[n] entries and an ordinal: nothing that
	// could be a digest of a value.
	s1Discriminator = regexp.MustCompile(`^sig:s1:[^\[\],#]*\[[0-9]+\](,[^\[\],#]*\[[0-9]+\])*#([0-9]+)$`)
)

var modeHarnesses = []model.Harness{
	model.HarnessClaude, model.HarnessCodex, model.HarnessCursor, model.HarnessCopilot,
	model.HarnessGemini, model.HarnessOpenCode, model.HarnessWindsurf, model.SurfaceVSCode,
}

var modeRule = &rules.Rule{ID: "TC-TEST-006", Title: "fingerprint modes", Fix: "none", Severity: model.SeverityHigh}

type modeVariant struct {
	name string
	args []any
}

func modeEnvFlagArgs(privateKey, pass string) []any {
	return []any{"run", "-i", "--rm", "-e", "PRIVATE_KEY=" + privateKey, "-ePASS=" + pass, "ghcr.io/vgmartinez/app-mcp:1.2.0"}
}

func modeBearerTailArgs(apiKey, bearer string) []any {
	return []any{"run", "-i", "--rm", "-eAPI_KEY=" + apiKey + " Bearer " + bearer, "ghcr.io/vgmartinez/app-mcp:1.2.0"}
}

// modeGroups are the two cases of the conformance test in PR #12: each
// variant changes only secret values that redaction removes.
var modeGroups = []struct {
	name     string
	variants []modeVariant
	secrets  []string
}{
	{
		name: "-e PRIVATE_KEY=X -ePASS=Y",
		variants: []modeVariant{
			{"base", modeEnvFlagArgs("zsX01q", "zsY01q")},
			{"PRIVATE_KEY differs", modeEnvFlagArgs("zsX02q", "zsY01q")},
			{"PASS differs", modeEnvFlagArgs("zsX01q", "zsY02q")},
		},
		secrets: []string{"zsX01q", "zsX02q", "zsY01q", "zsY02q"},
	},
	{
		name: "zsW07q bearer tail",
		variants: []modeVariant{
			{"base", modeBearerTailArgs("zsW06q", "zsW07q")},
			{"bearer differs", modeBearerTailArgs("zsW06q", "zsW08q")},
			{"API_KEY differs", modeBearerTailArgs("zsW05q", "zsW07q")},
		},
		secrets: []string{"zsW05q", "zsW06q", "zsW07q", "zsW08q"},
	},
}

func testKey(t *testing.T) *fpkey.Key {
	t.Helper()
	return kittest.FingerprintKey()
}

func modeEncode(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// writeModeServer writes the "app" server, command docker with args, in
// every MCP config format the adapters read.
func writeModeServer(t *testing.T, root, home string, args []any) {
	t.Helper()
	server := map[string]any{"command": "docker", "args": args}
	mcpServers := modeEncode(t, map[string]any{"mcpServers": map[string]any{"app": server}})
	kittest.WriteFile(t, filepath.Join(root, ".mcp.json"), mcpServers)
	kittest.WriteFile(t, filepath.Join(root, ".cursor", "mcp.json"), mcpServers)
	kittest.WriteFile(t, filepath.Join(root, ".gemini", "settings.json"), mcpServers)
	kittest.WriteFile(t, filepath.Join(root, ".vscode", "mcp.json"), modeEncode(t, map[string]any{"servers": map[string]any{"app": server}}))
	kittest.WriteFile(t, filepath.Join(root, ".codex", "config.toml"), "[mcp_servers.app]\ncommand = \"docker\"\nargs = "+modeEncode(t, args)+"\n")
	kittest.WriteFile(t, filepath.Join(root, "opencode.json"), modeEncode(t, map[string]any{"mcp": map[string]any{"app": map[string]any{"type": "local", "command": append([]any{"docker"}, args...)}}}))
	kittest.WriteFile(t, filepath.Join(home, ".copilot", "mcp-config.json"), mcpServers)
	kittest.WriteFile(t, filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), mcpServers)
}

// modeServers discovers args in a fresh repository and the given home
// (a fresh one when home is "") and returns each adapter's MCP item.
func modeServers(t *testing.T, args []any, k *fpkey.Key, home string) map[model.Harness]model.ConfigItem {
	t.Helper()
	root := t.TempDir()
	if home == "" {
		home = t.TempDir()
	}
	writeModeServer(t, root, home, args)
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
	for _, h := range modeHarnesses {
		if _, ok := out[h]; !ok {
			t.Fatalf("%s: no MCP item", h)
		}
	}
	return out
}

func modeFinding(t *testing.T, item model.ConfigItem) model.Finding {
	t.Helper()
	f, err := rules.Match{Rule: modeRule, Item: item}.Finding(model.SeverityHigh, model.DecisionWarn)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func keyParts(t *testing.T, item model.ConfigItem) []string {
	t.Helper()
	var parts []string
	if err := json.Unmarshal([]byte(rules.ConfigEvidenceKey(item)), &parts); err != nil {
		t.Fatalf("%s: evidence key %q: %v", item.Harness, rules.ConfigEvidenceKey(item), err)
	}
	return parts
}

func discriminatorOf(t *testing.T, item model.ConfigItem) string {
	t.Helper()
	parts := keyParts(t, item)
	return parts[len(parts)-1]
}

func modePayloadWithoutKey(t *testing.T, item model.ConfigItem) string {
	t.Helper()
	payload := kittest.Payload(t, item)
	delete(payload, "key")
	return modeEncode(t, payload)
}

// assertNoLeak fails when any secret or the test key appears in the
// item's payload or evidence key.
func assertNoLeak(t *testing.T, item model.ConfigItem, secrets []string) {
	t.Helper()
	for _, s := range append(slicesClone(secrets), kittest.TestFingerprintKey) {
		if strings.Contains(string(item.Payload), s) {
			t.Fatalf("%s: payload leaks %q: %s", item.Harness, s, item.Payload)
		}
		if strings.Contains(rules.ConfigEvidenceKey(item), s) {
			t.Fatalf("%s: evidence key leaks %q", item.Harness, s)
		}
	}
	if !strings.Contains(string(item.Payload), kit.Redacted) {
		t.Fatalf("%s: nothing redacted: %s", item.Harness, item.Payload)
	}
}

func slicesClone(in []string) []string { return append([]string(nil), in...) }

// assertFormatsClean renders findings in every format and fails when a
// secret or the test key appears in any of them.
func assertFormatsClean(t *testing.T, findings []model.Finding, secrets []string) {
	t.Helper()
	for _, format := range []string{"json", "md", "sarif", "text", "gha"} {
		var buf bytes.Buffer
		handle, err := output.SelectSink(format, "", &buf, output.Options{Redactor: output.DefaultRedactor, RepoRoot: t.TempDir(), ToolVersion: "test"})
		if err != nil {
			t.Fatal(err)
		}
		if err := handle.SetDiagnostics([]output.Diagnostic{{Message: "fingerprint mode diagnostic"}}); err != nil {
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
		if !strings.Contains(report, modeRule.ID) {
			t.Fatalf("%s report has no finding:\n%s", format, report)
		}
		for _, s := range append(slicesClone(secrets), kittest.TestFingerprintKey) {
			if strings.Contains(report, s) {
				t.Fatalf("%s output leaks %q:\n%s", format, s, report)
			}
		}
	}
}

// TestK1SecretChangesFingerprint is PR #12's conformance test run with a
// fingerprint key: the same MCP server with a different secret gets a
// different fingerprint in every adapter.
func TestK1SecretChangesFingerprint(t *testing.T) {
	t.Parallel()
	k := testKey(t)
	for _, group := range modeGroups {
		t.Run(group.name, func(t *testing.T) {
			t.Parallel()
			found := make([]map[model.Harness]model.ConfigItem, len(group.variants))
			for i, v := range group.variants {
				found[i] = modeServers(t, v.args, k, "")
			}
			again := modeServers(t, group.variants[0].args, k, "")
			var findings []model.Finding
			for _, h := range modeHarnesses {
				seen := map[string]string{}
				for i, v := range group.variants {
					item := found[i][h]
					assertNoLeak(t, item, group.secrets)
					if d := discriminatorOf(t, item); !k1Discriminator.MatchString(d) {
						t.Fatalf("%s %s: discriminator %q has no k1 marker", h, v.name, d)
					}
					if i > 0 && modePayloadWithoutKey(t, item) != modePayloadWithoutKey(t, found[0][h]) {
						t.Fatalf("%s %s: sanitized payload differs from base", h, v.name)
					}
					f := modeFinding(t, item)
					if prev, dup := seen[f.Fingerprint]; dup {
						t.Fatalf("%s: %s and %s share fingerprint %s", h, prev, v.name, f.Fingerprint)
					}
					seen[f.Fingerprint] = v.name
					findings = append(findings, f)
				}
				if a, b := modeFinding(t, found[0][h]).Fingerprint, modeFinding(t, again[h]).Fingerprint; a != b {
					t.Fatalf("%s: same config, fingerprints %s and %s", h, a, b)
				}
			}
			assertFormatsClean(t, findings, group.secrets)
		})
	}
}

// TestS1RotationKeepsFingerprint is the s1 counterpart: with no key, a
// rotated secret keeps the fingerprint, the discriminator is structural,
// and a k1 fingerprint of the same entry never equals the s1 one.
func TestS1RotationKeepsFingerprint(t *testing.T) {
	t.Parallel()
	for _, group := range modeGroups {
		t.Run(group.name, func(t *testing.T) {
			t.Parallel()
			found := make([]map[model.Harness]model.ConfigItem, len(group.variants))
			for i, v := range group.variants {
				found[i] = modeServers(t, v.args, nil, "")
			}
			keyed := modeServers(t, group.variants[0].args, testKey(t), "")
			var findings []model.Finding
			for _, h := range modeHarnesses {
				base := modeFinding(t, found[0][h])
				for i, v := range group.variants {
					item := found[i][h]
					assertNoLeak(t, item, group.secrets)
					d := discriminatorOf(t, item)
					m := s1Discriminator.FindStringSubmatch(d)
					if m == nil || m[2] != "0" {
						t.Fatalf("%s %s: discriminator %q is not s1 with ordinal 0", h, v.name, d)
					}
					f := modeFinding(t, item)
					if f.Fingerprint != base.Fingerprint {
						t.Fatalf("%s %s: rotated secret changed the fingerprint: %s vs %s", h, v.name, f.Fingerprint, base.Fingerprint)
					}
					findings = append(findings, f)
				}
				if k1 := modeFinding(t, keyed[h]); k1.Fingerprint == base.Fingerprint {
					t.Fatalf("%s: k1 and s1 fingerprints collide: %s", h, k1.Fingerprint)
				}
			}
			assertFormatsClean(t, findings, group.secrets)
		})
	}
}

// hookDuplicateFiles writes, for each harness that reads a hook array,
// two hooks that are identical after sanitizing: they differ only in
// the --token value.
func hookDuplicateFiles(t *testing.T, root, first, second string) map[model.Harness]string {
	t.Helper()
	hook := func(token string) map[string]any {
		return map[string]any{"type": "command", "command": "notify --token " + token}
	}
	grouped := modeEncode(t, map[string]any{"hooks": map[string]any{"Stop": []any{
		map[string]any{"hooks": []any{hook(first), hook(second)}},
	}}})
	flat := modeEncode(t, map[string]any{"version": 1, "hooks": map[string]any{"stop": []any{
		map[string]any{"command": "notify --token " + first}, map[string]any{"command": "notify --token " + second},
	}}})
	copilot := modeEncode(t, map[string]any{"version": 1, "hooks": map[string]any{"sessionEnd": []any{
		map[string]any{"type": "command", "bash": "notify --token " + first}, map[string]any{"type": "command", "bash": "notify --token " + second},
	}}})
	windsurf := modeEncode(t, map[string]any{"hooks": map[string]any{"post_cascade_response": []any{
		map[string]any{"command": "notify --token " + first}, map[string]any{"command": "notify --token " + second},
	}}})
	files := map[model.Harness]string{
		model.HarnessClaude:   ".claude/settings.json",
		model.HarnessCodex:    ".codex/hooks.json",
		model.HarnessGemini:   ".gemini/settings.json",
		model.HarnessCursor:   ".cursor/hooks.json",
		model.HarnessCopilot:  ".github/hooks/notify.json",
		model.HarnessWindsurf: ".windsurf/hooks.json",
	}
	content := map[model.Harness]string{
		model.HarnessClaude: grouped, model.HarnessCodex: grouped, model.HarnessGemini: grouped,
		model.HarnessCursor: flat, model.HarnessCopilot: copilot, model.HarnessWindsurf: windsurf,
	}
	for h, rel := range files {
		kittest.WriteFile(t, filepath.Join(root, filepath.FromSlash(rel)), content[h])
	}
	return files
}

func duplicateHooks(t *testing.T, k *fpkey.Key, first, second string) map[model.Harness][]model.ConfigItem {
	t.Helper()
	root := t.TempDir()
	files := hookDuplicateFiles(t, root, first, second)
	got := discoverAll(t, root, allAdaptersWithKey(t.TempDir(), false, k))
	out := map[model.Harness][]model.ConfigItem{}
	for h, rel := range files {
		for _, item := range got.byAdapter[h] {
			if item.Kind == model.ConfigKindHook && item.Path == rel {
				out[h] = append(out[h], item)
			}
		}
		if len(out[h]) != 2 {
			t.Fatalf("%s: %d hook items from %s, want 2", h, len(out[h]), rel)
		}
	}
	return out
}

// TestS1DuplicatesDifferOnlyByOrdinal checks that two hooks identical
// after sanitizing get keys that differ only in the s1 ordinal, so their
// fingerprints differ, and that rotating both secrets changes neither.
// In k1 the HMAC alone tells them apart.
func TestS1DuplicatesDifferOnlyByOrdinal(t *testing.T) {
	t.Parallel()
	secrets := []string{"zsD01q", "zsD02q", "zsD03q", "zsD04q"}
	s1 := duplicateHooks(t, nil, "zsD01q", "zsD02q")
	rotated := duplicateHooks(t, nil, "zsD03q", "zsD04q")
	k1 := duplicateHooks(t, testKey(t), "zsD01q", "zsD02q")
	var findings []model.Finding
	for h, items := range s1 {
		ordinals := map[string]bool{}
		var prefix string
		for i, item := range items {
			assertNoLeak(t, item, secrets)
			parts := keyParts(t, item)
			m := s1Discriminator.FindStringSubmatch(parts[len(parts)-1])
			if m == nil {
				t.Fatalf("%s: discriminator %q is not s1", h, parts[len(parts)-1])
			}
			ordinals[m[2]] = true
			withoutOrdinal := modeEncode(t, append(parts[:len(parts)-1:len(parts)-1], strings.TrimSuffix(parts[len(parts)-1], "#"+m[2])))
			if i == 0 {
				prefix = withoutOrdinal
			} else if withoutOrdinal != prefix {
				t.Fatalf("%s: duplicates differ in more than the ordinal: %s vs %s", h, withoutOrdinal, prefix)
			}
			findings = append(findings, modeFinding(t, item))
		}
		if !ordinals["0"] || !ordinals["1"] {
			t.Fatalf("%s: ordinals %v, want 0 and 1", h, ordinals)
		}
		a, b := modeFinding(t, items[0]).Fingerprint, modeFinding(t, items[1]).Fingerprint
		if a == b {
			t.Fatalf("%s: duplicates share fingerprint %s", h, a)
		}
		got := map[string]bool{modeFinding(t, rotated[h][0]).Fingerprint: true, modeFinding(t, rotated[h][1]).Fingerprint: true}
		if !got[a] || !got[b] {
			t.Fatalf("%s: rotating both secrets changed the fingerprints", h)
		}
		k1a, k1b := modeFinding(t, k1[h][0]).Fingerprint, modeFinding(t, k1[h][1]).Fingerprint
		if k1a == k1b || k1a == a || k1a == b || k1b == a || k1b == b {
			t.Fatalf("%s: k1 duplicates %s %s, s1 %s %s", h, k1a, k1b, a, b)
		}
		for _, item := range k1[h] {
			if d := discriminatorOf(t, item); !k1Discriminator.MatchString(d) {
				t.Fatalf("%s: k1 discriminator %q", h, d)
			}
		}
	}
	assertFormatsClean(t, findings, secrets)
}

// secretShapes are 13 realistic credential shapes, each triggering a
// different number of output.secretPatterns matches (zero for the
// generic one, one or more for the provider-shaped ones) when the OLD
// removal-log-based s1 discriminator counted every detection pass. The
// NEW discriminator (internal/adapters/kit.StructuralDiscriminator) scans
// only the final sanitized payload for [REDACTED] markers, so it must
// produce the exact same structural key for every shape in the same
// position: the shape of a secret, like its value, must never leak
// through the s1 discriminator (researcher review, blocker 1).
var secretShapes = []struct {
	name  string
	value string
}{
	{"generic", "zsG01q-opaque-token-value-0123456789"},
	{"github PAT", "ghp_" + strings.Repeat("a1B2c3", 7)},
	{"github fine-grained PAT", "github_pat_" + strings.Repeat("a1B2c3", 4)},
	{"gitlab PAT", "glpat-" + strings.Repeat("a1B2c3", 4)},
	{"openai-style", "sk-" + strings.Repeat("a1B2c3", 4)},
	{"stripe-style live key", "sk_live_" + strings.Repeat("a1B2c3", 4)},
	{"slack bot token", "xoxb-" + strings.Repeat("a1B2c3", 2)},
	{"npm token", "npm_" + strings.Repeat("a1B2c3", 4)},
	{"huggingface token", "hf_" + strings.Repeat("a1B2c3", 4)},
	{"google oauth token", "ya29." + strings.Repeat("a1B2c3", 4)},
	{"google api key", "AIza" + strings.Repeat("a1B2c3d4e", 3) + "aaaaaaaa"},
	{"aws access key", "AKIA" + "ABCD1234EFGH5678"},
	{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
}

// TestS1DiscriminatorShapeIndependent is the test the researcher asked
// for: the s1 key is unchanged for 13 secret shapes x all positions x
// all adapters. "Position" varies the shape of the surrounding redacted
// field: a credential-named env assignment (-e PRIVATE_KEY=...) and a
// bearer-token tail glued onto another flag's value (-eAPI_KEY=... Bearer
// ...), the same two shapes modeGroups already covers for rotation.
func TestS1DiscriminatorShapeIndependent(t *testing.T) {
	t.Parallel()
	positions := []struct {
		name string
		args func(secret string) []any
	}{
		{"env assignment", func(secret string) []any { return modeEnvFlagArgs(secret, "zsY01q") }},
		{"bearer tail", func(secret string) []any { return modeBearerTailArgs("zsW05q", secret) }},
	}
	for _, position := range positions {
		t.Run(position.name, func(t *testing.T) {
			t.Parallel()
			var want map[model.Harness]string
			for _, shape := range secretShapes {
				items := modeServers(t, position.args(shape.value), nil, "")
				got := map[model.Harness]string{}
				for _, h := range modeHarnesses {
					item := items[h]
					assertNoLeak(t, item, []string{shape.value})
					d := discriminatorOf(t, item)
					m := s1Discriminator.FindStringSubmatch(d)
					if m == nil {
						t.Fatalf("%s %s: discriminator %q is not s1", h, shape.name, d)
					}
					got[h] = strings.TrimSuffix(d, "#"+m[2])
				}
				if want == nil {
					want = got
					continue
				}
				for h, structural := range got {
					if structural != want[h] {
						t.Fatalf("%s: %s discriminator %q, want %q (same as %s)", h, shape.name, structural, want[h], secretShapes[0].name)
					}
				}
			}
		})
	}
}

// TestFingerprintModesDeterministicAndHomeIndependent discovers the same
// configuration 200 times per mode, each time under a different home
// directory (including homes of different depth), and requires every
// item's fingerprint to match the first run.
func TestFingerprintModesDeterministicAndHomeIndependent(t *testing.T) {
	t.Parallel()
	args := modeGroups[0].variants[0].args
	for _, mode := range []struct {
		name string
		key  *fpkey.Key
	}{{"k1", testKey(t)}, {"s1", nil}} {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()
			fingerprints := func(home string) map[model.Harness]string {
				out := map[model.Harness]string{}
				for h, item := range modeServers(t, args, mode.key, home) {
					out[h] = modeFinding(t, item).Fingerprint
				}
				return out
			}
			want := fingerprints("")
			homes := []string{
				filepath.Join(t.TempDir(), "h"),
				filepath.Join(t.TempDir(), "users", "someone-else", "nested", "home"),
			}
			for i := range 200 {
				home := ""
				if i < len(homes) {
					home = homes[i]
				}
				got := fingerprints(home)
				for h, fp := range want {
					if got[h] != fp {
						t.Fatalf("run %d %s: fingerprint %s, want %s", i, h, got[h], fp)
					}
				}
			}
		})
	}
}

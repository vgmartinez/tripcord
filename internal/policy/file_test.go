package policy

import (
	"strings"
	"testing"
)

// specSample is the policy.yaml sample from the spec, verbatim except
// for the sha256, which the sample elides as 9f2c...e1.
const specSample = `# .tripcord/policy.yaml  (versionado en el repo)
version: 1
mode: enforce            # enforce | warn | audit
harnesses: [claude, cursor, codex, copilot, gemini, opencode, windsurf]
rules:
  include: ["TC-CFG-*", "TC-SEC-*", "TC-FOR-*"]
  severity_overrides:
    TC-CFG-011: high
  exceptions:
    - rule: TC-CFG-001
      path: .claude/settings.json
      sha256: 9f2c0000000000000000000000000000000000000000000000000000000000e1        # se invalida si el hook cambia
      reason: "hook de formato aprobado por @plataforma"
      expires: 2027-01-31
custom:
  - id: ACME-001
    when: event.kind == "tool_call" && event.tool == "shell"
    deny_if: event.command.matches("(?i)railway\\s+(volume|environment)\\s+delete")
    message: "Borrado de infraestructura bloqueado: pide token con alcance"
secrets:
  rulesets: [gitleaks-default, tripcord-ai]
  store: fingerprint-only   # nunca guardamos el valor
privacy:
  egress: none              # no hay modo con red: todo es local
  redact: true
cloud:
  report_channel: [hook-message, git-notes]
`

const sampleSHA = "9f2c0000000000000000000000000000000000000000000000000000000000e1"

func TestParseSpecSample(t *testing.T) {
	f, err := Parse([]byte(specSample))
	if err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 || f.Mode != ModeEnforce || len(f.Harnesses) != 7 || len(f.Rules.Include) != 3 {
		t.Fatalf("file = %+v", f)
	}
	if f.Rules.SeverityOverrides["TC-CFG-011"] != "high" {
		t.Fatal("severity override lost")
	}
	ex := f.Rules.Exceptions[0]
	if ex.Rule != "TC-CFG-001" || ex.Path != ".claude/settings.json" || ex.SHA256 != sampleSHA || ex.Expires != "2027-01-31" {
		t.Fatalf("exception = %+v", ex)
	}
	c := f.Custom[0]
	if c.ID != "ACME-001" || !strings.Contains(c.DenyIf, `railway\\s+`) {
		t.Fatalf("custom = %+v", c)
	}
	if f.Secrets.Store != SecretStoreFingerprintOnly || f.Privacy.Egress != EgressNone || !*f.Privacy.Redact || len(f.Cloud.ReportChannel) != 2 {
		t.Fatalf("sections = %+v %+v %+v", f.Secrets, f.Privacy, f.Cloud)
	}
}

func TestParseSpecSampleElidedHash(t *testing.T) {
	doc := strings.Replace(specSample, sampleSHA, "9f2c...e1", 1)
	if _, err := Parse([]byte(doc)); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("err = %v", err)
	}
}

func TestParsePackAndExtends(t *testing.T) {
	doc := "version: 1\npack: tripcord/core@2026.11\nextends: [../org/policy.yaml, acme/org-policy@2026.11]\n"
	f, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Pack) != 1 || len(f.Extends) != 2 {
		t.Fatalf("file = %+v", f)
	}
	f, err = Parse([]byte("version: 1\nextends: ./base.yaml\npack: [tripcord/core@2026.11, acme/extra@2026.10]\n"))
	if err != nil || len(f.Extends) != 1 || len(f.Pack) != 2 {
		t.Fatalf("file = %+v, %v", f, err)
	}
}

func TestParseRejects(t *testing.T) {
	r := strings.NewReplacer
	cases := map[string]string{
		"version 2":            r("version: 1", "version: 2").Replace(specSample),
		"no version":           r("version: 1\n", "").Replace(specSample),
		"bad mode":             r("mode: enforce ", "mode: block ").Replace(specSample),
		"bad fail-on":          specSample + "fail-on: severe\n",
		"egress":               r("egress: none ", "egress: https ").Replace(specSample),
		"store":                r("store: fingerprint-only", "store: plaintext").Replace(specSample),
		"report channel":       r("[hook-message, git-notes]", "[slack]").Replace(specSample),
		"bad harness":          r("opencode, windsurf]", "opencode, vscode]").Replace(specSample),
		"twice harness":        r("[claude, cursor,", "[claude, claude,").Replace(specSample),
		"empty include":        r(`include: ["TC-CFG-*", "TC-SEC-*", "TC-FOR-*"]`, "include: []").Replace(specSample),
		"bad include":          r(`"TC-CFG-*"`, `"TC-[CFG"`).Replace(specSample),
		"bad override id":      r("TC-CFG-011: high", "tc-cfg-11: high").Replace(specSample),
		"bad override sev":     r("TC-CFG-011: high", "TC-CFG-011: severe").Replace(specSample),
		"exception rule":       r("- rule: TC-CFG-001", "- rule: TC-CFG").Replace(specSample),
		"exception path":       r("path: .claude/settings.json", "path: /etc/passwd").Replace(specSample),
		"exception dotdot":     r("path: .claude/settings.json", "path: ../x/settings.json").Replace(specSample),
		"exception reason":     r(`reason: "hook de formato aprobado por @plataforma"`, `reason: ""`).Replace(specSample),
		"exception expires":    r("expires: 2027-01-31", "expires: next year").Replace(specSample),
		"no expires":           r("      expires: 2027-01-31\n", "").Replace(specSample),
		"no sha":               r("      sha256: "+sampleSHA+"        # se invalida si el hook cambia\n", "").Replace(specSample),
		"custom no deny_if":    r(`    deny_if: event.command.matches("(?i)railway\\s+(volume|environment)\\s+delete")`+"\n", "").Replace(specSample),
		"custom no message":    r(`    message: "Borrado de infraestructura bloqueado: pide token con alcance"`+"\n", "").Replace(specSample),
		"custom bad id":        r("- id: ACME-001", "- id: acme").Replace(specSample),
		"custom bad sev":       r("    message:", "    severity: huge\n    message:").Replace(specSample),
		"ruleset name":         r("[gitleaks-default, tripcord-ai]", "[\"Gitleaks Default\"]").Replace(specSample),
		"unknown key":          specSample + "telemetry: true\n",
		"unknown nested":       r("  redact: true", "  redact: true\n  upload: false").Replace(specSample),
		"duplicate key":        specSample + "mode: audit\n",
		"bad pack":             specSample + "pack: core\n",
		"bad extends":          specSample + "extends: org-policy\n",
		"locked bad rule":      specSample + "locked:\n  rules: [\"TC-[\"]\n",
		"locked bad exception": specSample + "locked:\n  exceptions: [\"TC-[\"]\n",
		"two documents":        specSample + "---\nversion: 1\n",
		"empty":                "",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestParseSizeLimit(t *testing.T) {
	doc := specSample + "# " + strings.Repeat("x", MaxFileBytes) + "\n"
	if _, err := Parse([]byte(doc)); err == nil {
		t.Fatal("oversized policy accepted")
	}
}

func TestParseExtends(t *testing.T) {
	for s, want := range map[string]ExtendsKind{
		"./base.yaml":             ExtendsPath,
		"../org/policy.yaml":      ExtendsPath,
		"/etc/tripcord/org.yaml":  ExtendsPath,
		"acme/org-policy@2026.11": ExtendsPack,
	} {
		kind, _, err := ParseExtends(s)
		if err != nil || kind != want {
			t.Errorf("ParseExtends(%q) = %v, %v", s, kind, err)
		}
	}
	for _, s := range []string{"base.yaml", "acme/org-policy", "", "https://example.com/p.yaml"} {
		if _, _, err := ParseExtends(s); err == nil {
			t.Errorf("ParseExtends(%q) succeeded", s)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(specSample))
	f.Add([]byte("version: 1\nlocked:\n  mode: true\n  rules: [TC-CFG-*]\n"))
	f.Add([]byte("version: 1\nextends: [./a.yaml, acme/p@2026.11]\n"))
	f.Add([]byte("a: &a [*a, *a, *a]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := Parse(data)
		if err != nil {
			return
		}
		if file.Version != Version {
			t.Fatalf("accepted version %d", file.Version)
		}
		if err := file.Validate(); err != nil {
			t.Fatalf("Parse accepted what Validate rejects: %v", err)
		}
	})
}

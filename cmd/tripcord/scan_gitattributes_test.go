package main

import (
	"bytes"
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
	replaceInFile(embedded.BootstrapPath, `"$cached" scan --config "$repo_root" >&2`+"\n", `"$cached" scan --config "$repo_root" >&2`+"\r\n")(t, dir)
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

package embedded

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

const wantGitattributes = gitattributesComment + "\n" +
	"/.tripcord/bootstrap.sh text eol=lf\n" +
	"/.tripcord/embed.json text eol=lf\n" +
	"/.github/workflows/tripcord.yml text eol=lf\n" +
	"/.github/hooks/tripcord.json text eol=lf\n"

func TestMergeGitattributes(t *testing.T) {
	for _, tc := range []struct {
		name, old string
		exists    bool
		want      string
	}{
		{name: "new", want: wantGitattributes},
		{name: "empty", exists: true, want: wantGitattributes},
		{name: "user lines kept", old: "*.png binary\n", exists: true, want: "*.png binary\n" + wantGitattributes},
		{name: "no trailing newline", old: "*.png binary", exists: true, want: "*.png binary\n" + wantGitattributes},
		{name: "already there", old: "*.png binary\n" + wantGitattributes, exists: true, want: "*.png binary\n" + wantGitattributes},
		{
			name: "one line missing", exists: true,
			old:  strings.Replace(wantGitattributes, "/.tripcord/embed.json text eol=lf\n", "", 1),
			want: strings.Replace(wantGitattributes, "/.tripcord/embed.json text eol=lf\n", "", 1) + "/.tripcord/embed.json text eol=lf\n",
		},
		{
			name: "CRLF file", exists: true,
			old:  "*.png binary\r\n",
			want: "*.png binary\r\n" + strings.ReplaceAll(wantGitattributes, "\n", "\r\n"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mergeGitattributes([]byte(tc.old), tc.exists)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("got %q\nwant %q", got, tc.want)
			}
			again, err := mergeGitattributes(got, true)
			if err != nil || string(again) != string(got) {
				t.Fatalf("second merge changed the file: %q, %v", again, err)
			}
		})
	}
}

func toCRLF(t *testing.T, dir string, rels ...string) {
	t.Helper()
	for _, rel := range rels {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		write(t, dir, rel, strings.ReplaceAll(string(raw), "\n", "\r\n"))
	}
}

func TestCheckCRLFCheckout(t *testing.T) {
	dir := embed(t, model.HarnessClaude, model.HarnessCopilot)
	toCRLF(t, dir, BootstrapPath, ManifestPath, WorkflowPath, ClaudeSettingsPath, CopilotHooksPath, CopilotSetupStepsPath)
	if got := check(t, dir); len(got) != 0 {
		t.Fatalf("hits = %+v", got)
	}
	replace(t, dir, BootstrapPath, `[ "$got" = "$want" ]`, "true")
	want := []guardHit{{model.SurfaceGeneric, BootstrapPath, subjectBootstrap, StateChanged}}
	if got := check(t, dir); !slices.Equal(got, want) {
		t.Fatalf("an edit under CRLF: hits = %+v\nwant %+v", got, want)
	}
}

func TestInitRewritesCRLFOwnFiles(t *testing.T) {
	dir := embed(t, model.HarnessClaude)
	toCRLF(t, dir, BootstrapPath, WorkflowPath)
	changes, err := Plan(dir, Options{Embed: true, Harnesses: []model.Harness{model.HarnessClaude}, Pin: testPin})
	if err != nil {
		t.Fatalf("a CRLF checkout needs --force: %v", err)
	}
	if _, err := Apply(dir, changes); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{BootstrapPath, WorkflowPath} {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "\r") {
			t.Errorf("%s still has CRLF", rel)
		}
	}
}

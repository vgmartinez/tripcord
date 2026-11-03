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
	replace(t, dir, BootstrapPath, `[ "$got" != "$want" ]`, "false")
	want := []guardHit{{model.SurfaceGeneric, BootstrapPath, subjectBootstrap, StateChanged}}
	if got := check(t, dir); !slices.Equal(got, want) {
		t.Fatalf("an edit under CRLF: hits = %+v\nwant %+v", got, want)
	}
}

// TestLFNormalizesOnlyUniformCRLF is the reviewer's repro: a `.gitattributes`
// `-text` override for bootstrap.sh's own pattern lets a checkout keep a
// `\r` the init-write hash would otherwise have converted away. A real
// autocrlf checkout converts every line the same way; a file with a `\r`
// on one line and plain `\n` elsewhere is not that, so it is hashed as
// its raw bytes and the injected byte is not lost before the compare.
func TestLFNormalizesOnlyUniformCRLF(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"uniform CRLF", "a\r\nb\r\nc\r\n", "a\nb\nc\n"},
		{"one CR line among LF lines", "a\nb\r\nc\n", "a\nb\r\nc\n"},
		{"bare CR with no following LF", "a\rb\n", "a\rb\n"},
		{"no line endings", "a", "a"},
		{"LF only", "a\nb\n", "a\nb\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(lf([]byte(tc.in))); got != tc.want {
				t.Fatalf("lf(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCheckMixedCRLineIsChanged is the reviewer's repro in full: a
// `.gitattributes` `-text` override for bootstrap.sh, plus a `\r`
// injected on one line (the one bash would see as redirecting a command
// to a file literally named with a trailing carriage return). The
// single-tree check reports it as changed with no base at all, the same
// as any other bootstrap.sh edit.
func TestCheckMixedCRLineIsChanged(t *testing.T) {
	dir := embed(t)
	replaceInFile := func(rel, old, replacement string) {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), old) {
			t.Fatalf("%s does not contain %q", rel, old)
		}
		write(t, dir, rel, strings.Replace(string(raw), old, replacement, 1))
	}
	replaceInFile(GitattributesPath, "/"+BootstrapPath+" text eol=lf\n", "/"+BootstrapPath+" -text\n")
	replaceInFile(BootstrapPath, `"$cached" scan --config "$repo_root" >&2`+"\n", `"$cached" scan --config "$repo_root" >&2`+"\r\n")
	want := []guardHit{
		{model.SurfaceGeneric, BootstrapPath, subjectBootstrap, StateChanged},
		{model.SurfaceGeneric, GitattributesPath, subjectGitattributes, StateChanged},
	}
	got := check(t, dir)
	slices.SortFunc(got, func(a, b guardHit) int { return strings.Compare(a.subject, b.subject) })
	if !slices.Equal(got, want) {
		t.Fatalf("hits = %+v\nwant %+v", got, want)
	}
}

// TestCheckIndexTreeNeverNormalizesCRLF covers CheckOptions.IndexTree: a
// --staged scan reads the git index as raw blobs, with no checkout
// filter at all, so even a uniformly-CRLF bootstrap.sh (which a normal
// working-tree checkout read tolerates as a real autocrlf conversion) is
// reported as changed there.
func TestCheckIndexTreeNeverNormalizesCRLF(t *testing.T) {
	dir := embed(t)
	toCRLF(t, dir, BootstrapPath)
	if got := checkWith(t, dir, CheckOptions{}); len(got) != 0 {
		t.Fatalf("a working-tree checkout tolerates uniform CRLF: hits = %+v", got)
	}
	want := []guardHit{{model.SurfaceGeneric, BootstrapPath, subjectBootstrap, StateChanged}}
	if got := checkWith(t, dir, CheckOptions{IndexTree: true}); !slices.Equal(got, want) {
		t.Fatalf("an index tree never does: hits = %+v\nwant %+v", got, want)
	}
}

// TestCheckGitattributesWeakened covers the second half of the
// reviewer's repro: a later .gitattributes line for bootstrap.sh's own
// pattern that overrides text or eol back away from text eol=lf, and
// the line being removed entirely.
func TestCheckGitattributesWeakened(t *testing.T) {
	for name, edit := range map[string]func(t *testing.T, dir string){
		"-text override": func(t *testing.T, dir string) {
			write(t, dir, GitattributesPath, readFile(t, dir, GitattributesPath)+"/"+BootstrapPath+" -text\n")
		},
		"eol=crlf override": func(t *testing.T, dir string) {
			write(t, dir, GitattributesPath, readFile(t, dir, GitattributesPath)+"/"+BootstrapPath+" text eol=crlf\n")
		},
		"line removed": func(t *testing.T, dir string) {
			write(t, dir, GitattributesPath, strings.Replace(readFile(t, dir, GitattributesPath), "/"+BootstrapPath+" text eol=lf\n", "", 1))
		},
		"file removed": func(t *testing.T, dir string) {
			remove(t, dir, GitattributesPath)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := embed(t)
			edit(t, dir)
			want := []guardHit{{model.SurfaceGeneric, GitattributesPath, subjectGitattributes, StateChanged}}
			if name == "file removed" {
				want = []guardHit{{model.SurfaceGeneric, GitattributesPath, subjectGitattributes, StateMissing}}
			}
			if got := check(t, dir); !slices.Equal(got, want) {
				t.Fatalf("hits = %+v\nwant %+v", got, want)
			}
		})
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

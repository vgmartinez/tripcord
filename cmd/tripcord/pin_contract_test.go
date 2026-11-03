package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/project"
)

// embedCheckMinimum is the first commit on main whose tree contains the
// embed check: internal/embedded and rules/TC-CFG-016.yaml. A pin of
// this repository's action or reusable workflow must be this commit or
// a later commit on main. It is the merge of the init --embed change.
const embedCheckMinimum = "8b33b1b5a69c686b611b43a475da9658fe44614d"

// usesPin matches a pin of this repository's composite action or of a
// reusable workflow, plus the optional "# main@<prefix>" comment.
var usesPin = regexp.MustCompile(regexp.QuoteMeta(project.Repository) + `/\.github/(?:actions/tripcord|workflows/tripcord-pr(?:-comment)?\.yml)@([0-9a-fA-F]+)(?:\s+#\s*main@([0-9a-fA-F]+))?`)

type repoPin struct {
	where, pin, comment string
}

// TestPinsHaveEmbedCheck fails when the init --embed template, a
// workflow, or a documented example pins this repository's action or
// reusable workflow to anything other than a full 40-character sha that
// is on main and whose tree contains the embed check. A clone that does
// not have that history skips the git checks; the sha-length check
// always runs. CI checks the commits out with fetch-depth 0, so a
// missing object fails there instead of skipping.
func TestPinsHaveEmbedCheck(t *testing.T) {
	root := filepath.Join("..", "..")
	pins := collectRepoPins(t, root)
	if len(pins) == 0 {
		t.Fatal("found no pins of this repository's action or reusable workflow")
	}
	formatOK := true
	for _, p := range pins {
		if !commitPinSHA(p.pin) {
			t.Errorf("%s pins %q, want a 40-character lowercase sha", p.where, p.pin)
			formatOK = false
		}
		if p.comment != "" && !strings.HasPrefix(p.pin, p.comment) {
			t.Errorf("%s comment main@%s is not a prefix of %s", p.where, p.comment, p.pin)
			formatOK = false
		}
	}
	if !formatOK {
		return
	}
	if !pinHistoryAvailable(t, root) {
		return
	}
	ref := mainRef(t, root)
	if err := gitRun(root, "merge-base", "--is-ancestor", embedCheckMinimum, ref); err != nil {
		t.Fatalf("recorded minimum %s is not on %s", embedCheckMinimum, ref)
	}
	if err := treeHasEmbedCheck(root, embedCheckMinimum); err != nil {
		t.Fatalf("recorded minimum %s: %v", embedCheckMinimum, err)
	}
	seen := map[string]bool{}
	for _, p := range pins {
		if seen[p.pin] {
			continue
		}
		seen[p.pin] = true
		if err := gitRun(root, "cat-file", "-e", p.pin); err != nil {
			t.Errorf("%s pin %s is not in this clone: %v", p.where, p.pin, err)
			continue
		}
		if err := gitRun(root, "merge-base", "--is-ancestor", p.pin, ref); err != nil {
			t.Errorf("%s pin %s is not on %s", p.where, p.pin, ref)
			continue
		}
		if err := gitRun(root, "merge-base", "--is-ancestor", embedCheckMinimum, p.pin); err != nil {
			t.Errorf("%s pin %s does not contain the embed check: it is not %s or a descendant of it", p.where, p.pin, embedCheckMinimum)
			continue
		}
		if err := treeHasEmbedCheck(root, p.pin); err != nil {
			t.Errorf("%s pin %s: %v", p.where, p.pin, err)
		}
	}
}

func collectRepoPins(t *testing.T, root string) []repoPin {
	t.Helper()
	var pins []repoPin
	pins = append(pins, repoPin{where: "embedded.WorkflowPin", pin: embedded.WorkflowPin})
	pins = append(pins, pinsIn(t, "generated tripcord.yml", string(embedded.Workflow()))...)
	var files []string
	for _, dir := range []string{filepath.Join(root, ".github", "workflows"), filepath.Join(root, "docs")} {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			switch strings.ToLower(filepath.Ext(path)) {
			case ".yml", ".yaml", ".md":
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	files = append(files, filepath.Join(root, "README.md"))
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatal(err)
		}
		pins = append(pins, pinsIn(t, filepath.ToSlash(rel), string(raw))...)
	}
	return pins
}

func pinsIn(t *testing.T, where, text string) []repoPin {
	t.Helper()
	var out []repoPin
	for _, m := range usesPin.FindAllStringSubmatch(text, -1) {
		out = append(out, repoPin{where: where, pin: m[1], comment: m[2]})
	}
	return out
}

func commitPinSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// pinHistoryAvailable reports whether this clone can prove a pin is on
// main. It skips, after the caller has already checked sha length, when
// git, the checkout, or the recorded minimum is missing. CI does not
// skip a missing minimum: the vet-and-test job fetches full history.
func pinHistoryAvailable(t *testing.T, root string) bool {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	out, err := gitOutput(root, "rev-parse", "--is-inside-work-tree")
	if err != nil || strings.TrimSpace(out) != "true" {
		t.Skip("not a git checkout")
	}
	shallow, err := gitOutput(root, "rev-parse", "--is-shallow-repository")
	if err != nil {
		t.Skip("not a git checkout")
	}
	if strings.TrimSpace(shallow) == "true" {
		t.Skip("shallow clone: the pinned commit may be missing")
	}
	if gitRun(root, "cat-file", "-e", embedCheckMinimum) != nil {
		if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
			t.Fatalf("recorded minimum %s is not in this clone; the checkout needs fetch-depth: 0", embedCheckMinimum)
		}
		t.Skipf("recorded minimum %s is not in this clone", embedCheckMinimum)
	}
	if mainRef(t, root) == "" {
		if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
			t.Fatal("neither origin/main nor main is in this clone, so a pin cannot be checked against main")
		}
		t.Skip("neither origin/main nor main is in this clone")
	}
	return true
}

func mainRef(t *testing.T, root string) string {
	t.Helper()
	for _, ref := range []string{"origin/main", "main"} {
		if gitRun(root, "rev-parse", "--verify", "--quiet", ref) == nil {
			return ref
		}
	}
	return ""
}

func treeHasEmbedCheck(root, sha string) error {
	check, err := gitOutput(root, "cat-file", "-p", sha+":internal/embedded/check.go")
	if err != nil {
		return err
	}
	if !strings.Contains(check, "func Check(") {
		return fmt.Errorf("internal/embedded/check.go has no embed check")
	}
	rule, err := gitOutput(root, "cat-file", "-p", sha+":rules/TC-CFG-016.yaml")
	if err != nil {
		return err
	}
	if !strings.Contains(rule, "id: TC-CFG-016") || !strings.Contains(rule, "tripcordGuard") {
		return fmt.Errorf("rules/TC-CFG-016.yaml is missing the embed rule")
	}
	return nil
}

func gitRun(root string, args ...string) error {
	_, err := gitOutput(root, args...)
	return err
}

func gitOutput(root string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"--no-optional-locks"}, args...)...)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && len(exit.Stderr) > 0 {
			return "", errors.New(strings.TrimSpace(string(exit.Stderr)))
		}
		return "", err
	}
	return string(out), nil
}

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/project"
)

// embedCheckMinimum is the first commit on main whose tree contains the
// embed check: internal/embedded and rules/TC-CFG-016.yaml. A pin of
// this repository's action or reusable workflow must be this commit or
// a later commit on main. It is the merge of the init --embed change.
const embedCheckMinimum = "8b33b1b5a69c686b611b43a475da9658fe44614d"

// usesPin matches a uses ref of this repository's composite action or of
// a reusable workflow, plus an optional "# main@<prefix>" comment. The
// ref is whatever follows @. A branch or tag (@main, @v1, @v1.2.3,
// @release) is still a pin and fails the 40-character check.
var usesPin = regexp.MustCompile(regexp.QuoteMeta(project.Repository) + `/\.github/(?:actions/tripcord|workflows/tripcord-pr(?:-comment)?\.yml)@([^\s#]+)(?:\s+#\s*main@([0-9a-fA-F]+))?`)

// runningInCI is the CI environment of the process that started the
// test binary. Package initialization reads it before TestMain sets
// CI=true and unsets GITHUB_ACTIONS, so a later os.Getenv("CI") is not
// the environment the developer launched.
var runningInCI = os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != ""

type repoPin struct {
	where, pin, comment string
	needsComment        bool
}

// TestPinsHaveEmbedCheck fails when the init --embed template, a
// workflow, or a documented example pins this repository's action or
// reusable workflow to anything other than a full 40-character sha that
// is on main and whose tree contains the embed check. Every uses line
// also needs a "# main@<short>" comment that is a prefix of that sha.
// A branch or tag ref (@main, @v1, @v1.2.3, @release) fails that
// sha-length check. The sha-length check always runs. Outside CI, a
// clone that does not have the history skips the git checks. When the
// process was started with CI or GITHUB_ACTIONS set, a shallow clone
// and a directory that is not a git checkout fail those checks.
// runningInCI records that environment before TestMain overwrites it.
// TestVetAndTestFetchesFullHistory keeps the vet and test job at
// fetch-depth 0 so that checkout has the objects.
func TestPinsHaveEmbedCheck(t *testing.T) {
	root := filepath.Join("..", "..")
	pins := collectRepoPins(t, root)
	if len(pins) == 0 {
		t.Fatal("found no pins of this repository's action or reusable workflow")
	}
	formatOK := true
	for _, p := range pins {
		if err := pinFormatError(p); err != nil {
			t.Error(err)
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

// pinCurrencyPaths are the files a documented pin falls behind by
// missing. A pin is behind when it does not contain the latest commit
// on origin/main (or main, when origin/main is absent) that changes any
// of them. The set is the reusable workflows, the composite action, the
// pre-commit hook manifest, and the scanner those pins ship: advisories,
// the rule registry, top-level rule YAML, the rule and adapter sources,
// and go.mod. It leaves out init's templates and the docs that quote the
// pin, so a commit that only changes those does not make a pin that
// already contains the scanner look stale.
var pinCurrencyPaths = []string{
	".github/workflows/tripcord-pr.yml",
	".github/workflows/tripcord-pr-comment.yml",
	".github/actions/tripcord",
	".pre-commit-hooks.yaml",
	"rules/ADVISORIES.json",
	"rules/REGISTRY",
	"rules/embed.go",
	":(glob)rules/*.yaml",
	":(glob)internal/rules/*.go",
	":(glob)internal/rules/**/*.go",
	":(glob)internal/adapters/*.go",
	":(glob)internal/adapters/**/*.go",
	"go.mod",
}

// reusableWorkflowPin matches a full-SHA pin of tripcord-pr.yml or
// tripcord-pr-comment.yml. The composite action pin is a different
// check: the workflow file at WorkflowPin still calls that action, and
// this test does not require the action SHA itself to move.
var reusableWorkflowPin = regexp.MustCompile(regexp.QuoteMeta(project.Repository) + `/\.github/workflows/tripcord-pr(?:-comment)?\.yml@([0-9a-f]{40})`)

// documentedPreCommitRev matches a tripcord pre-commit repo line and the
// full SHA on the next line. The hook builds that commit.
var documentedPreCommitRev = regexp.MustCompile(`(?m)repo:[ \t]+https://github\.com/` + regexp.QuoteMeta(project.Repository) + `(?:\.git)?[ \t]*\r?\n[ \t]*rev:[ \t]+([0-9a-f]{40})`)

// anyPreCommitRev matches a tripcord pre-commit repo line and whatever
// follows rev: on the next line, so a branch, a tag, or a short sha is
// collected and fails the full-sha check instead of being skipped.
var anyPreCommitRev = regexp.MustCompile(`(?m)repo:[ \t]+https://github\.com/` + regexp.QuoteMeta(project.Repository) + `(?:\.git)?[ \t]*\r?\n[ \t]*rev:[ \t]+([^\s#]+)`)

// TestPinsReachableFromHead is the per-pull-request pin check. It does
// not read origin/main. Every pin of this repository's action or
// reusable workflows in the generated workflow, README.md, and docs/,
// and every pre-commit rev in README.md and docs/pre-commit.md, must be
// a full 40-character lowercase sha (never a branch or a tag) and an
// ancestor of the HEAD under test. A pin missing from the clone, or any
// pin in a shallow clone, is fetched by that exact sha from origin; a
// failed fetch fails the test. It never skips.
func TestPinsReachableFromHead(t *testing.T) {
	root := filepath.Join("..", "..")
	pins := headPins(t, root)
	if len(pins) == 0 {
		t.Fatal("found no pins")
	}
	for _, p := range pins {
		if !commitPinSHA(p.pin) {
			t.Errorf("%s pins %q, want a 40-character lowercase sha, not a branch, tag, or short sha", p.where, p.pin)
		}
	}
	if t.Failed() {
		return
	}
	seen := map[string]bool{}
	for _, p := range pins {
		if seen[p.pin] {
			continue
		}
		seen[p.pin] = true
		if err := ensurePinCommit(root, p.pin); err != nil {
			t.Errorf("%s pin %s: %v", p.where, p.pin, err)
			continue
		}
		if err := gitRun(root, "merge-base", "--is-ancestor", p.pin, "HEAD"); err != nil {
			t.Errorf("%s pin %s is not an ancestor of HEAD", p.where, p.pin)
		}
	}
}

// ensurePinCommit makes sha's commit and its history available in the
// clone at root. A clone that already has the commit and is not shallow
// needs nothing. Otherwise it fetches that exact sha from origin, with
// --unshallow when the clone is shallow so ancestry can be computed.
// Any failure is returned; the caller fails closed.
func ensurePinCommit(root, sha string) error {
	if _, err := exec.LookPath("git"); err != nil {
		return errors.New("git is not installed")
	}
	shallow, err := gitOutput(root, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return fmt.Errorf("not a git checkout: %v", err)
	}
	isShallow := strings.TrimSpace(shallow) == "true"
	if !isShallow && gitRun(root, "cat-file", "-e", sha+"^{commit}") == nil {
		return nil
	}
	args := []string{"fetch", "--no-tags", "--quiet"}
	if isShallow {
		args = append(args, "--unshallow")
	}
	args = append(args, "origin", sha)
	if _, err := gitOutput(root, args...); err != nil {
		return fmt.Errorf("fetching it from origin failed: %v", err)
	}
	if err := gitRun(root, "cat-file", "-e", sha+"^{commit}"); err != nil {
		return fmt.Errorf("not in the clone after fetching it: %v", err)
	}
	return nil
}

func headPins(t *testing.T, root string) []repoPin {
	t.Helper()
	pins := []repoPin{{where: "embedded.WorkflowPin", pin: embedded.WorkflowPin}}
	for where, text := range pinTexts(t, root) {
		for _, m := range usesPin.FindAllStringSubmatch(text, -1) {
			pins = append(pins, repoPin{where: where, pin: m[1]})
		}
		if where != "README.md" && where != "docs/pre-commit.md" {
			continue
		}
		for _, m := range anyPreCommitRev.FindAllStringSubmatch(text, -1) {
			pins = append(pins, repoPin{where: where, pin: m[1]})
		}
	}
	return pins
}

// TestReleaseGatePinsContainLatestScannerChange runs only with
// TRIPCORD_RELEASE_GATE=1 (make release-gate), before a tag. No
// pull_request or push workflow sets that variable. It fails when the
// generated workflow pin, a documented pin of the reusable workflows, or
// a documented pre-commit rev does not contain the latest commit on
// origin/main (or main) that changes pinCurrencyPaths. Every merge that
// changes those paths makes it fail until a repin pull request lands.
// main@6a12795 and the pre-commit rev main@c44853c fail it. A shallow or
// non-git checkout fails it too.
func TestReleaseGatePinsContainLatestScannerChange(t *testing.T) {
	if os.Getenv("TRIPCORD_RELEASE_GATE") != "1" {
		t.Log("release gate not requested; set TRIPCORD_RELEASE_GATE=1 to run it")
		return
	}
	root := filepath.Join("..", "..")
	setRunningInCI(t, true)
	if !pinHistoryAvailable(t, root) {
		return
	}
	ref := mainRef(t, root)
	latest := currentPinCommit(t, root, ref)
	for _, stale := range []string{
		"6a1279565e9e41e9dec163e6bedf07f2647a2c67",
		"c44853c105b84c1e2928aab1c75f2da31c29d13e",
	} {
		if err := gitRun(root, "merge-base", "--is-ancestor", latest, stale); err == nil {
			t.Errorf("pinCurrencyPaths is too narrow: %s contains %s, so that old pin would not count as behind", stale, latest)
		}
	}
	workflows, revs := currentPins(t, root)
	if len(workflows) == 0 || len(revs) == 0 {
		t.Fatalf("workflow pins = %v, pre-commit revs = %v", workflows, revs)
	}
	for _, p := range workflows {
		if err := gitRun(root, "merge-base", "--is-ancestor", latest, p.pin); err != nil {
			t.Errorf("release gate: %s workflow pin %s does not contain %s, the latest commit on %s that changes the scanner, the reusable workflows, the action, or the hook manifest; land a repin pull request before tagging", p.where, p.pin, latest, ref)
		}
	}
	for _, p := range revs {
		if err := gitRun(root, "merge-base", "--is-ancestor", latest, p.pin); err != nil {
			t.Errorf("release gate: %s pre-commit rev %s does not contain %s, the latest commit on %s that changes the scanner, the reusable workflows, the action, or the hook manifest; land a repin pull request before tagging", p.where, p.pin, latest, ref)
		}
	}
}

// TestReleaseGateNotInPullRequestCI keeps the release gate off the
// pull_request and push workflows: none may set TRIPCORD_RELEASE_GATE
// or run make release-gate.
func TestReleaseGateNotInPullRequestCI(t *testing.T) {
	dir := filepath.Join("..", "..", ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if s := string(raw); strings.Contains(s, "TRIPCORD_RELEASE_GATE") || strings.Contains(s, "release-gate") {
			t.Errorf(".github/workflows/%s runs the release gate; it must only run before a tag", e.Name())
		}
	}
}

func currentPinCommit(t *testing.T, root, ref string) string {
	t.Helper()
	args := append([]string{"log", "-1", "--format=%H", ref, "--"}, pinCurrencyPaths...)
	out, err := gitOutput(root, args...)
	if err != nil {
		t.Fatal(err)
	}
	latest := strings.TrimSpace(out)
	if !commitPinSHA(latest) {
		t.Fatalf("latest commit for the pin pathspec = %q", latest)
	}
	return latest
}

func pinTexts(t *testing.T, root string) map[string]string {
	t.Helper()
	texts := map[string]string{"generated tripcord.yml": string(embedded.Workflow())}
	var files []string
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".md") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
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
		texts[filepath.ToSlash(rel)] = string(raw)
	}
	return texts
}

func currentPins(t *testing.T, root string) (workflows, revs []repoPin) {
	t.Helper()
	workflows = append(workflows, repoPin{where: "embedded.WorkflowPin", pin: embedded.WorkflowPin})
	for where, text := range pinTexts(t, root) {
		for _, m := range reusableWorkflowPin.FindAllStringSubmatch(text, -1) {
			workflows = append(workflows, repoPin{where: where, pin: m[1]})
		}
		if where != "README.md" && where != "docs/pre-commit.md" {
			continue
		}
		for _, m := range documentedPreCommitRev.FindAllStringSubmatch(text, -1) {
			revs = append(revs, repoPin{where: where, pin: m[1]})
		}
	}
	return workflows, revs
}

// TestEnsurePinCommitFetchesIntoShallowClone checks the fail-closed
// fetch: a shallow clone gets the pinned commit and its history from
// origin, and a clone whose origin cannot serve it fails.
func TestEnsurePinCommitFetchesIntoShallowClone(t *testing.T) {
	src := tempRepo(t)
	first, err := gitOutput(src, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	first = strings.TrimSpace(first)
	for i := range 2 {
		if err := os.WriteFile(filepath.Join(src, "README"), []byte(strconv.Itoa(i)), 0o644); err != nil {
			t.Fatal(err)
		}
		gitIn(t, src, "commit", "-qam", "next")
	}
	clone := t.TempDir()
	gitIn(t, src, "clone", "-q", "--no-local", "--depth", "1", src, clone)
	if gitRun(clone, "cat-file", "-e", first+"^{commit}") == nil {
		t.Fatal("the shallow clone already has the first commit")
	}
	if err := ensurePinCommit(clone, first); err != nil {
		t.Fatalf("ensurePinCommit: %v", err)
	}
	if err := gitRun(clone, "merge-base", "--is-ancestor", first, "HEAD"); err != nil {
		t.Fatalf("after the fetch the first commit is not an ancestor of HEAD: %v", err)
	}

	broken := t.TempDir()
	gitIn(t, src, "clone", "-q", "--no-local", "--depth", "1", src, broken)
	gitIn(t, broken, "remote", "set-url", "origin", filepath.Join(t.TempDir(), "missing"))
	if err := ensurePinCommit(broken, first); err == nil {
		t.Fatal("ensurePinCommit succeeded with an origin that cannot serve the commit")
	}
	if err := ensurePinCommit(t.TempDir(), first); err == nil {
		t.Fatal("ensurePinCommit succeeded outside a git checkout")
	}
}

// TestUsesPinRejectsBranchAndTag checks that a docs or README ref of
// @main, @v1, @v1.2.3, or @release fails the 40-character pin check,
// and that a hexadecimal ref still has to be a full sha with a
// # main@ comment.
func TestUsesPinRejectsBranchAndTag(t *testing.T) {
	repo := project.Repository
	text := strings.Join([]string{
		"uses: " + repo + "/.github/actions/tripcord@v1",
		"uses: " + repo + "/.github/workflows/tripcord-pr.yml@main",
		"uses: " + repo + "/.github/workflows/tripcord-pr-comment.yml@v1.2.3",
		"uses: " + repo + "/.github/actions/tripcord@release",
		"ref: main",
		"uses: " + repo + "/.github/actions/tripcord@8b33b1b # main@8b33b1b",
		"uses: " + repo + "/.github/actions/tripcord@" + embedCheckMinimum,
		"uses: " + repo + "/.github/actions/tripcord@" + embedCheckMinimum + " # main@8b33b1b",
	}, "\n")
	pins := pinsIn(t, "sample", text)
	if len(pins) != 7 {
		t.Fatalf("pins = %+v, want the four refs, the short sha, the bare sha, and the commented sha", pins)
	}
	for _, p := range pins[:6] {
		if err := pinFormatError(p); err == nil {
			t.Errorf("%s pin %q with comment %q passed the format check", p.where, p.pin, p.comment)
		}
	}
	if err := pinFormatError(pins[6]); err != nil {
		t.Error(err)
	}
}

// TestVetAndTestFetchesFullHistory keeps the job that runs
// TestPinsHaveEmbedCheck from dropping to a shallow checkout. In CI a
// shallow clone fails the git half of that test.
func TestVetAndTestFetchesFullHistory(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Jobs map[string]struct {
			Name  string `yaml:"name"`
			Steps []struct {
				Uses string         `yaml:"uses"`
				With map[string]any `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	found := 0
	for id, job := range doc.Jobs {
		if job.Name != "vet and test" {
			continue
		}
		found++
		depth := ""
		checkout := false
		for _, step := range job.Steps {
			if !strings.HasPrefix(step.Uses, "actions/checkout@") {
				continue
			}
			checkout = true
			depth = yamlScalar(step.With["fetch-depth"])
		}
		if !checkout {
			t.Errorf("job %s (%s) has no actions/checkout step", id, job.Name)
		}
		if depth != "0" {
			t.Errorf("job %s (%s) fetch-depth = %q, want 0", id, job.Name, depth)
		}
	}
	if found != 1 {
		t.Fatalf("jobs named %q: %d, want 1", "vet and test", found)
	}
}

// TestPinHistoryProblemFailsWhenGitMissingInCI checks that a missing
// git fails the history check when the process was started with CI or
// GITHUB_ACTIONS set, and skips outside CI. PATH is emptied so
// LookPath cannot find git. runningInCI is assigned directly because
// TestMain has already overwritten the launch environment.
func TestPinHistoryProblemFailsWhenGitMissingInCI(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	setRunningInCI(t, true)
	reason, skip := pinHistoryProblem(t.TempDir())
	if skip || reason != "git is not installed" {
		t.Fatalf("missing git in CI: skip=%v reason=%q", skip, reason)
	}
	setRunningInCI(t, false)
	reason, skip = pinHistoryProblem(t.TempDir())
	if !skip || reason != "git is not installed" {
		t.Fatalf("missing git outside CI: skip=%v reason=%q", skip, reason)
	}
}

// TestPinHistoryFailsShallowAndNonGitInCI checks that a shallow clone
// and a directory that is not a git checkout fail the git half of
// TestPinsHaveEmbedCheck when the process started in CI, and skip
// otherwise. It assigns runningInCI directly: TestMain has already set
// CI=true, so t.Setenv cannot restore the launch environment. A
// non-shallow checkout that is missing the recorded minimum still
// fails when that flag is set.
func TestPinHistoryFailsShallowAndNonGitInCI(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	nonGit := t.TempDir()
	shallow := shallowClone(t)
	full := tempRepo(t)

	setRunningInCI(t, true)
	if reason, skip := pinHistoryProblem(nonGit); skip || !strings.Contains(reason, "not a git checkout") {
		t.Fatalf("non-git checkout in CI: skip=%v reason=%q", skip, reason)
	}
	if reason, skip := pinHistoryProblem(shallow); skip || !strings.Contains(reason, "shallow") {
		t.Fatalf("shallow clone in CI: skip=%v reason=%q", skip, reason)
	}
	reason, skip := pinHistoryProblem(full)
	if skip || !strings.Contains(reason, embedCheckMinimum) {
		t.Fatalf("non-shallow CI checkout missing the minimum: skip=%v reason=%q", skip, reason)
	}

	setRunningInCI(t, false)
	if reason, skip := pinHistoryProblem(nonGit); !skip {
		t.Fatalf("non-git checkout outside CI: skip=%v reason=%q", skip, reason)
	}
	if reason, skip := pinHistoryProblem(shallow); !skip {
		t.Fatalf("shallow clone outside CI: skip=%v reason=%q", skip, reason)
	}
}

// TestCIFailOrSkipUsesInitEnv checks ciFailOrSkip under the environment
// TestMain actually leaves behind. TestMain sets CI=true and unsets
// GITHUB_ACTIONS before tests run. The decision has to follow
// runningInCI, which was captured before that override.
func TestCIFailOrSkipUsesInitEnv(t *testing.T) {
	if os.Getenv("CI") != "true" {
		t.Fatal("TestMain did not set CI=true")
	}
	if _, ok := os.LookupEnv("GITHUB_ACTIONS"); ok {
		t.Fatal("TestMain left GITHUB_ACTIONS set")
	}
	reason, skip := ciFailOrSkip("not a git checkout")
	if reason != "not a git checkout" {
		t.Fatalf("reason = %q", reason)
	}
	if runningInCI == skip {
		t.Fatalf("runningInCI=%v skip=%v; ciFailOrSkip followed TestMain's CI override", runningInCI, skip)
	}
}

func setRunningInCI(t *testing.T, v bool) {
	t.Helper()
	prev := runningInCI
	runningInCI = v
	t.Cleanup(func() { runningInCI = prev })
}

func tempRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitIn(t, dir, "init", "-b", "main")
	gitIn(t, dir, "config", "user.email", "tripcord@example.com")
	gitIn(t, dir, "config", "user.name", "Tripcord")
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "add", "README")
	gitIn(t, dir, "commit", "-m", "init")
	return dir
}

func shallowClone(t *testing.T) string {
	t.Helper()
	src := tempRepo(t)
	dst := t.TempDir()
	// A local path is cloned with --local, which ignores --depth.
	gitIn(t, src, "clone", "--no-local", "--depth", "1", src, dst)
	return dst
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
		out = append(out, repoPin{where: where, pin: m[1], comment: m[2], needsComment: true})
	}
	return out
}

func pinFormatError(p repoPin) error {
	if !commitPinSHA(p.pin) {
		return fmt.Errorf("%s pins %q, want a 40-character lowercase sha", p.where, p.pin)
	}
	if p.needsComment && !pinCommentOK(p.pin, p.comment) {
		return fmt.Errorf("%s pin %s is missing a # main@ comment that is a prefix of the sha", p.where, p.pin)
	}
	return nil
}

func pinCommentOK(pin, comment string) bool {
	if len(comment) < 7 || len(comment) > len(pin) || !strings.HasPrefix(pin, comment) {
		return false
	}
	for _, c := range comment {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
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
// main. Outside CI it skips when git, the checkout, or the recorded
// minimum is missing. When the process was started with CI or
// GITHUB_ACTIONS set, a missing git, a shallow clone, and a directory
// that is not a git checkout fail, as does a non-shallow checkout that
// is missing the minimum. That flag is runningInCI, not the environment
// TestMain sets.
func pinHistoryAvailable(t *testing.T, root string) bool {
	t.Helper()
	reason, skip := pinHistoryProblem(root)
	if skip {
		t.Skip(reason)
	}
	if reason != "" {
		t.Fatal(reason)
	}
	return true
}

// pinHistoryProblem reports why root cannot prove a pin is on main.
// skip is true when the caller should skip rather than fail. Outside CI
// a missing git, a shallow clone, and a non-git checkout skip. When the
// process was started with CI or GITHUB_ACTIONS set, all three fail.
func pinHistoryProblem(root string) (reason string, skip bool) {
	if _, err := exec.LookPath("git"); err != nil {
		return ciFailOrSkip("git is not installed")
	}
	out, err := gitOutput(root, "rev-parse", "--is-inside-work-tree")
	if err != nil || strings.TrimSpace(out) != "true" {
		return ciFailOrSkip("not a git checkout")
	}
	shallow, err := gitOutput(root, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return ciFailOrSkip("not a git checkout")
	}
	if strings.TrimSpace(shallow) == "true" {
		return ciFailOrSkip("shallow clone: the pinned commit may be missing; the checkout needs fetch-depth: 0")
	}
	if gitRun(root, "cat-file", "-e", embedCheckMinimum) != nil {
		return ciFailOrSkip(fmt.Sprintf("recorded minimum %s is not in this clone; the checkout needs fetch-depth: 0", embedCheckMinimum))
	}
	if mainRefOf(root) == "" {
		return ciFailOrSkip("neither origin/main nor main is in this clone, so a pin cannot be checked against main")
	}
	return "", false
}

// ciFailOrSkip fails the history check when the process was started with
// CI or GITHUB_ACTIONS set, and skips it otherwise. It uses runningInCI
// because TestMain overwrites those variables before tests run.
func ciFailOrSkip(reason string) (string, bool) {
	if runningInCI {
		return reason, false
	}
	return reason, true
}

func mainRef(t *testing.T, root string) string {
	t.Helper()
	ref := mainRefOf(root)
	if ref == "" {
		t.Fatal("neither origin/main nor main is in this clone")
	}
	return ref
}

func mainRefOf(root string) string {
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

func yamlScalar(v any) string {
	switch n := v.(type) {
	case string:
		return n
	case int:
		return strconv.Itoa(n)
	case int64:
		return strconv.FormatInt(n, 10)
	case uint64:
		return strconv.FormatUint(n, 10)
	case float64:
		if n == float64(int64(n)) {
			return strconv.FormatInt(int64(n), 10)
		}
		return strconv.FormatFloat(n, 'f', -1, 64)
	default:
		return ""
	}
}

func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"--no-optional-locks"}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
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

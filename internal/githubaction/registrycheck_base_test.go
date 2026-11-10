package githubaction_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const baseChecker = `package main

import "fmt"

func main() {
	fmt.Println("registrycheck-from-base")
}
`

const headChecker = `package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("registrycheck-from-head")
	os.Exit(9)
}
`

// TestRegistryCheckBuiltFromBaseCommit runs the rule-registry script
// against a two-commit fixture. The parent program prints
// registrycheck-from-base and exits 0. The head program prints
// registrycheck-from-head and exits 9. A pull request and a push both
// have to execute the parent program. A pull request whose base SHA is
// the checked-out commit fails before either program is built.
func TestRegistryCheckBuiltFromBaseCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Fatal("go is not installed")
	}
	job := ciJob(t, "rule-registry")
	if got := permMap(t, job["permissions"]); !samePerms(got, map[string]string{"contents": "read"}) {
		t.Fatalf("permissions = %v, want contents: read", got)
	}
	var checkout map[string]*yaml.Node
	for _, step := range seq(t, job["steps"]) {
		parsed := mapping(t, step)
		if scalar(parsed["name"]) == "Checkout" {
			checkout = parsed
		}
	}
	if checkout == nil {
		t.Fatal("rule-registry has no checkout step")
	}
	if scalar(checkout["uses"]) != workflowCheckout {
		t.Fatalf("checkout uses %q", scalar(checkout["uses"]))
	}
	with := mapping(t, checkout["with"])
	if scalar(with["persist-credentials"]) != "false" {
		t.Fatal("rule-registry checkout persists credentials")
	}
	if scalar(with["fetch-depth"]) != "0" {
		t.Fatalf("fetch-depth = %q, want 0 so the base commit is local", scalar(with["fetch-depth"]))
	}
	run := stepRun(t, "rule-registry", "Registry is append-only")
	if strings.Contains(run, "${{") {
		t.Fatal("registry step interpolates an expression into run")
	}
	if strings.Contains(run, "go run ./internal/tools/registrycheck") || strings.Contains(run, "go build -C .") {
		t.Fatal("registrycheck is still built from the checkout")
	}
	for _, want := range []string{
		`src="${RUNNER_TEMP}/registrycheck-base"`,
		`git worktree add --detach "$src" "$base"`,
		`go build -C "$src" -o "${RUNNER_TEMP}/registrycheck" ./internal/tools/registrycheck`,
		`"${RUNNER_TEMP}/registrycheck" "$old" rules/REGISTRY`,
	} {
		if !strings.Contains(run, want) {
			t.Errorf("registry step missing %s", want)
		}
	}
	repo := checkerFixtureRepo(t)
	base := runGit(t, repo, "rev-parse", "HEAD~1")
	head := runGit(t, repo, "rev-parse", "HEAD")
	if base == head {
		t.Fatal("fixture base and head are the same commit")
	}

	t.Run("pull request", func(t *testing.T) {
		out := mustRegistryScript(t, repo, run, []string{
			"EVENT_NAME=pull_request",
			"PR_BASE_SHA=" + base,
			"DEFAULT_BRANCH=main",
		})
		assertBaseChecker(t, out)
	})
	t.Run("push parent", func(t *testing.T) {
		out := mustRegistryScript(t, repo, run, []string{
			"EVENT_NAME=push",
			"PUSH_BEFORE_SHA=" + base,
			"DEFAULT_BRANCH=main",
		})
		assertBaseChecker(t, out)
	})
	t.Run("pull request refuses the head", func(t *testing.T) {
		out, err := runRegistryScript(t, repo, run, []string{
			"EVENT_NAME=pull_request",
			"PR_BASE_SHA=" + head,
			"DEFAULT_BRANCH=main",
		})
		if err == nil {
			t.Fatalf("building from the head succeeded:\n%s", out)
		}
		if !strings.Contains(out, "registrycheck base SHA is the checked-out head") || strings.Contains(out, "registrycheck-from-head") || strings.Contains(out, "registrycheck-from-base") {
			t.Fatalf("got %v\n%s", err, out)
		}
	})
}

func assertBaseChecker(t *testing.T, out string) {
	t.Helper()
	if !strings.Contains(out, "registrycheck-from-base") || strings.Contains(out, "registrycheck-from-head") {
		t.Fatalf("checker output:\n%s", out)
	}
}

// TestInternalToolsHaveCodeowners keeps internal/tools/, including
// registrycheck, on the spec owner's review path.
func TestInternalToolsHaveCodeowners(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "CODEOWNERS"))
	if err != nil {
		t.Fatal(err)
	}
	covered := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "/internal/tools/" && fields[1] == "@vgmartinez" {
			covered = true
		}
	}
	if !covered {
		t.Fatal("CODEOWNERS does not cover /internal/tools/ for @vgmartinez")
	}
}

func checkerFixtureRepo(t *testing.T) string {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "repo")
	src := filepath.Join(repo, "internal", "tools", "registrycheck")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(repo, "go.mod"), "module example.com/registrycheck\n\ngo 1.27.3\n")
	writeFixture(t, filepath.Join(src, "main.go"), baseChecker)
	runGit(t, repo, "init", "-q", "-b", "main")
	runGit(t, repo, "add", ".")
	tree := runGit(t, repo, "write-tree")
	base := runGit(t, repo, "commit-tree", tree, "-m", "base")
	runGit(t, repo, "update-ref", "HEAD", base)
	writeFixture(t, filepath.Join(src, "main.go"), headChecker)
	runGit(t, repo, "add", ".")
	tree = runGit(t, repo, "write-tree")
	head := runGit(t, repo, "commit-tree", tree, "-p", base, "-m", "head")
	runGit(t, repo, "update-ref", "HEAD", head)
	return repo
}

func mustRegistryScript(t *testing.T, repo, script string, env []string) string {
	t.Helper()
	out, err := runRegistryScript(t, repo, script, env)
	if err != nil {
		t.Fatalf("script: %v\n%s", err, out)
	}
	return out
}

func runRegistryScript(t *testing.T, repo, script string, env []string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash")
	cmd.Dir = repo
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append(gitlessEnv(t), "RUNNER_TEMP="+t.TempDir(), "GITHUB_WORKSPACE="+repo)
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(gitlessEnv(t),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_AUTHOR_NAME=t",
		"GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t",
		"GIT_COMMITTER_EMAIL=t@example.invalid",
	)
	out, err := cmd.Output()
	if err != nil {
		detail := ""
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			detail = string(exitErr.Stderr)
		}
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, detail)
	}
	return strings.TrimSpace(string(out))
}

func gitlessEnv(t *testing.T) []string {
	t.Helper()
	env := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "EVENT_NAME", "PR_BASE_SHA", "PUSH_BEFORE_SHA", "DEFAULT_BRANCH", "RUNNER_TEMP", "GITHUB_WORKSPACE":
			continue
		default:
			env = append(env, entry)
		}
	}
	return env
}

func writeFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

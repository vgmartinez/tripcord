package githubaction_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/vgmartinez/tripcord/internal/cfg014"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
	"github.com/vgmartinez/tripcord/internal/prcontext"
)

// pathCapWarning is the annotation the action and the caller self-test
// emit when pr-context stops at the path cap.
const pathCapWarning = "::warning::TC-CFG-014 could not be fully evaluated (incomplete because of the path cap)"

type everyPath struct{}

func (everyPath) Harness() model.Harness { return model.HarnessCursor }

func (everyPath) Classifies(string) bool { return true }

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// pathCapLineFromRule is the stderr line pr-context writes for the
// path cap. The reason comes from cfg014.Evaluate, and the prefix is
// the write in prcontext.go. The shell file has to assign that line.
func pathCapLineFromRule(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "cmd", "tripcord", "prcontext.go"))
	if err != nil {
		t.Fatal(err)
	}
	const write = `writeString(stderr, "tripcord pr-context: TC-CFG-014 incomplete: "+output.Message(foldHome(outcome.Reason))+"\n")`
	if !strings.Contains(string(src), write) {
		t.Fatal("pr-context no longer writes the path-cap line this test derives")
	}
	paths := make([]string, 65)
	for i := range paths {
		paths[i] = fmt.Sprintf(".cursor/hooks-%d.json", i)
	}
	outcome := cfg014.Evaluate(cfg014.Input{
		Agent:       true,
		Author:      "agent",
		Head:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Paths:       paths,
		PathsKnown:  true,
		Reviews:     prcontext.ReviewSet{Available: true},
		Classifiers: []cfg014.Classifier{everyPath{}},
	})
	if outcome.Status != cfg014.StatusIncomplete {
		t.Fatalf("status = %q, reason %q", outcome.Status, outcome.Reason)
	}
	home, homeErr := os.UserHomeDir()
	if homeErr == nil && home != "" && strings.Contains(outcome.Reason, home) {
		t.Fatal("path-cap reason contains a home directory, so foldHome would change it")
	}
	if got := output.Message(outcome.Reason); got != outcome.Reason {
		t.Fatalf("Message changed the reason to %q", got)
	}
	return "tripcord pr-context: TC-CFG-014 incomplete: " + outcome.Reason
}

// pathCapStderr is the line pathcap.sh compares against. It has to be
// the line pr-context writes.
func pathCapStderr(t *testing.T) string {
	t.Helper()
	want := pathCapLineFromRule(t)
	cmd := exec.Command("bash", "-c", `. .github/actions/tripcord/pathcap.sh; printf '%s' "$path_cap_stderr"`)
	cmd.Dir = repoRoot(t)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("read path_cap_stderr: %v", err)
	}
	if string(out) != want {
		t.Fatalf("pathcap.sh = %q, want %q", out, want)
	}
	script, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "actions", "tripcord", "pathcap.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "path_cap_stderr='"+want+"'") {
		t.Fatal("pathcap.sh does not assign the derived line")
	}
	if !strings.Contains(string(script), `echo "`+pathCapWarning+`"`) {
		t.Fatal("pathcap.sh does not emit the path-cap warning")
	}
	return want
}

func TestPathCapLineIsNotCopiedIntoTheCheckers(t *testing.T) {
	line := pathCapStderr(t)
	root := repoRoot(t)
	for _, rel := range []string{
		".github/actions/tripcord/action.yml",
		".github/workflows/ci.yml",
	} {
		text, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(text), line) {
			t.Fatalf("%s copies the path-cap line; source pathcap.sh instead", rel)
		}
		if !strings.Contains(string(text), "pathcap.sh") {
			t.Fatalf("%s does not source pathcap.sh", rel)
		}
	}
}

func TestCallerAssertsPathCap(t *testing.T) {
	script := callerAssertScript(t)
	line := pathCapStderr(t)
	sarif := filepath.Join(t.TempDir(), "out.sarif")
	body := []byte(`{"runs":[{"results":[{"ruleId":"TC-CFG-001","locations":[{"physicalLocation":{"artifactLocation":{"uri":"testdata/ci-caller/hooks.json"}}}]}]}]}`)
	if err := os.WriteFile(sarif, body, 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, prExit, stderr string) (int, string) {
		t.Helper()
		cmd := exec.Command("bash", "-c", script)
		cmd.Dir = repoRoot(t)
		cmd.Env = append(os.Environ(),
			"TRIPCORD_OUTCOME=failure",
			"TRIPCORD_EXIT=1",
			"TRIPCORD_SARIF="+sarif,
			"TRIPCORD_PR_EXIT="+prExit,
			"TRIPCORD_PR_STDERR="+stderr,
			"TRIPCORD_IS_AGENT=true",
		)
		out, err := cmd.CombinedOutput()
		return exitCode(t, err), string(out)
	}

	t.Run("path cap", func(t *testing.T) {
		for _, stderr := range []string{line, line + "\n"} {
			code, out := run(t, "3", stderr)
			if code != 0 || !strings.Contains(out, pathCapWarning) || !strings.Contains(out, "assertion passed: pr-context exit 3 is the TC-CFG-014 path cap") {
				t.Fatalf("stderr %q = %d\n%s", stderr, code, out)
			}
		}
	})
	t.Run("other exit 3", func(t *testing.T) {
		for _, stderr := range []string{
			"tripcord pr-context: TC-CFG-014 incomplete: review data is not available\n",
			line + "\nmore\n",
			line + " ",
			"",
		} {
			code, out := run(t, "3", stderr)
			if code == 0 || strings.Contains(out, pathCapWarning) || !strings.Contains(out, "pr-context exit 3 is not the TC-CFG-014 path cap") {
				t.Fatalf("stderr %q = %d\n%s", stderr, code, out)
			}
		}
	})
	t.Run("exit 1", func(t *testing.T) {
		code, out := run(t, "1", line+"\n")
		if code != 0 || strings.Contains(out, pathCapWarning) || !strings.Contains(out, "assertion passed: pr-context exit is 1") {
			t.Fatalf("exit 1 = %d\n%s", code, out)
		}
	})
}

func callerAssertScript(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	job := mapping(t, mapping(t, mapping(t, &root)["jobs"])["tripcord-caller"])
	for _, step := range seq(t, job["steps"]) {
		parsed := mapping(t, step)
		if scalar(parsed["name"]) == "Assert remote scan" {
			return scalar(parsed["run"])
		}
	}
	t.Fatal("caller is missing Assert remote scan")
	return ""
}

func TestPRContextStepCapturesStderr(t *testing.T) {
	action := parseAction(t)
	var run string
	for _, step := range action.Runs.Steps {
		if step.ID == "pr-context" {
			run = step.Run
		}
	}
	if run == "" {
		t.Fatal("action has no pr-context step")
	}
	line := pathCapStderr(t)
	dir := t.TempDir()
	stub := filepath.Join(dir, "tripcord")
	body := "#!/bin/sh\nprintf '%s\\n' '" + line + "' >&2\nexit 3\n"
	if err := os.WriteFile(stub, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("#!/bin/sh\nprintf '%s\\n' 'tripcord pr-context: TC-CFG-014 incomplete: review data is not available' >&2\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	capture := func(t *testing.T, bin string) (string, string) {
		t.Helper()
		outFile := filepath.Join(t.TempDir(), "output")
		cmd := exec.Command("bash", "-c", run)
		cmd.Env = append(os.Environ(),
			"TRIPCORD="+bin,
			"TRIPCORD_PATH="+dir,
			"TRIPCORD_REVIEWS_FILE="+filepath.Join(dir, "reviews.json"),
			"RUNNER_TEMP="+dir,
			"GITHUB_OUTPUT="+outFile,
		)
		if _, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(outFile)
		if err != nil {
			t.Fatal(err)
		}
		return githubOutput(t, string(raw), "exit-code"), githubOutput(t, string(raw), "stderr")
	}
	if code, stderr := capture(t, stub); code != "3" || (stderr != line && stderr != line+"\n") {
		t.Fatalf("path cap capture = code %q stderr %q", code, stderr)
	}
	if code, stderr := capture(t, other); code != "3" || stderr == line || stderr == line+"\n" || !strings.Contains(stderr, "review data is not available") {
		t.Fatalf("other capture = code %q stderr %q", code, stderr)
	}
}

func githubOutput(t *testing.T, raw, key string) string {
	t.Helper()
	lines := strings.Split(raw, "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if strings.HasPrefix(line, key+"<<") {
			delim := strings.TrimPrefix(line, key+"<<")
			var b strings.Builder
			for i++; i < len(lines) && lines[i] != delim; i++ {
				if b.Len() > 0 {
					b.WriteByte('\n')
				}
				b.WriteString(lines[i])
			}
			return b.String()
		}
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimPrefix(line, key+"=")
		}
	}
	t.Fatalf("output %s missing from %q", key, raw)
	return ""
}

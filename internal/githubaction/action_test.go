package githubaction_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestTripcordActionContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "actions", "tripcord", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "always()") {
		t.Fatal("action uses always()")
	}
	for _, gone := range []string{"hashFiles(", "go install", "TODO(#33)"} {
		if strings.Contains(text, gone) {
			t.Fatalf("action still contains %s", gone)
		}
	}

	var action struct {
		Inputs map[string]struct {
			Default string `yaml:"default"`
		} `yaml:"inputs"`
		Outputs map[string]struct {
			Value string `yaml:"value"`
		} `yaml:"outputs"`
		Runs struct {
			Using string `yaml:"using"`
			Steps []struct {
				ID   string `yaml:"id"`
				If   string `yaml:"if"`
				Uses string `yaml:"uses"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(data, &action); err != nil {
		t.Fatalf("parse action.yml: %v", err)
	}
	if action.Runs.Using != "composite" {
		t.Fatalf("runs.using = %q, want composite", action.Runs.Using)
	}
	if got := action.Inputs["fail-on"].Default; got != "" {
		t.Fatalf("fail-on default = %q, want empty", got)
	}
	if got := action.Inputs["binary"].Default; got != "" {
		t.Fatalf("binary default = %q, want empty", got)
	}
	if got := action.Inputs["ref"].Default; got != "" {
		t.Fatalf("ref default = %q, want empty", got)
	}
	if got := action.Inputs["upload-sarif"].Default; got != "true" {
		t.Fatalf("upload-sarif default = %q, want true", got)
	}
	for _, name := range []string{"is_agent", "agents"} {
		if action.Outputs[name].Value == "" {
			t.Errorf("action does not expose pr-context output %s", name)
		}
	}
	if action.Outputs["tc-cfg-014"].Value == "" {
		t.Error("action does not expose the TC-CFG-014 outcome")
	}

	const (
		checkout    = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
		setupGo     = "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e"
		uploadSARIF = "github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370"
		comment     = "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3"
	)
	seenUses := map[string]bool{}
	allowed := map[string]bool{checkout: true, setupGo: true, uploadSARIF: true, comment: true}
	var scan, prContext string
	for _, step := range action.Runs.Steps {
		if strings.Contains(step.If, "always()") || strings.Contains(step.Run, "always()") {
			t.Fatalf("step %q uses always()", step.ID)
		}
		if strings.Contains(step.Run, "${{") {
			t.Fatalf("step %q interpolates an expression into run", step.ID)
		}
		if step.Uses != "" {
			if !allowed[step.Uses] {
				t.Errorf("unpinned or unexpected action %q", step.Uses)
			}
			seenUses[step.Uses] = true
		}
		if step.ID == "scan" {
			scan = step.Run
		}
		if step.ID == "pr-context" {
			prContext = step.Run
		}
	}
	for pin := range allowed {
		if !seenUses[pin] {
			t.Errorf("missing pinned action %s", pin)
		}
	}
	for _, version := range []string{"# v7.0.1", "# v7.0.0", "# v4.39.1", "# v9.0.0"} {
		if !strings.Contains(text, version) {
			t.Errorf("action is missing pin comment %s", version)
		}
	}
	if !strings.Contains(scan, `if [ -n "$TRIPCORD_FAIL_ON" ]`) || !strings.Contains(scan, `args+=(--fail-on "$TRIPCORD_FAIL_ON")`) {
		t.Fatal("scan does not pass --fail-on only when the caller sets it")
	}
	if got := action.Inputs["base"].Default; got != "${{ github.event.pull_request.base.sha }}" {
		t.Fatalf("base default = %q, want the pull request base sha", got)
	}
	if strings.Count(scan, `"${args[@]}"`) != 3 || !strings.Contains(scan, `args+=(--base "$TRIPCORD_BASE")`) {
		t.Fatal("scan does not pass --base to every report")
	}
	if strings.Contains(scan, "--fail-on high") {
		t.Fatal("scan hard-codes --fail-on high")
	}
	if !strings.Contains(scan, "exit 0") {
		t.Fatal("scan step fails the job before publishing")
	}
	if !strings.Contains(text, "steps.scan.outputs.exit-code != ''") {
		t.Fatal("publishing steps are not gated on the scan exit code")
	}
	if !strings.Contains(text, "go build -trimpath -o") || !strings.Contains(text, "./cmd/tripcord") {
		t.Fatal("action does not build ./cmd/tripcord")
	}
	if !strings.Contains(prContext, "pr-context --format gha") {
		t.Fatal("action does not run pr-context with the built binary")
	}
	reviews, ok := action.Inputs["reviews-file"]
	if !ok {
		t.Fatal("action has no reviews-file input")
	}
	if reviews.Default != "" {
		t.Fatalf("reviews-file default = %q, want empty", reviews.Default)
	}
	if !strings.Contains(prContext, `if [ -n "$TRIPCORD_REVIEWS_FILE" ]`) || !strings.Contains(prContext, `--reviews-file "$TRIPCORD_REVIEWS_FILE"`) {
		t.Fatal("pr-context does not pass --reviews-file only when the caller sets it")
	}
	if !strings.Contains(prContext, `echo "exit-code=$status"`) {
		t.Fatal("pr-context does not record exit-code=$status")
	}
	if strings.Contains(prContext, "${{") {
		t.Fatal("pr-context interpolates an expression into run")
	}
	if !strings.Contains(prContext, "could not make a policy decision") {
		t.Fatal("pr-context does not warn when reviews are unavailable")
	}
	if !strings.Contains(text, "core.warning") || !strings.Contains(text, "catch (error)") {
		t.Fatal("fork and read-only publishing does not warn")
	}

	bin := buildTripcord(t)
	t.Run("policy medium", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "repo")
		writeFile(t, filepath.Join(root, ".claude-plugin", "plugin.json"), "{\n  \"name\": \"acme-tools\"\n}\n")
		policy := writePolicy(t, "version: 1\nmode: enforce\nfail-on: medium\n")
		code, stdout, stderr := runScan(t, bin, root, policy)
		if code != 1 {
			t.Fatalf("policy medium + medium finding = %d, want 1\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
	})
	t.Run("policy critical with a high finding", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "repo")
		writeFile(t, filepath.Join(root, ".vscode", "tasks.json"), `{
  "version": "2.0.0",
  "tasks": [{
    "label": "watch",
    "type": "process",
    "command": "node",
    "args": [".vscode/setup.js"],
    "runOptions": { "runOn": "folderOpen" }
  }]
}
`)
		policy := writePolicy(t, "version: 1\nmode: enforce\nfail-on: critical\n")
		code, stdout, stderr := runScan(t, bin, root, policy)
		if code != 0 {
			t.Fatalf("policy critical + high finding = %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
		if !strings.Contains(stdout, "TC-CFG-002") {
			t.Fatalf("high finding was not reported:\n%s", stdout)
		}
	})
	t.Run("locked policy", func(t *testing.T) {
		root := t.TempDir()
		policy := writePolicy(t, "version: 1\nmode: enforce\nfail-on: medium\nlocked:\n  mode: true\n")
		cmd := exec.Command(bin, "scan", "--policy", policy, "--fail-on", "critical", root)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		code := exitCode(t, err)
		if code != 3 || !strings.Contains(stderr.String(), "ceiling") {
			t.Fatalf("loosening a locked policy = %d, want 3\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}
	})
}

func TestActionRejectsBinaryNewline(t *testing.T) {
	var tool actionStep
	for _, step := range parseAction(t).Runs.Steps {
		if step.ID == "tool" {
			tool = step
		}
	}
	if tool.Run == "" {
		t.Fatal("action has no tool step")
	}
	for _, tc := range []struct {
		name, binary string
	}{
		{name: "line feed", binary: "/tmp/tripcord\ninjected=1"},
		{name: "carriage return", binary: "/tmp/tripcord\rinjected=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "output")
			cmd := exec.Command("bash", "-c", tool.Run)
			cmd.Env = append(os.Environ(), "TRIPCORD_BINARY="+tc.binary, "TRIPCORD_BUILT=", "GITHUB_OUTPUT="+output)
			out, err := cmd.CombinedOutput()
			if exitCode(t, err) == 0 || !strings.Contains(string(out), "binary contains a newline") {
				t.Fatalf("exit error %v\n%s", err, out)
			}
			raw, readErr := os.ReadFile(output)
			if readErr != nil && !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			if strings.Contains(string(raw), "injected=") || strings.Contains(string(raw), "\npath=") {
				t.Fatalf("GITHUB_OUTPUT = %q", raw)
			}
		})
	}
	output := filepath.Join(t.TempDir(), "output")
	cmd := exec.Command("bash", "-c", tool.Run)
	cmd.Env = append(os.Environ(), "TRIPCORD_BINARY=/tmp/tripcord", "GITHUB_OUTPUT="+output)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("plain binary: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "path=/tmp/tripcord\n" {
		t.Fatalf("GITHUB_OUTPUT = %q", raw)
	}
}

func TestActionRejectsMissingOrEmptyPath(t *testing.T) {
	action := parseAction(t)
	var check actionStep
	checkAt, scanAt := -1, -1
	for i, step := range action.Runs.Steps {
		switch step.ID {
		case "check-path":
			check = step
			checkAt = i
		case "scan":
			scanAt = i
		}
	}
	if check.Run == "" {
		t.Fatal("action has no path check")
	}
	if checkAt < 0 || scanAt < 0 || checkAt > scanAt {
		t.Fatalf("path check is not before the scan: check=%d scan=%d", checkAt, scanAt)
	}
	if strings.Contains(check.Run, "${{") {
		t.Fatal("path check interpolates an expression into run")
	}
	run := func(t *testing.T, path string) (int, string) {
		t.Helper()
		cmd := exec.Command("bash", "-c", check.Run)
		cmd.Env = append(os.Environ(), "TRIPCORD_PATH="+path)
		out, err := cmd.CombinedOutput()
		return exitCode(t, err), string(out)
	}
	t.Run("empty", func(t *testing.T) {
		if code, out := run(t, ""); code == 0 || !strings.Contains(out, "path is empty") {
			t.Fatalf("empty path = %d\n%s", code, out)
		}
	})
	t.Run("missing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing")
		if code, out := run(t, path); code == 0 || !strings.Contains(out, "does not exist") {
			t.Fatalf("missing path = %d\n%s", code, out)
		}
	})
	t.Run("file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, out := run(t, path); code == 0 || !strings.Contains(out, "not a directory") {
			t.Fatalf("file path = %d\n%s", code, out)
		}
	})
	t.Run("empty directory", func(t *testing.T) {
		if code, out := run(t, t.TempDir()); code == 0 || !strings.Contains(out, "path is empty") {
			t.Fatalf("empty directory = %d\n%s", code, out)
		}
	})
	t.Run("unreadable directory", func(t *testing.T) {
		// Root can read a mode-000 directory, so the check would not fail.
		if runningAsRoot() {
			t.Skip("euid is 0")
		}
		dir := t.TempDir()
		if err := os.Chmod(dir, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		code, out := run(t, dir)
		if code == 0 || !strings.Contains(out, "path is unreadable") || strings.Contains(out, "path is empty") {
			t.Fatalf("unreadable directory = %d\n%s", code, out)
		}
	})
	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "README"), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, out := run(t, dir); code != 0 {
			t.Fatalf("non-empty directory = %d\n%s", code, out)
		}
	})
	t.Run("workflow command data", func(t *testing.T) {
		// Newline, %, ::, and comma. The path is command data, so % CR
		// and LF are escaped. : and , stay, inside the one error line.
		path := "a%b\n::error::injected,x\ry"
		code, out := run(t, path)
		want := "::error::tripcord path does not exist: a%25b%0A::error::injected,x%0Dy\n"
		if code == 0 || out != want {
			t.Fatalf("crafted path = %d\n%q\nwant %q", code, out, want)
		}
		if strings.Contains(out, "\n::") || strings.Contains(out, "\r") {
			t.Fatalf("crafted path starts another workflow command: %q", out)
		}
	})
}

func TestCICallerFixtureIsTCFG001(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "ci-caller", ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".claude", "settings.json"), string(raw))
	cmd := exec.Command(buildTripcord(t), "scan", "--format", "sarif", root)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if code := exitCode(t, err); code != 1 {
		t.Fatalf("fixture scan = %d, want 1\nstderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "TC-CFG-001") || !strings.Contains(stdout.String(), ".claude/settings.json") {
		t.Fatalf("fixture SARIF does not report TC-CFG-001 at the settings file:\n%s", stdout.String())
	}
}

func TestRefCheckoutIsRemovedBeforeDefaultPathScan(t *testing.T) {
	action := parseAction(t)
	if got := action.Inputs["path"].Default; got != "." {
		t.Fatalf("path default = %q, want .", got)
	}
	checkout, build, clean, scan := -1, -1, -1, -1
	for i, step := range action.Runs.Steps {
		switch {
		case strings.HasPrefix(step.Uses, "actions/checkout@"):
			checkout = i
			if !strings.Contains(step.If, "inputs.ref != ''") {
				t.Fatal("checkout is not limited to a set ref")
			}
			if step.With["path"] != "tripcord-src" {
				t.Fatalf("checkout path = %#v, want tripcord-src", step.With["path"])
			}
		case step.ID == "build":
			build = i
		case step.ID == "clean-source":
			clean = i
			if !strings.Contains(step.If, "inputs.ref != ''") {
				t.Fatal("source cleanup is not limited to a set ref")
			}
			if !strings.Contains(step.Run, `test -n "${GITHUB_WORKSPACE}"`) || !strings.Contains(step.Run, `rm -rf "${GITHUB_WORKSPACE}/tripcord-src"`) {
				t.Fatalf("source cleanup does not remove the workspace checkout:\n%s", step.Run)
			}
		case step.ID == "scan":
			scan = i
			if !strings.Contains(step.Run, `"$TRIPCORD_PATH"`) {
				t.Fatal("scan does not use the path input")
			}
		}
	}
	if checkout < 0 || build < 0 || clean < 0 || scan < 0 {
		t.Fatalf("missing step index checkout=%d build=%d clean=%d scan=%d", checkout, build, clean, scan)
	}
	if checkout >= build || build >= clean || clean >= scan {
		t.Fatalf("ref checkout is still in the tree at scan time: checkout=%d build=%d clean=%d scan=%d", checkout, build, clean, scan)
	}
}

func TestMissingSARIFFileWarnsWithoutBlamingTheToken(t *testing.T) {
	action := parseAction(t)
	var present, uploadIf, warning string
	for _, step := range action.Runs.Steps {
		switch step.ID {
		case "sarif-file":
			present = step.Run
		case "upload-sarif":
			uploadIf = step.If
		}
		script := step.With["script"]
		if strings.Contains(script, "the SARIF file is missing") {
			warning = script
		}
	}
	if !strings.Contains(present, `[ -f "$TRIPCORD_SARIF" ]`) || !strings.Contains(present, "present=false") {
		t.Fatalf("action does not record a missing SARIF file:\n%s", present)
	}
	if !strings.Contains(uploadIf, "steps.sarif-file.outputs.present == 'true'") {
		t.Fatalf("upload runs without a SARIF file: %s", uploadIf)
	}
	missing := strings.Index(warning, "the SARIF file is missing")
	token := strings.Index(warning, "the token cannot upload code scanning results")
	if missing < 0 || token < 0 || missing > token {
		t.Fatalf("missing-file warning does not precede the token warning:\n%s", warning)
	}
	if !strings.Contains(warning, `TRIPCORD_SARIF_PRESENT !== "true"`) {
		t.Fatal("warning does not check that the SARIF file is present")
	}
}

func TestTripcordActionPropagatesPolicyExit(t *testing.T) {
	action := parseAction(t)
	var apply actionStep
	for i, step := range action.Runs.Steps {
		if step.ID == "apply-exit-code" {
			if i != len(action.Runs.Steps)-1 {
				t.Fatal("Apply scan exit code is not the final action step")
			}
			apply = step
		}
	}
	if apply.Run == "" {
		t.Fatal("action has no policy exit-code step")
	}
	if apply.Name != "Apply scan exit code" {
		t.Fatalf("final step name = %q, want Apply scan exit code", apply.Name)
	}
	if apply.If != "steps.scan.outputs.exit-code != ''" {
		t.Fatalf("final step if = %q", apply.If)
	}
	if apply.ContinueOnError {
		t.Fatal("final step must not continue on error")
	}
	wantEnv := map[string]string{
		"TRIPCORD_SCAN_STATUS":       "${{ steps.scan.outputs.exit-code }}",
		"TRIPCORD_PR_CONTEXT_STATUS": "${{ steps.pr-context.outputs.exit-code }}",
		"TRIPCORD_REVIEWS_FILE":      "${{ inputs.reviews-file }}",
	}
	if len(apply.Env) != len(wantEnv) {
		t.Fatalf("final step env = %#v, want %#v", apply.Env, wantEnv)
	}
	for name, want := range wantEnv {
		if got := apply.Env[name]; got != want {
			t.Fatalf("final step env %s = %q, want %q", name, got, want)
		}
	}

	run := func(t *testing.T, scanStatus, reviewsFile, prContextStatus string) (int, string) {
		t.Helper()
		cmd := exec.Command("bash", "-c", apply.Run)
		cmd.Env = append(os.Environ(),
			"TRIPCORD_SCAN_STATUS="+scanStatus,
			"TRIPCORD_PR_CONTEXT_STATUS="+prContextStatus,
			"TRIPCORD_REVIEWS_FILE="+reviewsFile,
		)
		out, err := cmd.CombinedOutput()
		return exitCode(t, err), string(out)
	}

	reviewsFile := filepath.Join(t.TempDir(), "reviews.json")
	if err := os.WriteFile(reviewsFile, []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("deny with reviews file fails", func(t *testing.T) {
		if code, out := run(t, "0", reviewsFile, "1"); code != 1 || !strings.Contains(out, "denied the pull request under TC-CFG-014") {
			t.Fatalf("policy deny = %d, want 1\n%s", code, out)
		}
	})
	t.Run("deny without reviews file fails", func(t *testing.T) {
		if code, out := run(t, "0", "", "1"); code != 1 {
			t.Fatalf("policy deny without reviews = %d, want 1\n%s", code, out)
		}
	})
	t.Run("incomplete reviews file fails", func(t *testing.T) {
		if code, out := run(t, "0", reviewsFile, "3"); code != 3 || !strings.Contains(out, "could not validate TC-CFG-014") {
			t.Fatalf("incomplete review file = %d, want 3\n%s", code, out)
		}
	})
	t.Run("review read error fails", func(t *testing.T) {
		if code, out := run(t, "0", reviewsFile, "4"); code != 4 {
			t.Fatalf("review read error = %d, want 4\n%s", code, out)
		}
	})
	t.Run("incomplete without reviews file warns", func(t *testing.T) {
		if code, out := run(t, "0", "", "3"); code != 0 {
			t.Fatalf("missing review file = %d, want 0\n%s", code, out)
		}
	})
	t.Run("missing policy status fails", func(t *testing.T) {
		if code, out := run(t, "0", "", ""); code == 0 {
			t.Fatalf("missing policy status = %d, want non-zero\n%s", code, out)
		}
	})
	t.Run("scan exit code wins", func(t *testing.T) {
		if code, out := run(t, "2", reviewsFile, "1"); code != 2 {
			t.Fatalf("scan exit = %d, want 2\n%s", code, out)
		}
	})
}

type actionFile struct {
	Inputs map[string]struct {
		Default string `yaml:"default"`
	} `yaml:"inputs"`
	Outputs map[string]struct {
		Value string `yaml:"value"`
	} `yaml:"outputs"`
	Runs struct {
		Steps []actionStep `yaml:"steps"`
	} `yaml:"runs"`
}

type actionStep struct {
	ID              string            `yaml:"id"`
	Name            string            `yaml:"name"`
	If              string            `yaml:"if"`
	Uses            string            `yaml:"uses"`
	Run             string            `yaml:"run"`
	With            map[string]string `yaml:"with"`
	Env             map[string]string `yaml:"env"`
	ContinueOnError bool              `yaml:"continue-on-error"`
}

func parseAction(t *testing.T) actionFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "actions", "tripcord", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var action actionFile
	if err := yaml.Unmarshal(data, &action); err != nil {
		t.Fatalf("parse action.yml: %v", err)
	}
	return action
}

func buildTripcord(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tripcord")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/tripcord")
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build tripcord: %v\n%s", err, out)
	}
	return bin
}

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runScan(t *testing.T, bin, root, policy string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(bin, "scan", "--policy", policy, root)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return exitCode(t, err), stdout.String(), stderr.String()
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	t.Fatal(err)
	return -1
}

// TestActionScanComparesWithPullRequestBase runs the action's own scan
// step, as the reusable workflow does on a pull request, against a
// repository whose head removes the Tripcord embed its base has.
func TestActionScanComparesWithPullRequestBase(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	var scan actionStep
	for _, step := range parseAction(t).Runs.Steps {
		if step.ID == "scan" {
			scan = step
		}
	}
	if scan.Env["TRIPCORD_BASE"] != "${{ inputs.base }}" {
		t.Fatalf("scan env TRIPCORD_BASE = %q", scan.Env["TRIPCORD_BASE"])
	}
	bin := buildTripcord(t)
	repo := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.com"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	if out, err := exec.Command(bin, "init", "--embed", "--version", "0.1.0", "--sha256", "linux-x64="+strings.Repeat("a", 64), repo).CombinedOutput(); err != nil {
		t.Fatalf("init --embed: %v\n%s", err, out)
	}
	git("add", "-A")
	git("commit", "-qm", "embed tripcord")
	base := git("rev-parse", "HEAD")
	for _, p := range []string{".tripcord/bootstrap.sh", ".tripcord/embed.json", ".github/hooks/tripcord.json", ".github/workflows/tripcord.yml", ".github/workflows/copilot-setup-steps.yml"} {
		err := os.Remove(filepath.Join(repo, p))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(repo, ".claude", "settings.json"), "{\n  \"hooks\": {}\n}\n")
	writeFile(t, filepath.Join(repo, ".cursor", "hooks.json"), "{\n  \"version\": 1,\n  \"hooks\": {}\n}\n")
	// The same change turns the policy to audit, in policy.yaml and in
	// a committed policy.local.yaml: the scan must use the base's.
	writeFile(t, filepath.Join(repo, ".tripcord", "policy.yaml"), "version: 1\nmode: audit\n")
	writeFile(t, filepath.Join(repo, ".tripcord", "policy.local.yaml"), "version: 1\nmode: audit\n")
	git("add", "-A")
	git("commit", "-qm", "remove the guard")

	run := func(t *testing.T, base string) (string, string) {
		t.Helper()
		tmp := t.TempDir()
		output := filepath.Join(tmp, "output")
		cmd := exec.Command("bash", "-c", scan.Run)
		cmd.Env = append(os.Environ(),
			"TRIPCORD="+bin,
			"TRIPCORD_PATH="+repo,
			"TRIPCORD_FAIL_ON=",
			"TRIPCORD_BASE="+base,
			"TRIPCORD_SARIF="+filepath.Join(tmp, "tripcord.sarif"),
			"TRIPCORD_MARKDOWN="+filepath.Join(tmp, "tripcord.md"),
			"GITHUB_OUTPUT="+output,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("scan step: %v\n%s", err, out)
		}
		raw, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(raw)), string(out)
	}
	t.Run("pull request base", func(t *testing.T) {
		exit, out := run(t, base)
		if exit != "exit-code=1" || !strings.Contains(out, "TC-CFG-016") || !strings.Contains(out, "This change removes Tripcord") ||
			!strings.Contains(out, "This change weakens the Tripcord policy") {
			t.Fatalf("%s\n%s", exit, out)
		}
	})
	t.Run("no base", func(t *testing.T) {
		if exit, out := run(t, ""); exit != "exit-code=0" {
			t.Fatalf("%s\n%s", exit, out)
		}
	})
	t.Run("path is not a git repository", func(t *testing.T) {
		plain := t.TempDir()
		writeFile(t, filepath.Join(plain, "README"), "x\n")
		cmd := exec.Command("bash", "-c", scan.Run)
		output := filepath.Join(t.TempDir(), "output")
		cmd.Env = append(os.Environ(),
			"TRIPCORD="+bin,
			"TRIPCORD_PATH="+plain,
			"TRIPCORD_FAIL_ON=",
			"TRIPCORD_BASE="+base,
			"TRIPCORD_SARIF="+filepath.Join(t.TempDir(), "tripcord.sarif"),
			"TRIPCORD_MARKDOWN="+filepath.Join(t.TempDir(), "tripcord.md"),
			"GITHUB_OUTPUT="+output,
			"GIT_CEILING_DIRECTORIES="+filepath.Dir(plain),
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("scan step: %v\n%s", err, out)
		}
		raw, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if exit := strings.TrimSpace(string(raw)); exit != "exit-code=0" || !strings.Contains(string(out), "not a Git repository") {
			t.Fatalf("%s\n%s", exit, out)
		}
	})
	t.Run("base not fetched", func(t *testing.T) {
		exit, out := run(t, strings.Repeat("b", 40))
		if exit != "exit-code=3" || !strings.Contains(out, "fetch-depth: 0") {
			t.Fatalf("%s\n%s", exit, out)
		}
	})
	t.Run("base workflow command data", func(t *testing.T) {
		_, out := run(t, "abc%def\n::error::injected\r")
		want := "::error::tripcord base commit abc%25def%0A::error::injected%0D is not in the checkout"
		if !strings.Contains(out, want) || strings.Contains(out, "\n::error::injected") || strings.Contains(out, "\r") {
			t.Fatalf("crafted base = %q\nwant %q", out, want)
		}
	})
}

// TestCommentUpsertUsesTokenIdentity runs the action's comment script.
// A marked comment is updated only when its author is the authenticated
// token: github-actions[bot], another app, or a user. Another bot is left
// alone even when the login string matches.
func TestCommentUpsertUsesTokenIdentity(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Fatal("node is not installed")
	}
	var script string
	for _, step := range parseAction(t).Runs.Steps {
		if strings.Contains(step.With["script"], "tripcord-report") {
			script = step.With["script"]
		}
	}
	if script == "" {
		t.Fatal("action has no report comment script")
	}
	if strings.Contains(script, `comment.user.type === "Bot"`) {
		t.Fatal("comment upsert still accepts any bot")
	}
	if !strings.Contains(script, "users.getAuthenticated") {
		t.Fatal("comment upsert does not look up the token identity")
	}

	markdown := filepath.Join(t.TempDir(), "report.md")
	if err := os.WriteFile(markdown, []byte("report body\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const marker = "<!-- tripcord-report -->"
	comment := func(id int, login string, userID int, kind string) map[string]any {
		return map[string]any{
			"id":   id,
			"body": marker + "\nold",
			"user": map[string]any{"login": login, "id": userID, "type": kind},
		}
	}
	actions := comment(10, "github-actions[bot]", 41898282, "Bot")
	dependabot := comment(11, "dependabot[bot]", 49699333, "Bot")
	human := comment(12, "octocat", 1, "User")
	spoofed := comment(13, "github-actions[bot]", 1, "Bot")
	app := comment(14, "my-app[bot]", 99, "Bot")

	run := func(t *testing.T, fixture map[string]any) []map[string]any {
		t.Helper()
		fixture["markdown"] = markdown
		dir := t.TempDir()
		scriptPath := filepath.Join(dir, "script.js")
		fixturePath := filepath.Join(dir, "fixture.json")
		if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(fixture)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixturePath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		harness := `
const fs = require("fs");
const script = fs.readFileSync(process.argv[1], "utf8");
const fixture = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const calls = [];
const core = { warning(message) { calls.push({ op: "warning", message }); } };
const context = { payload: { pull_request: { number: 7 } }, repo: { owner: "acme", repo: "tools" } };
function httpError(spec) {
  const err = new Error(spec.message || "request failed");
  if (spec.status) err.status = spec.status;
  return err;
}
const github = {
  paginate: async () => fixture.comments,
  graphql: async () => {
    calls.push({ op: "graphql" });
    if (fixture.graphqlError) throw httpError(fixture.graphqlError);
    return { viewer: fixture.viewer == null ? null : fixture.viewer };
  },
  rest: {
    users: {
      getAuthenticated: async () => {
        calls.push({ op: "getUser" });
        if (fixture.userError) throw httpError(fixture.userError);
        return { data: fixture.me };
      },
    },
    issues: {
      updateComment: async (args) => { calls.push({ op: "update", id: args.comment_id }); },
      createComment: async (args) => { calls.push({ op: "create", body: args.body }); },
    },
  },
};
process.env.TRIPCORD_MARKDOWN = fixture.markdown;
process.env.TRIPCORD_HEAD_REPO = "";
process.env.TRIPCORD_BASE_REPO = "";
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
new AsyncFunction("core", "context", "github", "process", script)(core, context, github, process)
  .then(() => process.stdout.write(JSON.stringify(calls)))
  .catch((err) => { console.error(err); process.exit(1); });
`
		cmd := exec.Command("node", "-e", harness, scriptPath, fixturePath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("comment script: %v\n%s", err, out)
		}
		var calls []map[string]any
		if err := json.Unmarshal(out, &calls); err != nil {
			t.Fatalf("calls %s: %v", out, err)
		}
		return calls
	}
	ops := func(calls []map[string]any) []string {
		t.Helper()
		var got []string
		for _, call := range calls {
			switch call["op"] {
			case "update":
				got = append(got, "update:"+jsonNumber(t, call["id"]))
			case "create":
				body, _ := call["body"].(string)
				if !strings.HasPrefix(body, marker+"\n") || !strings.Contains(body, "report body") {
					t.Fatalf("create body = %q", body)
				}
				got = append(got, "create")
			case "warning":
				got = append(got, "warning")
			case "getUser", "graphql":
			default:
				t.Fatalf("call = %#v", call)
			}
		}
		return got
	}
	assertOps := func(t *testing.T, me map[string]any, comments []map[string]any, want ...string) {
		t.Helper()
		got := ops(run(t, map[string]any{"me": me, "comments": comments}))
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("ops = %v, want %v", got, want)
		}
	}
	saw := func(calls []map[string]any, op string) bool {
		for _, call := range calls {
			if call["op"] == op {
				return true
			}
		}
		return false
	}

	t.Run("github-actions bot", func(t *testing.T) {
		assertOps(t,
			map[string]any{"login": "github-actions[bot]", "id": 41898282, "type": "Bot"},
			[]map[string]any{dependabot, human, spoofed, actions},
			"update:10",
		)
	})
	t.Run("authenticated app", func(t *testing.T) {
		assertOps(t,
			map[string]any{"login": "my-app[bot]", "id": 99, "type": "Bot"},
			[]map[string]any{actions, app},
			"update:14",
		)
	})
	t.Run("authenticated user", func(t *testing.T) {
		assertOps(t,
			map[string]any{"login": "octocat", "id": 1, "type": "User"},
			[]map[string]any{actions, human},
			"update:12",
		)
	})
	t.Run("someone else's comment is not edited", func(t *testing.T) {
		assertOps(t,
			map[string]any{"login": "github-actions[bot]", "id": 41898282, "type": "Bot"},
			[]map[string]any{dependabot, human, spoofed},
			"create",
		)
	})
	t.Run("missing identity", func(t *testing.T) {
		assertOps(t, map[string]any{}, []map[string]any{actions}, "warning")
	})

	forbidden := map[string]any{"status": 403, "message": "Resource not accessible by integration"}
	t.Run("403 then graphql viewer", func(t *testing.T) {
		calls := run(t, map[string]any{
			"userError": forbidden,
			"viewer":    map[string]any{"login": "github-actions[bot]", "databaseId": 41898282},
			"comments":  []map[string]any{dependabot, human, spoofed, actions},
		})
		if !saw(calls, "getUser") || !saw(calls, "graphql") {
			t.Fatalf("calls = %#v", calls)
		}
		if got := ops(calls); strings.Join(got, ",") != "update:10" {
			t.Fatalf("ops = %v", got)
		}
	})
	t.Run("403 then graphql viewer for another app", func(t *testing.T) {
		calls := run(t, map[string]any{
			"userError": forbidden,
			"viewer":    map[string]any{"login": "my-app[bot]", "databaseId": 99},
			"comments":  []map[string]any{actions, app},
		})
		if got := ops(calls); strings.Join(got, ",") != "update:14" {
			t.Fatalf("ops = %v", got)
		}
	})
	t.Run("403 message without status", func(t *testing.T) {
		calls := run(t, map[string]any{
			"userError": map[string]any{"message": "Resource not accessible by integration"},
			"viewer":    map[string]any{"login": "github-actions[bot]", "databaseId": 41898282},
			"comments":  []map[string]any{dependabot, actions},
		})
		if got := ops(calls); strings.Join(got, ",") != "update:10" {
			t.Fatalf("ops = %v", got)
		}
	})
	t.Run("403 then graphql failure", func(t *testing.T) {
		calls := run(t, map[string]any{
			"userError":    forbidden,
			"graphqlError": map[string]any{"message": "Resource not accessible by integration"},
			"comments":     []map[string]any{actions, dependabot, human},
		})
		if !saw(calls, "graphql") {
			t.Fatalf("calls = %#v", calls)
		}
		if got := ops(calls); strings.Join(got, ",") != "warning" {
			t.Fatalf("ops = %v", got)
		}
	})
	t.Run("403 then empty viewer", func(t *testing.T) {
		calls := run(t, map[string]any{
			"userError": forbidden,
			"comments":  []map[string]any{actions, dependabot},
		})
		if got := ops(calls); strings.Join(got, ",") != "warning" {
			t.Fatalf("ops = %v", got)
		}
	})
	t.Run("non-403 identity error does not fail the step", func(t *testing.T) {
		calls := run(t, map[string]any{
			"userError": map[string]any{"status": 401, "message": "Bad credentials"},
			"viewer":    map[string]any{"login": "github-actions[bot]", "databaseId": 41898282},
			"comments":  []map[string]any{actions},
		})
		if saw(calls, "graphql") {
			t.Fatalf("graphql was called: %#v", calls)
		}
		if got := ops(calls); strings.Join(got, ",") != "warning" {
			t.Fatalf("ops = %v", got)
		}
	})
}

func jsonNumber(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

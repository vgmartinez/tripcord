// Command knownrenders regenerates internal/embedded/known_renders.json:
// for every main commit since the embed check whose WorkflowPin is in
// {WorkflowPin} ∪ KnownWorkflowPins, it builds that commit's tripcord,
// runs init --embed with a fixed dummy pin, and records the render
// digests under that pin, plus what this tree's init writes. Run it from
// the repository root after a repin:
//
//	go run ./scripts/knownrenders
//
// It needs the full git history.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/embedded"
)

// embedCheckCommit is the merge that added init --embed. Its own pin and
// its parent's are excluded (embedded.ExcludedWorkflowPins).
const embedCheckCommit = "8b33b1b5a69c686b611b43a475da9658fe44614d"

var workflowPinLine = regexp.MustCompile(`\bWorkflowPin\s*=\s*"([0-9a-f]{40})"`)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "knownrenders:", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := git("", "rev-parse", "--show-toplevel")
	if err != nil {
		return err
	}
	root = strings.TrimSpace(root)
	list, err := git(root, "rev-list", "--reverse", embedCheckCommit+"..HEAD", "--", "internal/embedded", "cmd/tripcord/init.go")
	if err != nil {
		return err
	}
	out := embedded.KnownRendersFile{Schema: embedded.KnownRendersSchema, Pins: map[string]embedded.RenderSet{}}
	keep := append([]string{embedded.WorkflowPin}, embedded.KnownWorkflowPins...)
	for _, commit := range strings.Fields(list) {
		src, err := git(root, "show", commit+":internal/embedded/workflow.go")
		if err != nil {
			return err
		}
		m := workflowPinLine.FindStringSubmatch(src)
		if m == nil {
			return fmt.Errorf("%s: no WorkflowPin", commit)
		}
		if !slices.Contains(keep, m[1]) {
			continue
		}
		set, err := observe(root, commit)
		if err != nil {
			return fmt.Errorf("%s: %w", commit, err)
		}
		add(out.Pins, m[1], set)
		fmt.Fprintf(os.Stderr, "knownrenders: %s pins %s\n", commit[:12], m[1][:12])
	}
	add(out.Pins, embedded.WorkflowPin, embedded.CurrentRenders())
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, filepath.FromSlash(embedded.KnownRendersPath)), append(raw, '\n'), 0o644)
}

func add(pins map[string]embedded.RenderSet, pin string, set embedded.RenderSet) {
	s := pins[pin]
	s.Add(set)
	pins[pin] = s
}

// observe builds commit's tripcord and returns what its init writes.
func observe(root, commit string) (embedded.RenderSet, error) {
	tmp, err := os.MkdirTemp("", "knownrenders-")
	if err != nil {
		return embedded.RenderSet{}, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	src, repo, bin := filepath.Join(tmp, "src"), filepath.Join(tmp, "repo"), filepath.Join(tmp, "tripcord")
	for _, d := range []string{src, repo} {
		if err := os.Mkdir(d, 0o755); err != nil {
			return embedded.RenderSet{}, err
		}
	}
	archive := exec.Command("git", "archive", "--format=tar", commit)
	archive.Dir = root
	tarball, err := archive.Output()
	if err != nil {
		return embedded.RenderSet{}, fmt.Errorf("git archive: %w", err)
	}
	untar := exec.Command("tar", "-x", "-C", src)
	untar.Stdin = bytes.NewReader(tarball)
	if err := runCmd(untar); err != nil {
		return embedded.RenderSet{}, err
	}
	build := exec.Command("go", "build", "-trimpath", "-o", bin, "./cmd/tripcord")
	build.Dir = src
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if err := runCmd(build); err != nil {
		return embedded.RenderSet{}, err
	}
	if _, err := git(repo, "init", "-q"); err != nil {
		return embedded.RenderSet{}, err
	}
	args := []string{"init", repo, "--embed", "--version", "0.1.0", "--sha256", "linux-x64=" + strings.Repeat("0", 64)}
	// Later inits write the Copilot setup step only with --cloud-setup.
	if src, err := os.ReadFile(filepath.Join(src, "cmd", "tripcord", "init.go")); err == nil && bytes.Contains(src, []byte(`"cloud-setup"`)) {
		args = append(args, "--cloud-setup")
	}
	init := exec.Command(bin, args...)
	if err := runCmd(init); err != nil {
		return embedded.RenderSet{}, err
	}
	return embedded.ObserveRenders(repo)
}

func runCmd(cmd *exec.Cmd) error {
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(cmd.Args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"encoding/json"

	"github.com/vgmartinez/tripcord/internal/cfg014"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/gitrun"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/prcontext"
)

const prContextUsage = `tripcord pr-context [flags]

pr-context reads a GitHub pull_request event and the commits in base..head
and reports whether the pull request looks agent-authored. It exits 0
whether or not an agent is detected. When that author is an agent and
the diff changes a file an adapter classifies, TC-CFG-014 exits 1 if no
human approved the pull request, and exits 3 when the reviews or the
diff cannot be read.

Flags:
`

// maxEventBytes bounds the GitHub event file.
const maxEventBytes = 8 << 20

func runPrContext(args []string, stdout, stderr io.Writer) int {
	opts, err := parsePrContextFlags(args, stdout)
	if errors.Is(err, errHelp) {
		return int(exitcode.OK)
	}
	if errors.Is(err, errHelpWrite) {
		return int(exitcode.Internal)
	}
	if err != nil {
		return prContextFail(stderr, err, true)
	}
	outputPath := os.Getenv("GITHUB_OUTPUT")
	if opts.format == "gha" && outputPath == "" {
		return prContextFail(stderr, errors.New("--format gha requires GITHUB_OUTPUT"), true)
	}

	eventPath := opts.event
	if eventPath == "" {
		eventPath = os.Getenv("GITHUB_EVENT_PATH")
	}
	var ev prcontext.Event
	var reviews prcontext.ReviewSet
	if eventPath != "" {
		ev, reviews, err = readPullRequestEvent(eventPath)
		if err != nil {
			return prContextFail(stderr, err, false)
		}
	}
	if opts.base != "" {
		ev.Base = opts.base
	}
	if opts.head != "" {
		ev.Head = opts.head
	}
	branch, branchSource := ev.Branch, "pull_request.head.ref"
	if branch == "" && opts.head != "" && !fullSHA(opts.head) {
		branch, branchSource = strings.TrimPrefix(opts.head, "refs/heads/"), "--head"
	}
	if ev.Base == "" || ev.Head == "" {
		return prContextFail(stderr, errors.New("need a pull_request event or both --base and --head"), true)
	}
	repo := opts.repo
	if repo == "" {
		repo = "."
	}
	// Login and branch are known before git runs. Write them first so a
	// commit-read failure, including the process being killed while the
	// log is read, leaves that verdict in GITHUB_OUTPUT.
	early := prcontext.Detect(prcontext.Input{
		PRLogin:      ev.Login,
		PRAuthorType: ev.AuthorType,
		Branch:       branch,
		BranchSource: branchSource,
	})
	if outputPath != "" {
		if err := appendGitHubOutput(outputPath, early); err != nil {
			return prContextFail(stderr, err, false)
		}
	}
	// A commit or notes read failure does not abort: commits and notes
	// signals are simply missing, same as a shallow checkout that misses
	// the range. readErr is kept and only decides the exit code, after
	// stdout is written and GITHUB_OUTPUT has been updated.
	commits, warnings, readErr := prcontext.ReadCommits(context.Background(), repo, ev.Base, ev.Head)
	if readErr != nil {
		commits = nil
		warnings = append(warnings, "commits and notes were not read: "+oneLineError(redactHomeFromError(readErr)))
	}
	result := prcontext.Detect(prcontext.Input{
		PRLogin:      ev.Login,
		PRAuthorType: ev.AuthorType,
		Branch:       branch,
		BranchSource: branchSource,
		Commits:      commits,
		Warnings:     warnings,
	})
	// TC-CFG-014 runs only after the agent verdict is known, and only
	// when the commit read itself succeeded. A fatal read still reports
	// that verdict and keeps its own exit code.
	var outcome cfg014.Outcome
	var diffErr error
	if readErr == nil && result.Agent {
		diff, err := prcontext.ChangedPaths(context.Background(), repo, ev.Base, ev.Head)
		if err != nil {
			diffErr = err
		} else {
			outcome = cfg014.Evaluate(cfg014.Input{
				Agent:       true,
				Author:      ev.Login,
				Paths:       diff.Paths,
				PathsKnown:  !diff.Missing,
				Truncated:   diff.Truncated,
				Reviews:     reviews,
				Classifiers: cfg014.DefaultClassifiers(),
			})
		}
	}
	rendered, err := renderPrContext(opts.format, result, outcome)
	if err != nil {
		return prContextFail(stderr, err, false)
	}
	if writeString(stdout, rendered) != int(exitcode.OK) {
		return int(exitcode.Internal)
	}
	// Append again only when commits add agents. A second identical
	// block would change a file that previously held one, and GitHub
	// Actions already keeps the last value of each name.
	if outputPath != "" && prcontext.FormatOutput(result) != prcontext.FormatOutput(early) {
		if err := appendGitHubOutput(outputPath, result); err != nil {
			return prContextFail(stderr, err, false)
		}
	}
	if outputPath != "" && outcome.Status != "" && outcome.Status != cfg014.StatusClear {
		if err := appendGitHubOutputText(outputPath, "tc_cfg_014="+string(outcome.Status)+"\n"); err != nil {
			return prContextFail(stderr, err, false)
		}
	}
	if readErr != nil {
		return prContextFail(stderr, readErr, false)
	}
	if diffErr != nil {
		return prContextFail(stderr, diffErr, false)
	}
	switch outcome.Status {
	case "", cfg014.StatusClear:
		return int(exitcode.OK)
	case cfg014.StatusMatch:
		return int(exitcode.Findings)
	case cfg014.StatusIncomplete:
		writeString(stderr, "tripcord pr-context: TC-CFG-014 incomplete: "+outcome.Reason+"\n")
		return int(exitcode.Config)
	default:
		panic("pr-context: unhandled TC-CFG-014 status " + string(outcome.Status))
	}
}

// oneLineError collapses a (possibly multi-line) error message onto one
// line, so it fits the single "- <warning>" line format used by
// FormatText and does not break a GITHUB_OUTPUT heredoc.
func oneLineError(msg string) string {
	return strings.Join(strings.Fields(msg), " ")
}

type prContextOptions struct {
	event  string
	base   string
	head   string
	repo   string
	format string
}

func parsePrContextFlags(args []string, stdout io.Writer) (prContextOptions, error) {
	var opts prContextOptions
	flags := flag.NewFlagSet("pr-context", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
	flags.StringVar(&opts.event, "event", "", "GitHub pull_request event JSON (default: $GITHUB_EVENT_PATH)")
	flags.StringVar(&opts.base, "base", "", "base revision, overriding the event")
	flags.StringVar(&opts.head, "head", "", "head revision, overriding the event")
	flags.StringVar(&opts.repo, "repo", "", "repository to read (default: .)")
	flags.StringVar(&opts.format, "format", "text", "text, json, or gha")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			var buf strings.Builder
			if _, werr := buf.WriteString(prContextUsage); werr != nil {
				return prContextOptions{}, fmt.Errorf("%w: %w", errHelpWrite, werr)
			}
			flags.SetOutput(&buf)
			flags.PrintDefaults()
			if writeString(stdout, buf.String()) != int(exitcode.OK) {
				return prContextOptions{}, errHelpWrite
			}
			return prContextOptions{}, errHelp
		}
		return prContextOptions{}, err
	}
	if flags.NArg() != 0 {
		return prContextOptions{}, errors.New("pr-context takes no positional arguments")
	}
	switch opts.format {
	case "text", "json", "gha":
	default:
		return prContextOptions{}, fmt.Errorf("--format %q: want text, json, or gha", opts.format)
	}
	return opts, nil
}

func renderPrContext(format string, result prcontext.Result, outcome cfg014.Outcome) (string, error) {
	switch format {
	case "text", "gha":
		return prcontext.FormatText(result) + formatCfg014Text(outcome), nil
	case "json":
		if outcome.Status == "" || outcome.Status == cfg014.StatusClear {
			raw, err := prcontext.FormatJSON(result)
			if err != nil {
				return "", err
			}
			return string(raw), nil
		}
		return formatCfg014JSON(result, outcome)
	default:
		panic("prcontext: unhandled format " + format)
	}
}

func formatCfg014Text(outcome cfg014.Outcome) string {
	switch outcome.Status {
	case "", cfg014.StatusClear:
		return ""
	case cfg014.StatusMatch:
		var b strings.Builder
		b.WriteString("tc-cfg-014: match\n")
		for _, path := range outcome.Paths {
			b.WriteString("- " + path + "\n")
		}
		return b.String()
	case cfg014.StatusIncomplete:
		return "tc-cfg-014: incomplete\n- " + outcome.Reason + "\n"
	default:
		panic("pr-context: unhandled TC-CFG-014 status " + string(outcome.Status))
	}
}

type prContextEnvelope struct {
	prcontext.Result
	TCCFG014 string         `json:"tc_cfg_014,omitempty"`
	Finding  *model.Finding `json:"finding,omitempty"`
}

func formatCfg014JSON(result prcontext.Result, outcome cfg014.Outcome) (string, error) {
	if result.Agents == nil {
		result.Agents = []string{}
	}
	if result.Signals == nil {
		result.Signals = []prcontext.Signal{}
	}
	raw, err := json.MarshalIndent(prContextEnvelope{
		Result:   result,
		TCCFG014: string(outcome.Status),
		Finding:  outcome.Finding,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw) + "\n", nil
}

func readPullRequestEvent(path string) (prcontext.Event, prcontext.ReviewSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return prcontext.Event{}, prcontext.ReviewSet{}, &prcontext.InputError{Msg: fmt.Sprintf("event file: %v", err)}
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return prcontext.Event{}, prcontext.ReviewSet{}, err
	}
	if info.IsDir() {
		_ = f.Close()
		return prcontext.Event{}, prcontext.ReviewSet{}, &prcontext.InputError{Msg: "event file is a directory"}
	}
	if info.Size() > maxEventBytes {
		_ = f.Close()
		return prcontext.Event{}, prcontext.ReviewSet{}, &prcontext.InputError{Msg: "event file is too large"}
	}
	data, err := io.ReadAll(io.LimitReader(f, maxEventBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return prcontext.Event{}, prcontext.ReviewSet{}, err
	}
	if len(data) > maxEventBytes {
		return prcontext.Event{}, prcontext.ReviewSet{}, &prcontext.InputError{Msg: "event file is too large"}
	}
	ev, err := prcontext.ParseEvent(data)
	if err != nil {
		return prcontext.Event{}, prcontext.ReviewSet{}, err
	}
	reviews, err := prcontext.ParseReviews(data)
	if err != nil {
		return prcontext.Event{}, prcontext.ReviewSet{}, err
	}
	return ev, reviews, nil
}

// appendGitHubOutput appends result to the GITHUB_OUTPUT file. The open
// refuses a symlink target (atomically via O_NOFOLLOW on unix, via an
// Lstat check first elsewhere) and, once opened, refuses anything that
// is not a regular file (a FIFO could otherwise hang a write or stream
// to an unexpected reader). If the file already has content that does
// not end in a newline, a newline is written before appending, so this
// line is never run together with the last one already in the file.
func appendGitHubOutput(path string, result prcontext.Result) error {
	if err := refuseGitHubOutputSymlink(path); err != nil {
		return err
	}
	// O_RDWR, not O_WRONLY: writeGitHubOutput reads the file's last byte
	// to decide whether a leading newline is needed before it appends.
	// O_APPEND still forces every write to the end regardless of that
	// read's position, and a FIFO opened O_RDWR never blocks waiting for
	// a reader, so this does not reintroduce the hang outputOpenFlags'
	// O_NONBLOCK guards against for O_WRONLY.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR|outputOpenFlags, 0o600)
	if err != nil {
		return classifyOutputOpenError(err)
	}
	err = writeGitHubOutput(f, prcontext.FormatOutput(result))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// appendGitHubOutputText appends one extra GITHUB_OUTPUT line, such as
// tc_cfg_014=match. The agent block is written separately and is left
// unchanged when the rule is clear.
func appendGitHubOutputText(path, text string) error {
	if err := refuseGitHubOutputSymlink(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR|outputOpenFlags, 0o600)
	if err != nil {
		return classifyOutputOpenError(err)
	}
	err = writeGitHubOutput(f, text)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func writeGitHubOutput(f *os.File, text string) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return &prcontext.InputError{Msg: "GITHUB_OUTPUT must be a regular file"}
	}
	if info.Size() > 0 {
		var last [1]byte
		if _, err := f.ReadAt(last[:], info.Size()-1); err != nil {
			return err
		}
		if last[0] != '\n' {
			if _, err := io.WriteString(f, "\n"); err != nil {
				return err
			}
		}
	}
	_, err = io.WriteString(f, text)
	return err
}

func fullSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// prContextFail maps err onto exit 3 or 4. config is true when err is
// already known to be bad input rather than an I/O failure.
func prContextFail(stderr io.Writer, err error, config bool) int {
	var input *prcontext.InputError
	code := exitcode.Internal
	if config || errors.As(err, &input) {
		code = exitcode.Config
	}
	if errors.Is(err, gitrun.ErrNotInstalled) {
		code = exitcode.Internal
	}
	writeString(stderr, "tripcord pr-context: "+redactHomeFromError(err)+"\n")
	return int(code)
}

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/gitrun"
	"github.com/vgmartinez/tripcord/internal/prcontext"
)

const prContextUsage = `tripcord pr-context [flags]

pr-context reads a GitHub pull_request event and the commits in base..head
and reports whether the pull request looks agent-authored. It exits 0
whether or not an agent is detected.

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
	if eventPath != "" {
		ev, err = readPullRequestEvent(eventPath)
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
	commits, warnings, err := prcontext.ReadCommits(context.Background(), repo, ev.Base, ev.Head)
	if err != nil {
		return prContextFail(stderr, err, false)
	}
	result := prcontext.Detect(prcontext.Input{
		PRLogin:      ev.Login,
		PRAuthorType: ev.AuthorType,
		Branch:       branch,
		BranchSource: branchSource,
		Commits:      commits,
		Warnings:     warnings,
	})
	rendered, err := renderPrContext(opts.format, result)
	if err != nil {
		return prContextFail(stderr, err, false)
	}
	if writeString(stdout, rendered) != int(exitcode.OK) {
		return int(exitcode.Internal)
	}
	if outputPath != "" {
		if err := appendGitHubOutput(outputPath, result); err != nil {
			return prContextFail(stderr, err, false)
		}
	}
	return int(exitcode.OK)
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

func renderPrContext(format string, result prcontext.Result) (string, error) {
	switch format {
	case "text", "gha":
		return prcontext.FormatText(result), nil
	case "json":
		raw, err := prcontext.FormatJSON(result)
		if err != nil {
			return "", err
		}
		return string(raw), nil
	default:
		panic("prcontext: unhandled format " + format)
	}
}

func readPullRequestEvent(path string) (prcontext.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return prcontext.Event{}, &prcontext.InputError{Msg: fmt.Sprintf("event file: %v", err)}
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return prcontext.Event{}, err
	}
	if info.IsDir() {
		_ = f.Close()
		return prcontext.Event{}, &prcontext.InputError{Msg: "event file is a directory"}
	}
	if info.Size() > maxEventBytes {
		_ = f.Close()
		return prcontext.Event{}, &prcontext.InputError{Msg: "event file is too large"}
	}
	data, err := io.ReadAll(io.LimitReader(f, maxEventBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return prcontext.Event{}, err
	}
	if len(data) > maxEventBytes {
		return prcontext.Event{}, &prcontext.InputError{Msg: "event file is too large"}
	}
	return prcontext.ParseEvent(data)
}

func appendGitHubOutput(path string, result prcontext.Result) error {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return err
	case info.Mode()&os.ModeSymlink != 0:
		return &prcontext.InputError{Msg: "GITHUB_OUTPUT must not be a symlink"}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = io.WriteString(f, prcontext.FormatOutput(result))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
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

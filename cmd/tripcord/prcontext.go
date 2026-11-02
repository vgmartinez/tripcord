package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"encoding/json"

	"github.com/vgmartinez/tripcord/internal/cfg014"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/gitrun"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/policy"
	"github.com/vgmartinez/tripcord/internal/prcontext"
)

const prContextUsage = `tripcord pr-context [flags]

pr-context reads a GitHub pull_request event and the commits in base..head
and reports whether the pull request looks agent-authored. It exits 0
whether or not an agent is detected. When that author is an agent and
the diff changes a file an adapter classifies, TC-CFG-014 exits 1 if no
human approved the pull request and the base revision's policy fails
the finding. The default is enforce, fail-on high. A mode or fail-on
on that base revision still applies; one added by the pull request
does not. The command exits 3 when the reviews, the diff, or the
policy cannot be read.

--reviews-file is a JSON array of review objects, the shape of
GET /pulls/{n}/reviews concatenated across pages. It is the complete
review set and replaces any reviews in the event. pr-context does not
call the GitHub API. Without the flag, a reviews array on the event is
the complete set, and a missing array is incomplete.

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
	if opts.reviewsFile != "" {
		reviews, err = readReviewsFile(opts.reviewsFile)
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
	// Policy is loaded after the login and branch verdict is written, so
	// a bad policy file does not drop that verdict. The repository
	// layers come from the base revision. The checkout is the pull
	// request's own merge, and policy.local.yaml is never read. A
	// missing base, or a directory that is not a git repository, uses
	// the surface defaults. The managed org policy is still applied,
	// and its locks still win.
	effective, err := loadPrContextPolicy(repo, ev.Base)
	if err != nil {
		return prContextFail(stderr, err, false)
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
	// TC-CFG-014 runs when pr-context classified an agent, and also when
	// any bot identity is present. The second check does not change
	// is_agent or agents. A fatal commit read still reports that verdict
	// and keeps its own exit code.
	var outcome cfg014.Outcome
	var diffErr error
	inScope := result.Agent || prcontext.BotInvolved(prcontext.Input{
		PRLogin:      ev.Login,
		PRAuthorType: ev.AuthorType,
		Commits:      commits,
	})
	if readErr == nil && inScope {
		diff, err := prcontext.ChangedPaths(context.Background(), repo, ev.Base, ev.Head)
		if err != nil {
			diffErr = err
		} else {
			extra, remaps, symlinkReason, linkErr := cfg014Links(repo, ev.Base, ev.Head, diff)
			if linkErr != nil {
				diffErr = linkErr
			} else {
				outcome = cfg014.Evaluate(cfg014.Input{
					Agent:         true,
					Author:        ev.Login,
					Head:          ev.Head,
					Paths:         diff.Paths,
					PathsKnown:    !diff.Missing,
					Truncated:     diff.Truncated,
					Reviews:       reviews,
					Classifiers:   cfg014.DefaultClassifiers(),
					Extra:         extra,
					Remaps:        remaps,
					SymlinkReason: symlinkReason,
				})
			}
		}
	}
	failMatch := false
	if outcome.Status == cfg014.StatusMatch {
		if outcome.Finding == nil {
			return prContextFail(stderr, errors.New("TC-CFG-014 match has no finding"), false)
		}
		outcome.Finding.Severity = effective.Severity(cfg014.RuleID, outcome.Finding.Severity)
		outcome.Finding.Decision = decision(effective.Mode)
		if err := outcome.Finding.Validate(); err != nil {
			return prContextFail(stderr, err, false)
		}
		var ferr error
		failMatch, ferr = effective.Fails(outcome.Finding.Severity)
		if ferr != nil {
			return prContextFail(stderr, ferr, false)
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
		if failMatch {
			return int(exitcode.Findings)
		}
		return int(exitcode.OK)
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
	event       string
	reviewsFile string
	base        string
	head        string
	repo        string
	format      string
}

func parsePrContextFlags(args []string, stdout io.Writer) (prContextOptions, error) {
	var opts prContextOptions
	flags := flag.NewFlagSet("pr-context", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
	flags.StringVar(&opts.event, "event", "", "GitHub pull_request event JSON (default: $GITHUB_EVENT_PATH)")
	flags.StringVar(&opts.reviewsFile, "reviews-file", "", "JSON array of GitHub reviews; the complete review set")
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
			b.WriteString("- " + redactControlPath(path) + "\n")
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

// redactControlPath keeps a filename from injecting a workflow command
// into text or gha output. The diff reader already rejects these paths;
// this is the backstop for a path that reached formatting anyway.
func redactControlPath(path string) string {
	for i := 0; i < len(path); i++ {
		if path[i] < 0x20 || path[i] == 0x7f {
			return "[path omitted]"
		}
	}
	return path
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

// readReviewsFile reads a JSON array of GitHub review objects. The file
// must be a regular file no larger than maxEventBytes. A directory,
// symlink, or other non-regular file is refused before it is opened, so
// a FIFO cannot hang the read. Invalid JSON, a non-array payload, and an
// oversized file are input errors (exit 3).
func readReviewsFile(path string) (prcontext.ReviewSet, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return prcontext.ReviewSet{}, &prcontext.InputError{Msg: fmt.Sprintf("reviews file: %v", err)}
	}
	if !info.Mode().IsRegular() {
		return prcontext.ReviewSet{}, &prcontext.InputError{Msg: "reviews file must be a regular file"}
	}
	if info.Size() > maxEventBytes {
		return prcontext.ReviewSet{}, &prcontext.InputError{Msg: "reviews file is too large"}
	}
	f, err := os.Open(path)
	if err != nil {
		return prcontext.ReviewSet{}, &prcontext.InputError{Msg: fmt.Sprintf("reviews file: %v", err)}
	}
	info, err = f.Stat()
	if err != nil {
		_ = f.Close()
		return prcontext.ReviewSet{}, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return prcontext.ReviewSet{}, &prcontext.InputError{Msg: "reviews file must be a regular file"}
	}
	if info.Size() > maxEventBytes {
		_ = f.Close()
		return prcontext.ReviewSet{}, &prcontext.InputError{Msg: "reviews file is too large"}
	}
	data, err := io.ReadAll(io.LimitReader(f, maxEventBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return prcontext.ReviewSet{}, err
	}
	if len(data) > maxEventBytes {
		return prcontext.ReviewSet{}, &prcontext.InputError{Msg: "reviews file is too large"}
	}
	return prcontext.ParseReviewArray(data)
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
// cfg014Links resolves symlinks in base and head and records symlink or
// gitlink diff entries at covered directories. A symlink is resolved
// when its path is a covered directory or an adapter classifies that
// path. A listing that is too large, or a target that cannot be mapped
// into the repository, becomes an incomplete reason rather than a pass.
func cfg014Links(repo, base, head string, diff prcontext.Diff) ([]cfg014.ExtraHit, []cfg014.Remap, string, error) {
	if diff.Missing {
		return nil, nil, "", nil
	}
	covered := cfg014.CoveredDirs()
	baseLinks, baseTrunc, err := prcontext.TreeSymlinks(context.Background(), repo, base, covered, cfg014Classifies)
	if err != nil {
		return nil, nil, "", err
	}
	headLinks, headTrunc, err := prcontext.TreeSymlinks(context.Background(), repo, head, covered, cfg014Classifies)
	if err != nil {
		return nil, nil, "", err
	}
	reason := ""
	if baseTrunc || headTrunc {
		reason = "could not resolve symlinks: the tree listing was too large"
	}
	links := append(baseLinks, headLinks...)
	extra, remaps, linkReason := cfg014.SymlinkPlan(diff.Changes, links)
	if reason == "" {
		reason = linkReason
	}
	return extra, remaps, reason, nil
}

// cfg014Classifies reports whether any installed adapter classifies rel
// from the path alone. It is the predicate TreeSymlinks uses next to
// the covered-directory names.
func cfg014Classifies(rel string) bool {
	for _, classifier := range cfg014.DefaultClassifiers() {
		if classifier.Classifies(rel) {
			return true
		}
	}
	return false
}

func loadPrContextPolicy(repo, base string) (*policy.Effective, error) {
	return loadPrContextPolicyFrom(context.Background(), repo, base, "")
}

// loadPrContextPolicyFrom loads the pr-context policy. managed is the
// org file; empty uses the platform managed path. Repository layers are
// copied out of base with git show. The checkout is not a policy source.
func loadPrContextPolicyFrom(ctx context.Context, repo, base, managed string) (*policy.Effective, error) {
	env, catalog, err := loadRules(scanLimits())
	if err != nil {
		return nil, err
	}
	root, err := os.MkdirTemp("", "tripcord-base-policy-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(root) }()
	if err := materializeBasePolicy(ctx, repo, base, root); err != nil {
		return nil, err
	}
	opts := policy.Options{
		RepoRoot: root,
		Surface:  policy.SurfacePRContext,
		Env:      env,
		Catalog:  catalog,
	}
	if managed != "" {
		opts.ManagedPolicy = managed
	}
	return policy.Load(opts)
}

// errBaseUnavailable means base cannot supply a repository policy: the
// directory is not a git repository, or the revision is not in this
// clone. The repository policy layer is then absent and the surface
// defaults apply. A missing policy blob is os.ErrNotExist and means the
// same thing for the root file. Other git failures stay errors.
var errBaseUnavailable = errors.New("base revision is not available")

// materializeBasePolicy writes <base>:.tripcord/policy.yaml and the
// relative files it extends into dest, using paths relative to the
// repository root. A missing file, a missing base, or a directory that
// is not a git repository leaves dest empty. policy.local.yaml is never
// written. Absolute extends are left for policy.Load, which reads them
// from the machine rather than the checkout.
func materializeBasePolicy(ctx context.Context, repo, base, dest string) error {
	seen := map[string]bool{}
	var walk func(rel string, required bool, depth int) error
	walk = func(rel string, required bool, depth int) error {
		if depth > policy.MaxExtendsDepth {
			return &policy.Error{Source: rel, Err: fmt.Errorf("extends is nested deeper than %d", policy.MaxExtendsDepth)}
		}
		if seen[rel] {
			return nil
		}
		if rel == policy.LocalFile {
			return &policy.Error{Source: rel, Err: errors.New("pr-context does not load .tripcord/policy.local.yaml")}
		}
		data, err := gitShowBlob(ctx, repo, base, rel)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, errBaseUnavailable) {
			if !required {
				return nil
			}
			return &policy.Error{Source: rel, Err: fmt.Errorf("%s does not exist in base", rel)}
		}
		if err != nil {
			return err
		}
		if len(data) > policy.MaxFileBytes {
			return &policy.Error{Source: rel, Err: fmt.Errorf("policy is %d bytes, limit %d", len(data), policy.MaxFileBytes)}
		}
		parsed, err := policy.Parse(data)
		if err != nil {
			return &policy.Error{Source: rel, Err: err}
		}
		seen[rel] = true
		if err := writeRepoFile(dest, rel, data); err != nil {
			return err
		}
		for _, entry := range parsed.Extends {
			kind, _, err := policy.ParseExtends(entry)
			if err != nil {
				return &policy.Error{Source: rel, Err: err}
			}
			if kind != policy.ExtendsPath || strings.HasPrefix(entry, "/") {
				continue
			}
			next, err := repoRelExtend(rel, entry)
			if err != nil {
				return &policy.Error{Source: rel, Err: err}
			}
			if err := walk(next, true, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(policy.RepoFile, false, 0)
}

func repoRelExtend(from, entry string) (string, error) {
	if strings.ContainsAny(entry, "\x00\r\n") {
		return "", fmt.Errorf("extends %s contains a control character", entry)
	}
	joined := path.Clean(path.Join(path.Dir(from), filepath.ToSlash(entry)))
	if !validPolicyRel(joined) {
		return "", fmt.Errorf("extends %s escapes the repository", entry)
	}
	if joined == policy.LocalFile {
		return "", errors.New("extends is not allowed to .tripcord/policy.local.yaml")
	}
	return joined, nil
}

func validPolicyRel(rel string) bool {
	if rel == "" || strings.Contains(rel, ":") || strings.Contains(rel, "\\") || strings.ContainsAny(rel, "\x00\r\n") {
		return false
	}
	if path.IsAbs(rel) || rel != path.Clean(rel) {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, "../")
}

func writeRepoFile(dest, rel string, data []byte) error {
	if !validPolicyRel(rel) {
		return &policy.Error{Source: rel, Err: errors.New("policy path is not inside the repository")}
	}
	full := filepath.Join(dest, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return err
	}
	return os.WriteFile(full, data, 0o600)
}

func gitShowBlob(ctx context.Context, repo, rev, rel string) ([]byte, error) {
	if err := prcontext.ValidateRev("base", rev); err != nil {
		return nil, err
	}
	if !validPolicyRel(rel) {
		return nil, &policy.Error{Source: rel, Err: errors.New("policy path is not inside the repository")}
	}
	spec := rev + ":" + rel
	out, err := gitrun.Run(ctx, repo, "--no-pager", "--no-optional-locks", "show", "--no-textconv", "--end-of-options", spec)
	if err == nil {
		return out, nil
	}
	var exitErr *gitrun.ExitError
	if !errors.As(err, &exitErr) {
		return nil, err
	}
	msg := strings.ToLower(exitErr.Stderr)
	switch {
	case strings.Contains(msg, "does not exist in"),
		strings.Contains(msg, "exists on disk, but not"):
		return nil, os.ErrNotExist
	case strings.Contains(msg, "invalid object name"),
		strings.Contains(msg, "bad revision"),
		strings.Contains(msg, "unknown revision"),
		strings.Contains(msg, "ambiguous argument"),
		strings.Contains(msg, "needed a single revision"),
		strings.Contains(msg, "not a git repository"):
		return nil, errBaseUnavailable
	default:
		return nil, err
	}
}

func prContextFail(stderr io.Writer, err error, config bool) int {
	var input *prcontext.InputError
	var pol *policy.Error
	code := exitcode.Internal
	if config || errors.As(err, &input) {
		code = exitcode.Config
	}
	if errors.As(err, &pol) {
		code = pol.ExitCode()
	}
	if errors.Is(err, gitrun.ErrNotInstalled) {
		code = exitcode.Internal
	}
	writeString(stderr, "tripcord pr-context: "+redactHomeFromError(err)+"\n")
	return int(code)
}

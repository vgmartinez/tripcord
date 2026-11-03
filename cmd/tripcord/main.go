// Command tripcord is the Tripcord command-line interface.
//
// The root command uses the standard library only, so a later hook mode
// can cold-start quickly.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/claude"
	"github.com/vgmartinez/tripcord/internal/adapters/codex"
	"github.com/vgmartinez/tripcord/internal/adapters/copilot"
	"github.com/vgmartinez/tripcord/internal/adapters/cursor"
	"github.com/vgmartinez/tripcord/internal/adapters/devcontainer"
	"github.com/vgmartinez/tripcord/internal/adapters/devin"
	"github.com/vgmartinez/tripcord/internal/adapters/gemini"
	"github.com/vgmartinez/tripcord/internal/adapters/generic"
	"github.com/vgmartinez/tripcord/internal/adapters/opencode"
	"github.com/vgmartinez/tripcord/internal/adapters/windsurf"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/fpkey"
	"github.com/vgmartinez/tripcord/internal/indexfiles"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
	"github.com/vgmartinez/tripcord/internal/pathx"
	"github.com/vgmartinez/tripcord/internal/policy"
	"github.com/vgmartinez/tripcord/internal/preopen"
	"github.com/vgmartinez/tripcord/internal/rules"
	"github.com/vgmartinez/tripcord/internal/scriptcheck"
)

// version is the build version. Override it at link time:
//
//	go build -ldflags "-X main.version=vX.Y.Z"
var version = "dev"

const usage = `tripcord is a local coding-agent security scanner (pre-release).

Usage:
  tripcord help
  tripcord version
  tripcord scan [PATH] [flags]
  tripcord pr-context [flags]
  tripcord preopen <git-url|path> [flags]

scan performs static configuration scanning only. A PATH inside a Git
repository scans that whole repository from its git root. Monorepo scoping
is tracked in https://github.com/vgmartinez/tripcord/issues/59.
--staged scans the Git index in a private temporary tree. The change set
is the union of any paths given on the command line and the paths that
differ between HEAD and the index (added, modified, deleted, type-changed,
and mode-changed). With nothing staged and no paths, nothing is reported.
When PRE_COMMIT_FROM_REF and PRE_COMMIT_TO_REF are set, that range is
included too and the scan reads the working tree instead of the index.
--scope selects repository
(the default), user, managed, or all. The default does not read the home
directory or system settings.
pr-context reports whether a pull request looks agent-authored. It reads a
GitHub pull_request event and the commits in base..head, and exits 0
whether or not an agent is detected.
preopen clones a repository into a temporary directory without running its
hooks, filters, LFS, or submodules, scans it like scan, and removes it. It
takes the scan flags except --since and --scope other than repo, and ignores
the repository's own .tripcord policy.
--secrets (v1) and --all (v1) are not available.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return writeString(stdout, usage)
	}
	switch args[0] {
	case "help", "-h", "--help":
		return writeString(stdout, usage)
	case "version", "--version":
		return writeString(stdout, version+"\n")
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "pr-context":
		return runPrContext(args[1:], stdout, stderr)
	case "preopen":
		return runPreopen(args[1:], stdout, stderr)
	default:
		msg := fmt.Sprintf("tripcord: unknown command %q\n\n%s", args[0], usage)
		writeString(stderr, msg)
		return int(exitcode.Config)
	}
}

type scanOptions struct {
	config      bool
	secrets     bool
	all         bool
	harnesses   string
	scope       string
	format      string
	output      string
	since       string
	failOn      string
	policy      string
	orgPolicy   string
	path        string
	staged      bool
	stagedFiles map[string]bool
}

func runScan(args []string, stdout, stderr io.Writer) int {
	opts, err := parseScanFlags(args, stdout)
	if errors.Is(err, errHelp) {
		return int(exitcode.OK)
	}
	if errors.Is(err, errHelpWrite) {
		return int(exitcode.Internal)
	}
	target := scanTarget{prog: "tripcord scan"}
	if err != nil {
		code := target.configError(stderr, err)
		if opts.staged {
			writeString(stderr, "tripcord scan: staged scan blocked the commit; bypass only with git commit --no-verify\n")
		}
		return code
	}
	if opts.secrets || opts.all {
		return target.configError(stderr, errors.New("secret scanning lands in v1; v0 supports --config only"))
	}
	root, err := scanRoot(opts.path)
	if err != nil {
		code := target.configError(stderr, err)
		if opts.staged {
			writeString(stderr, "tripcord scan: staged scan blocked the commit; bypass only with git commit --no-verify\n")
		}
		return code
	}
	if opts.staged {
		if !repoRoot(root) {
			code := target.configError(stderr, errors.New("--staged requires a Git repository"))
			writeString(stderr, "tripcord scan: staged scan blocked the commit; bypass only with git commit --no-verify\n")
			return code
		}
		if opts.scope != "repo" || opts.since != "" || opts.policy != "" || opts.orgPolicy != "" {
			code := target.configError(stderr, errors.New("--staged requires repo scope and index policy, and does not support --since, --policy, or --org-policy"))
			writeString(stderr, "tripcord scan: staged scan blocked the commit; bypass only with git commit --no-verify\n")
			return code
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		defer stop()
		// GIT_INDEX_FILE, when set, is the lock or temporary index git
		// built for the commit currently in this hook (plain, -a, a
		// pathspec, --only, or --include): see gitrun.IndexEnv. It is
		// read once, here, where --staged is already known to be a git
		// hook invocation, and passed explicitly to every call that
		// needs the proposed commit's content, rather than carried by
		// gitrun.Env for every git invocation tripcord makes.
		indexFile := os.Getenv("GIT_INDEX_FILE")
		// The change set is the union of paths the caller passed (a
		// pre-commit batch, or an explicit manual invocation) and every
		// path that differs between HEAD and this index. A batch that
		// does not name a staged symlink or deletion still sees it,
		// because diff-index does; every batch unions the same
		// diff-index set, so the same finding can be reported from more
		// than one batch.
		changed, err := preopen.StagedChangeSet(ctx, root, indexFile)
		if err != nil {
			code := target.configError(stderr, fmt.Errorf("--staged: %w", err))
			writeString(stderr, "tripcord scan: staged scan blocked the commit; bypass only with git commit --no-verify\n")
			return code
		}
		for path := range opts.stagedFiles {
			changed[path] = true
		}
		// pre-commit run --from-ref/--to-ref, including pre-commit.ci,
		// sets both. Nothing is staged in that mode, so diff-index is
		// empty, and pre-commit's filename filter drops deletions. The
		// range diff puts them back. Content is the working tree at TO,
		// which is what pre-commit checked out, not the index.
		fromRef := os.Getenv("PRE_COMMIT_FROM_REF")
		toRef := os.Getenv("PRE_COMMIT_TO_REF")
		if fromRef != "" && toRef != "" {
			ranged, err := preopen.RefRangeChangeSet(ctx, root, fromRef, toRef)
			if err != nil {
				code := target.configError(stderr, fmt.Errorf("--staged: %w", err))
				writeString(stderr, "tripcord scan: staged scan blocked the commit; bypass only with git commit --no-verify\n")
				return code
			}
			for path := range ranged {
				changed[path] = true
			}
			opts.stagedFiles = changed
			sources, notes, err := indexfiles.WorktreeSources(root)
			if err != nil {
				code := target.configError(stderr, fmt.Errorf("--staged: %w", err))
				writeString(stderr, "tripcord scan: staged scan blocked the commit; bypass only with git commit --no-verify\n")
				return code
			}
			target.root, target.policyRoot = root, root
			target.stagedNotes = notes
			target.stagedSources = sources
			code := scanTree(ctx, target, opts, stdout, stderr)
			if ctx.Err() != nil {
				writeString(stderr, "tripcord scan: staged scan blocked the commit; bypass only with git commit --no-verify\n")
				return int(exitcode.Config)
			}
			if code == int(exitcode.Config) || code == int(exitcode.Internal) {
				writeString(stderr, "tripcord scan: staged scan blocked the commit; bypass only with git commit --no-verify\n")
			}
			return code
		}
		opts.stagedFiles = changed
		ws, notes, sources, err := indexfiles.Materialize(ctx, root, indexFile)
		if err != nil {
			code := target.configError(stderr, fmt.Errorf("--staged: %w", err))
			writeString(stderr, "tripcord scan: staged scan blocked the commit; bypass only with git commit --no-verify\n")
			return code
		}
		defer func() { _ = ws.Close() }()
		target.root, target.policyRoot = ws.Tree(), ws.Tree()
		target.stagedNotes = notes
		target.stagedSources = sources
		target.redactRoot = ws.Tree()
		target.stageMore = func(items []model.ConfigItem) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return indexfiles.AddReferences(ctx, ws, scriptcheck.ReferencedPaths(items))
		}
		code := scanTree(ctx, target, opts, stdout, stderr)
		if ctx.Err() != nil {
			_ = ws.Close()
			writeString(stderr, "tripcord scan: staged scan blocked the commit; bypass only with git commit --no-verify\n")
			return int(exitcode.Config)
		}
		if code == int(exitcode.Config) || code == int(exitcode.Internal) {
			writeString(stderr, "tripcord scan: staged scan blocked the commit; bypass only with git commit --no-verify\n")
		}
		return code
	}
	target.root, target.policyRoot = root, root
	return scanTree(context.Background(), target, opts, stdout, stderr)
}

// scanTarget is the tree scanTree reads. prog prefixes every message.
// policyRoot holds the repository policy files (.tripcord/policy.yaml
// and policy.local.yaml); it is root for scan, and a directory with no
// policy for preopen, which must not let a cloned repository set its
// own policy or exceptions.
type scanTarget struct {
	prog        string
	root        string
	policyRoot  string
	stagedNotes []adapters.Diagnostic
	stageMore   func([]model.ConfigItem) error
	// stagedSources is indexfiles.Plan.Sources: it is applied to every
	// discovered repository item's SourcePaths once discovery and hook
	// script resolution have run, so the --staged filter can match a
	// finding's symlink chain or plugin manifest group, not only its
	// own Path. It is nil for a normal, non-staged scan.
	stagedSources map[string][]string
	// redactRoot, for a --staged scan, is the absolute path of the
	// private staged tree (ws.Tree()): an internal error that names it,
	// for example one filepath.EvalSymlinks on root returns, is
	// rewritten to a repo-relative "." so a diagnostic does not name a
	// temporary directory the pre-commit caller never asked about. It
	// is empty for a normal scan, where root is the repository itself.
	redactRoot string
}

func (t scanTarget) configError(stderr io.Writer, err error) int {
	writeString(stderr, t.prog+": "+t.redactError(err)+"\n")
	return int(exitcode.Config)
}

func (t scanTarget) internalError(stderr io.Writer, err error) int {
	writeString(stderr, t.prog+": "+t.redactError(err)+"\n")
	return int(exitcode.Internal)
}

// redactError renders err the way configError and internalError do: the
// user's home directory folded to "~", and, for a --staged scan, the
// private staged tree's absolute path folded to ".".
func (t scanTarget) redactError(err error) string {
	msg := redactHomeFromError(err)
	if t.redactRoot != "" {
		msg = strings.ReplaceAll(msg, t.redactRoot, ".")
	}
	return msg
}

// scanTree scans t.root with opts, writes the findings, and returns the
// scan exit code.
func scanTree(ctx context.Context, t scanTarget, opts scanOptions, stdout, stderr io.Writer) int {
	root := t.root
	env, catalog, err := loadRules(scanLimits())
	if err != nil {
		return t.internalError(stderr, err)
	}
	policyOpts := policy.Options{RepoRoot: t.policyRoot, RepoPolicy: opts.policy, Surface: policy.SurfaceScan, Env: env, Catalog: catalog}
	if opts.orgPolicy != "" {
		policyOpts.OrgPolicy = []string{opts.orgPolicy}
	}
	effective, err := policy.Load(policyOpts)
	if err != nil {
		return t.configError(stderr, err)
	}
	if opts.failOn != "" {
		sev, err := model.ParseSeverity(opts.failOn)
		if err != nil {
			return t.configError(stderr, fmt.Errorf("--fail-on: %w", err))
		}
		if err := effective.ApplyFailOn(sev); err != nil {
			return t.configError(stderr, err)
		}
	}
	requested, err := parseHarnesses(opts.harnesses)
	if err != nil {
		return t.configError(stderr, err)
	}
	repoScope, userScope, managedScope, err := parseScope(opts.scope)
	if err != nil {
		return t.configError(stderr, err)
	}
	key, keyNote, err := loadFingerprintKey()
	if err != nil {
		return t.configError(stderr, err)
	}
	registry, err := adapters.NewRegistry(
		claude.New(claude.Options{SkipRepo: !repoScope, IncludeUser: userScope, IncludeManaged: managedScope, FingerprintKey: key}),
		codex.New(codex.Options{SkipRepo: !repoScope, IncludeUser: userScope, IncludeManaged: managedScope, FingerprintKey: key}),
		copilot.New(copilot.Options{SkipRepo: !repoScope, IncludeUser: userScope, IncludeManaged: managedScope, FingerprintKey: key}),
		cursor.New(cursor.Options{SkipRepo: !repoScope, IncludeUser: userScope, IncludeManaged: managedScope, FingerprintKey: key}),
		gemini.New(gemini.Options{SkipRepo: !repoScope, IncludeUser: userScope, IncludeManaged: managedScope, FingerprintKey: key}),
		opencode.New(opencode.Options{SkipRepo: !repoScope, IncludeUser: userScope, IncludeManaged: managedScope, FingerprintKey: key}),
		windsurf.New(windsurf.Options{SkipRepo: !repoScope, IncludeUser: userScope, IncludeManaged: managedScope, FingerprintKey: key}),
		devin.New(devin.Options{SkipRepo: !repoScope, FingerprintKey: key}),
		devcontainer.New(devcontainer.Options{SkipRepo: !repoScope, FingerprintKey: key}),
		generic.New(generic.Options{SkipRepo: !repoScope, IncludeUser: userScope, FingerprintKey: key}),
	)
	if err != nil {
		return t.internalError(stderr, err)
	}
	selected, err := registry.Select(root, requested)
	if err != nil {
		return t.configError(stderr, err)
	}
	// The editor opens .vscode/tasks.json whichever agent is in use, so
	// a scan limited by --harness still reads it once. Only that file:
	// the harness may not load the shared skills and AGENTS.md.
	if len(requested) > 0 && repoScope && !slices.ContainsFunc(selected, func(a adapters.Adapter) bool { return a.Harness() == model.SurfaceGeneric }) {
		selected = append(selected, generic.New(generic.Options{TasksOnly: true, FingerprintKey: key}))
	}
	var items []model.ConfigItem
	diagnostics := append([]adapters.Diagnostic{}, t.stagedNotes...)
	if keyNote != "" && writeString(stderr, t.prog+": "+keyNote+"\n") != int(exitcode.OK) {
		return int(exitcode.Internal)
	}
	for _, owner := range registry.ImpliedOwners(requested) {
		diagnostics = append(diagnostics, adapters.Diagnostic{
			Harness:       owner,
			Message:       "also scanned: a requested harness loads files this adapter reports",
			Informational: true,
		})
	}
	for _, adapter := range selected {
		if ctx.Err() != nil {
			return int(exitcode.Config)
		}
		discovered, err := adapter.Discover(ctx, root)
		if ctx.Err() != nil {
			return int(exitcode.Config)
		}
		var partial *adapters.DiagnosticError
		switch {
		case errors.As(err, &partial):
			diagnostics = append(diagnostics, partial.Diagnostics...)
		case err != nil:
			return t.internalError(stderr, fmt.Errorf("%s discovery: %w", adapter.Harness(), err))
		}
		items = append(items, discovered...)
	}
	if t.stageMore != nil {
		if err := t.stageMore(items); err != nil {
			if ctx.Err() != nil {
				return int(exitcode.Config)
			}
			return t.internalError(stderr, fmt.Errorf("staged references: %w", err))
		}
	}
	if ctx.Err() != nil {
		return int(exitcode.Config)
	}
	if repoScope {
		if err := scriptcheck.Annotate(root, items); err != nil {
			return t.internalError(stderr, fmt.Errorf("hook scripts: %w", err))
		}
	}
	if opts.stagedFiles != nil {
		applyStagedSources(items, t.stagedSources)
	}
	diagnostics = adapters.DedupeEscapingSymlinkDiagnostics(diagnostics)
	if opts.since != "" {
		changed, err := changedFiles(root, opts.since)
		if err != nil {
			var invoke *gitInvokeError
			if errors.As(err, &invoke) && invoke.missing {
				return t.internalError(stderr, err)
			}
			return t.configError(stderr, err)
		}
		items = slices.DeleteFunc(items, func(item model.ConfigItem) bool {
			return item.Scope != model.ScopeRepo || !changed[item.Path]
		})
		diagnostics = slices.DeleteFunc(diagnostics, func(d adapters.Diagnostic) bool {
			return d.Scope == model.ScopeRepo && d.Path != "" && !changed[d.Path]
		})
	}
	engine := rules.NewEngine(env, catalog.Rules(), rules.WithFilter(effective.RuleFilter()))
	if ctx.Err() != nil {
		return int(exitcode.Config)
	}
	result := engine.ScanConfig(ctx, items)
	if ctx.Err() != nil {
		return int(exitcode.Config)
	}
	diagnostics = append(diagnostics, evalDiagnostics(result.Errors)...)
	diagnostics = append(diagnostics, opaqueDiagnostics(result.Notices)...)
	findings := make([]model.Finding, 0, len(result.Matches))
	for _, match := range result.Matches {
		if opts.stagedFiles != nil && !stagedSourceMatches(match.Item, opts.stagedFiles) {
			continue
		}
		if _, status := effective.Exception(match.Rule.ID, match.Item.Path, match.Item.SHA256, now()); status == policy.ExceptionActive {
			continue
		}
		base := match.Severity
		if base == "" {
			base = match.Rule.Severity
		}
		finding, err := match.Finding(effective.Severity(match.Rule.ID, base), decision(effective.Mode))
		if err != nil {
			return t.internalError(stderr, err)
		}
		findings = append(findings, finding)
	}
	handle, err := output.SelectSink(opts.format, opts.output, stdout, output.Options{
		Redactor:    output.DefaultRedactor,
		RepoRoot:    root,
		ToolVersion: version,
		Rules:       sarifRuleText(catalog),
	})
	if err != nil {
		var pathErr *output.PathError
		if errors.As(err, &pathErr) {
			return t.configError(stderr, err)
		}
		return t.internalError(stderr, err)
	}
	blocking, notes := partitionDiagnostics(diagnostics)
	if err := handle.SetDiagnostics(outputDiagnostics(append(append([]adapters.Diagnostic{}, blocking...), notes...))); err != nil {
		_ = handle.Close()
		return t.internalError(stderr, err)
	}
	for _, finding := range findings {
		if err := handle.Write(finding); err != nil {
			_ = handle.Close()
			return t.internalError(stderr, err)
		}
	}
	if err := handle.Flush(); err != nil {
		_ = handle.Close()
		return t.internalError(stderr, err)
	}
	if err := handle.Close(); err != nil {
		return t.internalError(stderr, err)
	}
	// Exit 3 wins over exit 1: an incomplete scan is not a clean result.
	// Informational diagnostics are printed and do not change the exit code.
	for _, d := range append(append([]adapters.Diagnostic{}, blocking...), notes...) {
		if writeString(stderr, t.prog+": "+output.TerminalLine(d.String())+"\n") != int(exitcode.OK) {
			return int(exitcode.Internal)
		}
	}
	if len(blocking) > 0 {
		if writeString(stderr, t.prog+": configuration could not be fully read or evaluated; the scan is incomplete\n") != int(exitcode.OK) {
			return int(exitcode.Internal)
		}
		return int(exitcode.Config)
	}
	for _, finding := range findings {
		fails, err := effective.Fails(finding.Severity)
		if err != nil {
			return t.internalError(stderr, err)
		}
		if fails {
			return int(exitcode.Findings)
		}
	}
	return int(exitcode.OK)
}

var (
	errHelp      = errors.New("help")
	errHelpWrite = errors.New("write scan help")
)

// flagCommand is a command that takes the scan flags: scan, or preopen.
type flagCommand struct {
	name    string
	operand string
}

var (
	scanCommand    = flagCommand{name: "scan", operand: "[PATH]"}
	preopenCommand = flagCommand{name: "preopen", operand: "<git-url|path>"}
)

func parseScanFlags(args []string, stdout io.Writer) (scanOptions, error) {
	return parseCommandFlags(scanCommand, args, stdout)
}

func parseCommandFlags(cmd flagCommand, args []string, stdout io.Writer) (scanOptions, error) {
	normalized, err := normalizeScanArgs(args)
	if err != nil {
		return scanOptions{}, err
	}
	var opts scanOptions
	flags := flag.NewFlagSet(cmd.name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
	flags.BoolVar(&opts.config, "config", false, "scan executable configuration (default)")
	flags.BoolVar(&opts.secrets, "secrets", false, "(v1) not available")
	flags.BoolVar(&opts.all, "all", false, "(v1) not available")
	flags.StringVar(&opts.harnesses, "harness", "", "comma-separated harnesses; default autodetect")
	flags.StringVar(&opts.scope, "scope", "repo", "repo, user, managed, or all")
	flags.StringVar(&opts.format, "format", "text", "text, json, sarif, md, or gha")
	flags.StringVar(&opts.output, "output", "-", "output path or - for stdout")
	flags.StringVar(&opts.since, "since", "", "files changed between the ref and HEAD; requires git")
	flags.StringVar(&opts.failOn, "fail-on", "", "low, medium, high, or critical")
	flags.StringVar(&opts.policy, "policy", "", "policy file")
	flags.StringVar(&opts.orgPolicy, "org-policy", "", "organization policy file")
	flags.BoolVar(&opts.staged, "staged", false, "scan Git's staged index; paths are unioned with the staged change set")
	if err := flags.Parse(normalized); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			var buf bytes.Buffer
			if _, werr := fmt.Fprintf(&buf, "tripcord %s %s\n\n", cmd.name, cmd.operand); werr != nil {
				return scanOptions{}, fmt.Errorf("%w: %w", errHelpWrite, werr)
			}
			flags.SetOutput(&buf)
			flags.PrintDefaults()
			if cmd == scanCommand {
				if _, werr := buf.WriteString("\nA PATH inside a Git repository scans that whole repository from its git root.\nMonorepo scoping is tracked in https://github.com/vgmartinez/tripcord/issues/59.\n--staged scans the Git index. Paths are unioned with the staged change set\n(added, modified, deleted, type-changed, and mode-changed). With nothing\nstaged and no paths, nothing is reported.\n"); werr != nil {
					return scanOptions{}, fmt.Errorf("%w: %w", errHelpWrite, werr)
				}
			}
			if writeString(stdout, buf.String()) != int(exitcode.OK) {
				return scanOptions{}, errHelpWrite
			}
			return scanOptions{}, errHelp
		}
		return scanOptions{}, err
	}
	if _, err := output.ParseFormat(opts.format); err != nil {
		return scanOptions{}, err
	}
	if _, _, _, err := parseScope(opts.scope); err != nil {
		return scanOptions{}, err
	}
	if opts.since != "" {
		if err := validateSinceRef(opts.since); err != nil {
			return scanOptions{}, err
		}
	}
	switch {
	case cmd == preopenCommand && flags.NArg() != 1:
		return opts, errors.New("preopen takes exactly one git URL or local path")
	case opts.staged:
		opts.path = "."
		if flags.NArg() > 0 {
			// Paths name one pre-commit batch, or a direct manual
			// invocation. They are unioned with the diff-index change
			// set in runScan; they do not replace it. With none given,
			// only that change set is used.
			opts.stagedFiles, err = stagedPaths(flags.Args())
			if err != nil {
				return opts, err
			}
		}
	case flags.NArg() > 1:
		return opts, errors.New("scan accepts at most one PATH")
	case flags.NArg() == 1:
		opts.path = flags.Arg(0)
	default:
		opts.path = "."
	}
	if (opts.config && opts.secrets) || (opts.config && opts.all) || (opts.secrets && opts.all) {
		return opts, errors.New("--config, --secrets, and --all are mutually exclusive")
	}
	return opts, nil
}

// applyStagedSources sets SourcePaths on every repository item in items
// from sources (indexfiles.Plan.Sources, keyed by item.Path) and from the
// scripts or checksum files a rule reads from it (see
// scriptcheck.ItemReferencedPaths, which names a referenced path whether
// or not it resolved, so a staged deletion of one still matches).
func applyStagedSources(items []model.ConfigItem, sources map[string][]string) {
	for i := range items {
		item := &items[i]
		if item.Scope != model.ScopeRepo {
			continue
		}
		var extra []string
		extra = append(extra, sources[item.Path]...)
		extra = append(extra, scriptcheck.ItemReferencedPaths(*item)...)
		if len(extra) == 0 {
			continue
		}
		item.SourcePaths = dedupeSortedPaths(extra)
	}
}

// dedupeSortedPaths returns paths with duplicates removed, sorted.
func dedupeSortedPaths(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// stagedSourceMatches reports whether item's own Path, or any path in
// its SourcePaths (see model.ConfigItem.SourcePaths), is among staged,
// the paths pre-commit passed. It is the --staged filter: a finding is
// reported when any file whose staged content it depends on changed,
// not only when its own location path did.
func stagedSourceMatches(item model.ConfigItem, staged map[string]bool) bool {
	if staged[item.Path] {
		return true
	}
	for _, p := range item.SourcePaths {
		if staged[p] {
			return true
		}
	}
	return false
}

func stagedPaths(paths []string) (map[string]bool, error) {
	out := make(map[string]bool, len(paths))
	for _, path := range paths {
		if filepath.IsAbs(path) {
			return nil, fmt.Errorf("--staged path %q must be relative", path)
		}
		clean := filepath.ToSlash(filepath.Clean(path))
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
			return nil, fmt.Errorf("--staged path %q escapes the repository", path)
		}
		out[clean] = true
	}
	return out, nil
}

// scanRoot is the directory to scan. A path inside a Git repository uses
// that repository so config paths stay repo-relative. Any other directory
// is scanned on its own; only --since needs Git.
func scanRoot(scanPath string) (string, error) {
	absolute, err := filepath.Abs(scanPath)
	if err != nil {
		return "", fmt.Errorf("resolve scan path: %w", err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", fmt.Errorf("scan path: %w", err)
	}
	if !info.IsDir() {
		absolute = filepath.Dir(absolute)
	}
	if root := gitRoot(absolute); root != "" {
		return root, nil
	}
	return absolute, nil
}

func gitRoot(dir string) string {
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func repoRoot(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

func normalizeScanArgs(args []string) ([]string, error) {
	valueFlags := map[string]bool{
		"harness": true, "format": true, "output": true, "since": true,
		"fail-on": true, "policy": true, "org-policy": true, "scope": true,
	}
	var flags []string
	var positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			positionals = append(positionals, arg)
			continue
		}
		name, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		flags = append(flags, arg)
		if valueFlags[name] && !strings.Contains(arg, "=") {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("flag needs an argument: %s", arg)
			}
			i++
			flags = append(flags, args[i])
		}
	}
	return append(append(flags, "--"), positionals...), nil
}

func validateSinceRef(ref string) error {
	if ref == "" || strings.HasPrefix(ref, "-") || strings.ContainsAny(ref, "\x00\n\r") {
		return fmt.Errorf("--since %q: git ref must not be empty, start with '-', or contain a control character", ref)
	}
	return nil
}

func parseHarnesses(value string) ([]model.Harness, error) {
	if value == "" {
		return nil, nil
	}
	var out []model.Harness
	for _, raw := range strings.Split(value, ",") {
		harness := model.Harness(strings.TrimSpace(raw))
		if !adapters.AdapterHarness(harness) {
			return nil, fmt.Errorf("--harness: %q is not a supported harness", raw)
		}
		out = append(out, harness)
	}
	return out, nil
}

// gitInvokeError reports that git could not be started. A non-zero git
// status is an ordinary error: the ref or repository is unusable.
type gitInvokeError struct {
	err     error
	missing bool
}

func (e *gitInvokeError) Error() string { return e.err.Error() }

func (e *gitInvokeError) Unwrap() error { return e.err }

// changedFiles lists paths that differ between ref and HEAD. The diff is
// tree-to-tree, so repository Git config, hooks, fsmonitor, textconv, and
// external diff drivers do not run. Untracked and uncommitted files are
// not included. Names are NUL-delimited so non-ASCII paths are preserved.
func changedFiles(root, ref string) (map[string]bool, error) {
	if err := validateSinceRef(ref); err != nil {
		return nil, err
	}
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, &gitInvokeError{err: fmt.Errorf("--since: git is not installed: %w", err), missing: true}
	}
	command := exec.Command(git,
		"-C", root,
		"-c", "core.fsmonitor=false",
		"-c", "core.hooksPath=/dev/null",
		"-c", "protocol.allow=never",
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.file.allow=never",
		"--no-optional-locks",
		"diff",
		"--no-textconv",
		"--no-ext-diff",
		"--no-renames",
		"--name-only",
		"-z",
		"--end-of-options",
		ref,
		"HEAD",
		"--",
	)
	command.Stdin = nil
	command.Env = gitCommandEnv(root)
	raw, err := command.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return nil, &gitInvokeError{err: fmt.Errorf("--since: git could not be started: %w", err), missing: true}
		}
		if detail := sanitizeGitStderr(exitErr.Stderr); detail != "" {
			return nil, fmt.Errorf("--since %q: git diff failed: %s", ref, detail)
		}
		return nil, fmt.Errorf("--since %q: git diff failed: %w", ref, err)
	}
	changed := map[string]bool{}
	raw = bytes.TrimSuffix(raw, []byte{0})
	if len(raw) == 0 {
		return changed, nil
	}
	for _, name := range bytes.Split(raw, []byte{0}) {
		if len(name) == 0 {
			continue
		}
		changed[filepath.ToSlash(string(name))] = true
	}
	return changed, nil
}

// gitCommandEnv drops inherited Git configuration. GIT_CONFIG_NOSYSTEM
// ignores the system file, the ceiling stops discovery above root, and
// GIT_NO_LAZY_FETCH stops a partial clone's promisor remote from being
// contacted to fill in missing objects.
func gitCommandEnv(root string) []string {
	env := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "GIT_") {
			continue
		}
		env = append(env, entry)
	}
	return append(env,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CEILING_DIRECTORIES="+filepath.Dir(root),
		"GIT_NO_LAZY_FETCH=1",
	)
}

// maxGitStderrBytes caps a git diagnostic once it is embedded in our own
// error message. Git's own remediation text for some failures (for
// example, dubious ownership) is long enough, and the file or ref names
// attacker-controlled content can prepend to the usual one-line error, to
// be worth bounding on its own, well before the sink-level MaxFieldBytes
// cap a Finding gets.
const maxGitStderrBytes = 1024

// sanitizeGitStderr trims git's diagnostic output for inclusion in an
// error message. The user's home directory is rewritten to "~" using the
// same pathx.TildeHome rule the Claude Code adapter uses, so the message
// does not leak the local account path and a shorter home does not
// rewrite a longer one, then the result is capped so one long git
// diagnostic (git's "dubious ownership" remediation text, for example, or
// its usage text on an argument git itself rejects) cannot grow this
// error message without bound.
func sanitizeGitStderr(stderr []byte) string {
	msg := strings.TrimSpace(string(stderr))
	if msg == "" {
		return ""
	}
	if home, err := os.UserHomeDir(); err == nil {
		msg = pathx.TildeHome(home, msg)
	}
	msg = strings.ReplaceAll(msg, "\n", "; ")
	return truncateUTF8(msg, maxGitStderrBytes)
}

// truncateUTF8 caps value at limit bytes, cutting on a UTF-8 rune
// boundary, and appends a marker naming how many bytes were dropped.
func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut] + fmt.Sprintf("...[truncated %d bytes]", len(value)-cut)
}

func parseScope(value string) (repo, user, managed bool, err error) {
	switch value {
	case "repo":
		return true, false, false, nil
	case "user":
		return false, true, false, nil
	case "managed":
		return false, false, true, nil
	case "all":
		return true, true, true, nil
	default:
		return false, false, false, fmt.Errorf("--scope %q: want repo, user, managed, or all", value)
	}
}

// loadFingerprintKey resolves the fingerprint key (see fpkey.Load). A key
// file that cannot be read or created is not fatal: the scan continues
// in s1 mode and note says so. A key that is set but invalid, or
// existing key material that is broken, is a configuration error.
// Neither message carries the key.
func loadFingerprintKey() (key *fpkey.Key, note string, err error) {
	key, _, err = fpkey.Load(fpkey.Options{})
	switch {
	case err == nil:
		return key, "", nil
	case errors.Is(err, fpkey.ErrCIFallback):
		// Error() is exactly "CI detected: fingerprint key not created,
		// using s1". Print that, not the generic ErrUnavailable
		// phrasing below.
		return nil, err.Error(), nil
	case errors.Is(err, fpkey.ErrUnavailable):
		return nil, "fingerprints use the structural s1 discriminator: " + err.Error(), nil
	default:
		return nil, "", err
	}
}

func partitionDiagnostics(in []adapters.Diagnostic) (blocking, notes []adapters.Diagnostic) {
	for _, d := range in {
		if d.Informational {
			notes = append(notes, d)
		} else {
			blocking = append(blocking, d)
		}
	}
	return blocking, notes
}

// evalDiagnostics reports each rule that could not be evaluated on a
// file, once, as a blocking diagnostic: the other rules and files are
// still reported, and the scan exits as incomplete.
func evalDiagnostics(errs []rules.EvalError) []adapters.Diagnostic {
	var out []adapters.Diagnostic
	for _, e := range errs {
		msg := "config item could not be evaluated: " + e.Reason()
		if e.Rule != "" {
			msg = e.Rule + ": rule evaluation failed: " + e.Reason()
		}
		d := adapters.Diagnostic{Harness: e.Harness, Scope: e.Scope, Path: e.Path, Message: msg}
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

func outputDiagnostics(in []adapters.Diagnostic) []output.Diagnostic {
	out := make([]output.Diagnostic, len(in))
	for i, d := range in {
		out[i] = output.Diagnostic{
			Harness:       string(d.Harness),
			Scope:         string(d.Scope),
			Path:          d.Path,
			Message:       d.Message,
			Informational: d.Informational,
		}
	}
	return out
}

// opaqueDiagnostics makes every map command argument the scanner cannot
// interpret, and every list argument it coerces, visible without making the
// scan incomplete.
func opaqueDiagnostics(notices []rules.EvalNotice) []adapters.Diagnostic {
	out := make([]adapters.Diagnostic, 0, len(notices))
	for _, notice := range notices {
		message := "opaque command value ignored"
		if notice.Kind == rules.NoticeCoercedList {
			message = "non-string arg coerced"
		}
		d := adapters.Diagnostic{
			Harness:       notice.Harness,
			Scope:         notice.Scope,
			Path:          notice.Path,
			Message:       message + " at JSON pointer " + notice.Pointer,
			Informational: true,
		}
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

func decision(mode policy.Mode) model.Decision {
	switch mode {
	case policy.ModeEnforce:
		return model.DecisionDeny
	case policy.ModeWarn:
		return model.DecisionWarn
	case policy.ModeAudit:
		return model.DecisionAudit
	default:
		panic("unhandled policy mode")
	}
}

func sarifRuleText(catalog *rules.Catalog) map[string]output.RuleText {
	text := make(map[string]output.RuleText, len(catalog.Rules()))
	for _, rule := range catalog.Rules() {
		uri := ""
		for _, ref := range rule.Refs {
			uri = ref
			break
		}
		text[rule.ID] = output.RuleText{FullDescription: rule.Title, Help: rule.Fix, HelpURI: uri}
	}
	return text
}

func now() time.Time { return time.Now() }

// scanLimits returns the CEL limits for a scan. A test that lowers them
// must not run in parallel.
var scanLimits = rules.DefaultLimits

// loadRules compiles the core pack under limits. The CLI scans once per
// process; tests replace it with a cache keyed by limits, since the
// compiled pack is read-only and compiling it dominates a small scan.
var loadRules = func(limits rules.Limits) (*rules.Env, *rules.Catalog, error) {
	env, err := rules.NewEnv(limits)
	if err != nil {
		return nil, nil, err
	}
	pack, err := rules.LoadCore(env)
	if err != nil {
		return nil, nil, err
	}
	catalog, err := rules.NewCatalog(pack)
	if err != nil {
		return nil, nil, err
	}
	return env, catalog, nil
}

// redactHomeFromError rewrites the running user's home directory to "~"
// in err's message, the same way sanitizeGitStderr already does for
// git's own diagnostics. scanTarget's configError and internalError are
// the only two paths every scan error passes through (--output's
// output.PathError, --policy/--org-policy's policy.Error, and the scan
// PATH argument's wrapped os.Stat/filepath.Abs failures among them), so
// redacting here covers all of them without each caller needing to
// remember to do it itself.
func redactHomeFromError(err error) string {
	msg := err.Error()
	home, homeErr := os.UserHomeDir()
	if homeErr != nil || home == "" {
		return msg
	}
	return pathx.TildeHome(home, msg)
}

// writeString writes s and reports the exit status: OK on success, or
// Internal for a write failure (stdout or stderr closed out from under
// the process), per the CLI exit code table.
func writeString(w io.Writer, s string) int {
	if _, err := io.WriteString(w, s); err != nil {
		return int(exitcode.Internal)
	}
	return int(exitcode.OK)
}

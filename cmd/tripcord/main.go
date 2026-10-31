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
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/claude"
	"github.com/vgmartinez/tripcord/internal/adapters/generic"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
	"github.com/vgmartinez/tripcord/internal/pathx"
	"github.com/vgmartinez/tripcord/internal/policy"
	"github.com/vgmartinez/tripcord/internal/rules"
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

scan performs static configuration scanning only. --scope selects repository
(the default), user, managed, or all. The default does not read the home
directory or system settings.
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
	default:
		msg := fmt.Sprintf("tripcord: unknown command %q\n\n%s", args[0], usage)
		writeString(stderr, msg)
		return int(exitcode.Config)
	}
}

type scanOptions struct {
	config    bool
	secrets   bool
	all       bool
	harnesses string
	scope     string
	format    string
	output    string
	since     string
	failOn    string
	policy    string
	orgPolicy string
	path      string
}

func runScan(args []string, stdout, stderr io.Writer) int {
	opts, err := parseScanFlags(args, stdout)
	if errors.Is(err, errHelp) {
		return int(exitcode.OK)
	}
	if errors.Is(err, errHelpWrite) {
		return int(exitcode.Internal)
	}
	if err != nil {
		return scanConfigError(stderr, err)
	}
	if opts.secrets || opts.all {
		return scanConfigError(stderr, errors.New("secret scanning lands in v1; v0 supports --config only"))
	}
	root, err := scanRoot(opts.path)
	if err != nil {
		return scanConfigError(stderr, err)
	}
	env, err := rules.NewEnv(rules.DefaultLimits())
	if err != nil {
		return scanInternalError(stderr, err)
	}
	pack, err := rules.LoadCore(env)
	if err != nil {
		return scanInternalError(stderr, err)
	}
	catalog, err := rules.NewCatalog(pack)
	if err != nil {
		return scanInternalError(stderr, err)
	}
	policyOpts := policy.Options{RepoRoot: root, RepoPolicy: opts.policy, Surface: policy.SurfaceScan, Env: env, Catalog: catalog}
	if opts.orgPolicy != "" {
		policyOpts.OrgPolicy = []string{opts.orgPolicy}
	}
	effective, err := policy.Load(policyOpts)
	if err != nil {
		return scanConfigError(stderr, err)
	}
	if opts.failOn != "" {
		sev, err := model.ParseSeverity(opts.failOn)
		if err != nil {
			return scanConfigError(stderr, fmt.Errorf("--fail-on: %w", err))
		}
		if err := effective.ApplyFailOn(sev); err != nil {
			return scanConfigError(stderr, err)
		}
	}
	requested, err := parseHarnesses(opts.harnesses)
	if err != nil {
		return scanConfigError(stderr, err)
	}
	repoScope, userScope, managedScope, err := parseScope(opts.scope)
	if err != nil {
		return scanConfigError(stderr, err)
	}
	registry, err := adapters.NewRegistry(
		claude.New(claude.Options{SkipRepo: !repoScope, IncludeUser: userScope, IncludeManaged: managedScope}),
		generic.New(generic.Options{SkipRepo: !repoScope}),
	)
	if err != nil {
		return scanInternalError(stderr, err)
	}
	selected, err := registry.Select(root, requested)
	if err != nil {
		return scanConfigError(stderr, err)
	}
	var items []model.ConfigItem
	var diagnostics []adapters.Diagnostic
	for _, adapter := range selected {
		discovered, err := adapter.Discover(context.Background(), root)
		var partial *adapters.DiagnosticError
		switch {
		case errors.As(err, &partial):
			diagnostics = append(diagnostics, partial.Diagnostics...)
		case err != nil:
			return scanInternalError(stderr, fmt.Errorf("%s discovery: %w", adapter.Harness(), err))
		}
		items = append(items, discovered...)
	}
	if opts.since != "" {
		changed, err := changedFiles(root, opts.since)
		if err != nil {
			var invoke *gitInvokeError
			if errors.As(err, &invoke) && invoke.missing {
				return scanInternalError(stderr, err)
			}
			return scanConfigError(stderr, err)
		}
		items = slices.DeleteFunc(items, func(item model.ConfigItem) bool {
			return item.Scope != model.ScopeRepo || !changed[item.Path]
		})
		diagnostics = slices.DeleteFunc(diagnostics, func(d adapters.Diagnostic) bool {
			return d.Scope == model.ScopeRepo && d.Path != "" && !changed[d.Path]
		})
	}
	engine := rules.NewEngine(env, catalog.Rules(), rules.WithFilter(effective.RuleFilter()))
	result := engine.ScanConfig(context.Background(), items)
	if len(result.Errors) > 0 {
		return scanInternalError(stderr, result.Errors[0])
	}
	findings := make([]model.Finding, 0, len(result.Matches))
	for _, match := range result.Matches {
		if _, status := effective.Exception(match.Rule.ID, match.Item.Path, match.Item.SHA256, now()); status == policy.ExceptionActive {
			continue
		}
		finding, err := match.Finding(effective.Severity(match.Rule.ID, match.Rule.Severity), decision(effective.Mode))
		if err != nil {
			return scanInternalError(stderr, err)
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
			return scanConfigError(stderr, err)
		}
		return scanInternalError(stderr, err)
	}
	blocking, notes := partitionDiagnostics(diagnostics)
	if err := handle.SetDiagnostics(outputDiagnostics(blocking)); err != nil {
		_ = handle.Close()
		return scanInternalError(stderr, err)
	}
	for _, finding := range findings {
		if err := handle.Write(finding); err != nil {
			_ = handle.Close()
			return scanInternalError(stderr, err)
		}
	}
	if err := handle.Flush(); err != nil {
		_ = handle.Close()
		return scanInternalError(stderr, err)
	}
	if err := handle.Close(); err != nil {
		return scanInternalError(stderr, err)
	}
	// Exit 3 wins over exit 1: an incomplete scan is not a clean result.
	// Informational diagnostics are printed and do not change the exit code.
	for _, d := range append(append([]adapters.Diagnostic{}, blocking...), notes...) {
		if writeString(stderr, "tripcord scan: "+output.TerminalLine(d.String())+"\n") != int(exitcode.OK) {
			return int(exitcode.Internal)
		}
	}
	if len(blocking) > 0 {
		if writeString(stderr, "tripcord scan: configuration could not be fully read; the scan is incomplete\n") != int(exitcode.OK) {
			return int(exitcode.Internal)
		}
		return int(exitcode.Config)
	}
	for _, finding := range findings {
		fails, err := effective.Fails(finding.Severity)
		if err != nil {
			return scanInternalError(stderr, err)
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

func parseScanFlags(args []string, stdout io.Writer) (scanOptions, error) {
	normalized, err := normalizeScanArgs(args)
	if err != nil {
		return scanOptions{}, err
	}
	var opts scanOptions
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
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
	if err := flags.Parse(normalized); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			var buf bytes.Buffer
			if _, werr := fmt.Fprint(&buf, "tripcord scan [PATH]\n\n"); werr != nil {
				return scanOptions{}, fmt.Errorf("%w: %w", errHelpWrite, werr)
			}
			flags.SetOutput(&buf)
			flags.PrintDefaults()
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
	if flags.NArg() > 1 {
		return opts, errors.New("scan accepts at most one PATH")
	}
	if flags.NArg() == 1 {
		opts.path = flags.Arg(0)
	} else {
		opts.path = "."
	}
	if (opts.config && opts.secrets) || (opts.config && opts.all) || (opts.secrets && opts.all) {
		return opts, errors.New("--config, --secrets, and --all are mutually exclusive")
	}
	return opts, nil
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

func outputDiagnostics(in []adapters.Diagnostic) []output.Diagnostic {
	out := make([]output.Diagnostic, len(in))
	for i, d := range in {
		out[i] = output.Diagnostic{
			Harness: string(d.Harness),
			Scope:   string(d.Scope),
			Path:    d.Path,
			Message: d.Message,
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

func scanConfigError(stderr io.Writer, err error) int {
	writeString(stderr, "tripcord scan: "+err.Error()+"\n")
	return int(exitcode.Config)
}

func scanInternalError(stderr io.Writer, err error) int {
	writeString(stderr, "tripcord scan: "+err.Error()+"\n")
	return int(exitcode.Internal)
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

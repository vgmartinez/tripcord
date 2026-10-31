// Command tripcord is the Tripcord command-line interface.
//
// The root command uses the standard library only, so a later hook mode
// can cold-start quickly.
package main

import (
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

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
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

scan performs static configuration scanning only. Harness adapters land in
later releases; this command already provides the safe orchestration boundary.
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
	format    string
	output    string
	since     string
	failOn    string
	policy    string
	orgPolicy string
	path      string
}

func runScan(args []string, stdout, stderr io.Writer) int {
	opts, err := parseScanFlags(args, stderr)
	if err != nil {
		return scanConfigError(stderr, err)
	}
	if opts.secrets || opts.all {
		return scanConfigError(stderr, errors.New("--secrets is not available in v0; v0 scans executable config only"))
	}
	root, err := repoRoot(opts.path)
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
		effective.FailOn = sev
	}
	requested, err := parseHarnesses(opts.harnesses)
	if err != nil {
		return scanConfigError(stderr, err)
	}
	registry, err := adapters.NewRegistry()
	if err != nil {
		return scanInternalError(stderr, err)
	}
	selected, err := registry.Select(root, requested)
	if err != nil {
		return scanConfigError(stderr, err)
	}
	var items []model.ConfigItem
	for _, adapter := range selected {
		discovered, err := adapter.Discover(context.Background(), root)
		if err != nil {
			return scanInternalError(stderr, fmt.Errorf("%s discovery: %w", adapter.Harness(), err))
		}
		items = append(items, discovered...)
	}
	if opts.since != "" {
		changed, err := changedFiles(root, opts.since)
		if err != nil {
			return scanConfigError(stderr, err)
		}
		items = slices.DeleteFunc(items, func(item model.ConfigItem) bool {
			return item.Scope != model.ScopeRepo || !changed[item.Path]
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

func parseScanFlags(args []string, stderr io.Writer) (scanOptions, error) {
	var opts scanOptions
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.BoolVar(&opts.config, "config", false, "scan executable configuration (default)")
	flags.BoolVar(&opts.secrets, "secrets", false, "scan secrets (not available in v0)")
	flags.BoolVar(&opts.all, "all", false, "scan config and secrets")
	flags.StringVar(&opts.harnesses, "harness", "", "comma-separated harnesses; default autodetect")
	flags.StringVar(&opts.format, "format", "text", "text, json, sarif, md, or gha")
	flags.StringVar(&opts.output, "output", "-", "output path or - for stdout")
	flags.StringVar(&opts.since, "since", "", "only files changed from git ref")
	flags.StringVar(&opts.failOn, "fail-on", "", "low, medium, high, or critical")
	flags.StringVar(&opts.policy, "policy", "", "policy file")
	flags.StringVar(&opts.orgPolicy, "org-policy", "", "organization policy file")
	if err := flags.Parse(args); err != nil {
		return opts, err
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

func repoRoot(scanPath string) (string, error) {
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
	for dir := absolute; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("scan path is not inside a git repository")
		}
	}
}

func parseHarnesses(value string) ([]model.Harness, error) {
	if value == "" {
		return nil, nil
	}
	var out []model.Harness
	for _, raw := range strings.Split(value, ",") {
		harness := model.Harness(strings.TrimSpace(raw))
		if !harness.IsProduct() {
			return nil, fmt.Errorf("--harness: %q is not a supported harness", raw)
		}
		out = append(out, harness)
	}
	return out, nil
}

func changedFiles(root, ref string) (map[string]bool, error) {
	command := exec.Command("git", "-C", root, "--no-optional-locks", "diff", "--no-ext-diff", "--name-only", ref, "--")
	command.Stdin = nil
	raw, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("--since %q: git diff --name-only failed: %w", ref, err)
	}
	changed := map[string]bool{}
	for _, name := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if name != "" {
			changed[filepath.ToSlash(name)] = true
		}
	}
	return changed, nil
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

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
	"github.com/vgmartinez/tripcord/internal/policy"
)

const initUsage = `tripcord init [PATH] [--embed] [--harness h,...] [--version V --sha256 os-arch=HEX ...] [--force] [--dry-run]

Without --embed, writes .tripcord/policy.yaml only. With --embed, also
writes .tripcord/bootstrap.sh, .tripcord/embed.json,
.github/workflows/tripcord.yml, and the wiring of each harness. Existing
files are merged, never replaced; a file that cannot be merged safely
exits 3 and nothing is written. See docs/init.md.

`

// sha256Flags collects repeated --sha256 values.
type sha256Flags map[string]string

func (s sha256Flags) String() string { return "" }

func (s sha256Flags) Set(value string) error { return embedded.ParsePinSHA256(s, value) }

func runInit(args []string, stdout, stderr io.Writer) int {
	const prog = "tripcord init"
	fail := func(code exitcode.Code, err error) int {
		writeString(stderr, prog+": "+errorText(err)+"\n")
		return int(code)
	}
	var (
		embed, force, dryRun bool
		harnesses, version   string
		sums                 = sha256Flags{}
	)
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&embed, "embed", false, "write the bootstrap script, PR workflow, and harness wiring")
	flags.StringVar(&harnesses, "harness", "", "comma-separated harnesses to wire: "+strings.Join(harnessNames(), ", ")+" (default all)")
	flags.StringVar(&version, "version", "", "Tripcord release bootstrap.sh installs (required with --embed)")
	flags.Var(sums, "sha256", "os-arch=HEX SHA-256 of that platform's tripcord binary; repeat per platform (required with --embed)")
	flags.BoolVar(&force, "force", false, "rewrite files whose merge would reformat them or replace a conflicting value")
	flags.BoolVar(&dryRun, "dry-run", false, "print a unified diff and write nothing")
	normalized, err := normalizeInitArgs(args)
	if err != nil {
		return fail(exitcode.Config, err)
	}
	if err := flags.Parse(normalized); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			var b strings.Builder
			b.WriteString(initUsage)
			flags.SetOutput(&b)
			flags.PrintDefaults()
			return writeString(stdout, b.String())
		}
		return fail(exitcode.Config, err)
	}
	if flags.NArg() > 1 {
		return fail(exitcode.Config, errors.New("init accepts at most one PATH"))
	}
	if !embed && (harnesses != "" || version != "" || len(sums) > 0) {
		return fail(exitcode.Config, errors.New("--harness, --version, and --sha256 require --embed"))
	}
	opts := embedded.Options{Embed: embed, Force: force, Pin: embedded.Pin{Version: version, SHA256: sums}}
	if harnesses != "" {
		for _, raw := range strings.Split(harnesses, ",") {
			opts.Harnesses = append(opts.Harnesses, model.Harness(strings.TrimSpace(raw)))
		}
	}
	dir, err := initRoot(flags.Arg(0))
	if err != nil {
		return fail(exitcode.Config, err)
	}
	// tripcord hook finds the policy at the Git root and fails without
	// one, so wiring outside a repository would block every tool call.
	if embed && !repoRoot(dir) {
		return fail(exitcode.Config, fmt.Errorf("--embed needs a Git repository: %s has no .git, so every hook would block; run git init there first; nothing was written", quotedRedactedArg(flags.Arg(0))))
	}
	changes, err := embedded.Plan(dir, opts)
	if err != nil {
		var plan *embedded.PlanError
		var invalid *embedded.OptionError
		switch {
		case errors.As(err, &plan):
			for _, f := range plan.Files {
				writeString(stderr, prog+": "+errorText(f)+"\n")
			}
			return fail(exitcode.Config, errors.New("nothing was written"))
		case errors.Is(err, embedded.ErrUnsafePath), errors.Is(err, os.ErrNotExist):
			return fail(exitcode.Config, fmt.Errorf("%w; nothing was written", err))
		case errors.As(err, &invalid):
			return fail(exitcode.Config, fmt.Errorf("%w; nothing was written", err))
		default:
			return fail(exitcode.Internal, err)
		}
	}
	// privacy.redact: false has no effect in v0 (see warnRedactFalse):
	// warn once, whether the setting is already on disk (init only
	// preserves an existing policy.yaml, never merges its content) or
	// about to be written by this run.
	for _, c := range changes {
		if c.Path != embedded.PolicyPath {
			continue
		}
		if f, perr := policy.Parse(c.New); perr == nil && f.Privacy != nil && f.Privacy.Redact != nil && !*f.Privacy.Redact {
			if code := warnRedactFalse(stderr, prog, filepath.Join(dir, filepath.FromSlash(c.Path))); code != int(exitcode.OK) {
				return code
			}
		}
	}
	// The diff quotes the existing files around each change, and a
	// harness settings file can hold credentials (an env block, an MCP
	// server's token), so it is redacted and each line capped like any
	// other output.
	if dryRun {
		for _, c := range changes {
			if code := writeString(stdout, output.PreviewLines(embedded.UnifiedDiff(c))); code != int(exitcode.OK) {
				return code
			}
		}
		return writeString(stderr, prog+": dry run, nothing written\n")
	}
	if _, err := embedded.Apply(dir, changes); err != nil {
		return fail(exitcode.Internal, err)
	}
	for _, c := range changes {
		verb := "updated"
		switch {
		case c.Unchanged():
			verb = "unchanged"
		case c.Old == nil:
			verb = "created"
		}
		if code := writeString(stdout, verb+" "+c.Path+"\n"); code != int(exitcode.OK) {
			return code
		}
	}
	return int(exitcode.OK)
}

// initRoot is the directory init writes into: path itself. A path
// inside a Git repository must be that repository's root, so init never
// writes somewhere other than the directory it was given. Every error
// names path as given, redacted and then quoted: filepath.Abs cleans
// "https://u:pw@h" into "https:/u:pw@h", which no URL userinfo pattern
// matches, so a stat error's own path must not be shown.
func initRoot(path string) (string, error) {
	if path == "" {
		path = "."
	}
	named := quotedRedactedArg(path)
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("init path %s: %w", named, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			err = pathErr.Err
		}
		return "", fmt.Errorf("init path %s: %w", named, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", named)
	}
	if root := gitRoot(abs); root != "" && root != abs {
		return "", fmt.Errorf("%s is inside the Git repository at %s; run init at the repository root", named, root)
	}
	return abs, nil
}

// quotedRedactedArg is path as the user gave it, with the home directory
// folded and credentials redacted, then quoted. Quoting first would let
// a line continuation or a cleaned "://" through unredacted.
func quotedRedactedArg(path string) string {
	if path == "" {
		path = "."
	}
	return strconv.Quote(output.Message(foldHome(path)))
}

// normalizeInitArgs moves flags ahead of the PATH operand, as scan does.
func normalizeInitArgs(args []string) ([]string, error) {
	valueFlags := map[string]bool{"harness": true, "version": true, "sha256": true}
	var flags, positionals []string
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

func harnessNames() []string {
	names := make([]string, len(embedded.Harnesses))
	for i, h := range embedded.Harnesses {
		names[i] = string(h)
	}
	return names
}

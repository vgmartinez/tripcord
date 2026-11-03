package policy

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/vgmartinez/tripcord/internal/rules"
)

// Policy file locations relative to the repository root.
const (
	RepoFile = ".tripcord/policy.yaml"
	// LocalFile is the per-checkout layer, loaded after the repo policy.
	// It is not committed. tripcord init, in a later change, must add
	// this path to the .gitignore it generates.
	LocalFile = ".tripcord/policy.local.yaml"
)

// PackPolicyFile is the policy file inside an installed pack directory.
const PackPolicyFile = "policy.yaml"

// MaxExtendsDepth caps extends chains.
const MaxExtendsDepth = 8

// Resolver finds the policy file for a pack reference in extends.
// Resolution is local only; there is no network fetch.
type Resolver interface {
	ResolvePolicy(ref rules.PackRef) (string, error)
}

// DirResolver resolves <namespace>/<name>@<version> to
// Root/<namespace>/<name>@<version>/policy.yaml.
type DirResolver struct {
	Root string
}

// ResolvePolicy implements Resolver.
func (d DirResolver) ResolvePolicy(ref rules.PackRef) (string, error) {
	return filepath.Join(d.Root, filepath.FromSlash(ref.Name)+"@"+ref.Version, PackPolicyFile), nil
}

// ManagedPolicyPath is the machine-wide org policy for goos: a path an
// administrator controls and a repository does not. On Windows the
// directory comes from %ProgramData%.
func ManagedPolicyPath(goos string) string {
	switch goos {
	case "windows":
		dir := os.Getenv("ProgramData")
		if dir == "" {
			dir = `C:\ProgramData`
		}
		return dir + `\Tripcord\policy.yaml`
	case "darwin":
		return "/Library/Application Support/Tripcord/policy.yaml"
	default:
		return "/etc/tripcord/policy.yaml"
	}
}

// Options configures Load.
type Options struct {
	// RepoRoot holds .tripcord/policy.yaml and .tripcord/policy.local.yaml.
	// Both are optional.
	RepoRoot string
	// RepoPolicy replaces RepoFile when set. It is used by the scan CLI's
	// --policy flag; its adjacent local policy is not loaded.
	RepoPolicy string
	// ManagedPolicy is the managed org policy file. Empty means
	// ManagedPolicyPath(runtime.GOOS). It is optional: when the file
	// does not exist there is no managed layer. When it exists, Load
	// rejects it if it is world-writable or, on Unix, not owned by root
	// or the current user; see checkManagedPolicyFile. On Windows that
	// ownership check is best-effort; use the file's ACL instead.
	ManagedPolicy string
	// OrgPolicy lists org policy files given explicitly, by the
	// --org-policy flag or the GitHub Action input. Each must exist.
	// They merge after the managed policy. In CI the Action input comes
	// from the repository's own workflow file, so it is only as
	// trustworthy as that workflow: it is not an org boundary the
	// repository cannot bypass the way the managed file is.
	OrgPolicy []string
	// Surface selects the no-policy mode and fail-on. Required.
	// An explicit policy mode or fail-on overrides that default.
	Surface Surface
	Env     *rules.Env
	// Catalog may be nil; see Merge.
	Catalog RuleCatalog
	// Resolver resolves pack references in extends. Nil rejects them.
	Resolver Resolver
	// SkipLocal does not read LocalFile. A scan that compares a change
	// with its base never reads it: it is per checkout, and a change
	// could add one.
	SkipLocal bool
}

// Load reads the org, repo, and local policy files, resolves extends,
// and merges the layers. Errors are *Error; invalid policy maps to exit
// code 3.
func Load(opts Options) (*Effective, error) {
	if _, err := DefaultsFor(opts.Surface); err != nil {
		return nil, &Error{Err: err}
	}
	layers, err := LoadLayers(opts)
	if err != nil {
		return nil, err
	}
	return Merge(opts.Env, opts.Catalog, opts.Surface, layers)
}

// LoadLayers returns the parsed layers in merge order:
//
//  1. org: the managed policy, then each OrgPolicy file, each preceded
//     by what it extends. The repository controls none of these.
//  2. extends: what the repo policy extends that the org layer did not
//     already load. These come after the org layer, so they can add to
//     it but neither replace nor skip it, and org locks bind them.
//  3. repo, then local.
func LoadLayers(opts Options) ([]Layer, error) {
	l := &loader{resolver: opts.Resolver, seen: map[string]bool{}}

	managed := opts.ManagedPolicy
	if managed == "" {
		managed = ManagedPolicyPath(runtime.GOOS)
	}
	if err := checkManagedPolicyFile(managed); err != nil {
		return nil, err
	}
	if err := l.root(managed, LayerOrg, false); err != nil {
		return nil, err
	}
	for _, p := range opts.OrgPolicy {
		if err := l.root(filepath.Clean(p), LayerOrg, true); err != nil {
			return nil, err
		}
	}

	repo := opts.RepoPolicy
	explicitRepo := opts.RepoPolicy != ""
	if repo == "" {
		repo = filepath.Join(opts.RepoRoot, filepath.FromSlash(RepoFile))
	}
	if err := l.root(repo, LayerRepo, explicitRepo); err != nil {
		return nil, err
	}

	if opts.RepoPolicy != "" || opts.SkipLocal {
		return l.layers, nil
	}
	local := filepath.Join(opts.RepoRoot, filepath.FromSlash(LocalFile))
	f, err := readFile(local)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if len(f.Extends) > 0 {
			return nil, &Error{Source: local, Err: errors.New("extends is not allowed in the local policy")}
		}
		l.layers = append(l.layers, Layer{Kind: LayerLocal, Source: local, File: f})
	}
	return l.layers, nil
}

type loader struct {
	resolver Resolver
	// seen holds every file already loaded, across roots, so a file
	// reached twice merges once, at its first position.
	seen map[string]bool
	// chain is the path of files from the current root to the current one.
	chain  []string
	layers []Layer
	// kind is the layer kind of files reached through extends.
	kind LayerKind
}

// root loads source and what it extends. A missing file is an error
// only when required. Files the repo policy extends become
// LayerExtends; files an org policy extends stay LayerOrg.
func (l *loader) root(source string, kind LayerKind, required bool) error {
	if l.seen[source] {
		return nil
	}
	f, err := readFile(source)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if required {
			return &Error{Source: source, Err: fmt.Errorf("%s does not exist", requiredPolicyKind(kind))}
		}
		return nil
	case err != nil:
		return err
	}
	l.seen[source] = true
	l.chain = []string{source}
	l.kind = kind
	if kind == LayerRepo {
		l.kind = LayerExtends
	}
	if err := l.extends(source, f, 0); err != nil {
		return err
	}
	l.layers = append(l.layers, Layer{Kind: kind, Source: source, File: f})
	return nil
}

// requiredPolicyKind names a required but missing policy file layer for
// the error message root returns.
func requiredPolicyKind(kind LayerKind) string {
	switch kind {
	case LayerOrg:
		return "org policy"
	case LayerRepo:
		return "--policy file"
	default:
		return "policy"
	}
}

func (l *loader) onChain(target string) bool {
	for _, c := range l.chain {
		if c == target {
			return true
		}
	}
	return false
}

// extends appends the ancestors of f, depth first, in declaration order.
// A file reached twice (a diamond) is merged once, at its first position.
func (l *loader) extends(source string, f *File, depth int) error {
	for _, entry := range f.Extends {
		if depth+1 > MaxExtendsDepth {
			return &Error{Source: source, Err: fmt.Errorf("extends is nested deeper than %d", MaxExtendsDepth)}
		}
		target, err := l.resolve(source, entry)
		if err != nil {
			return err
		}
		if l.seen[target] {
			if l.onChain(target) {
				return &Error{Source: source, Err: fmt.Errorf("extends cycle through %s", target)}
			}
			continue
		}
		l.seen[target] = true
		parent, err := readFile(target)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return &Error{Source: source, Err: fmt.Errorf("extends %s: %s does not exist", entry, target)}
			}
			return err
		}
		l.chain = append(l.chain, target)
		err = l.extends(target, parent, depth+1)
		l.chain = l.chain[:len(l.chain)-1]
		if err != nil {
			return err
		}
		l.layers = append(l.layers, Layer{Kind: l.kind, Source: target, File: parent})
	}
	return nil
}

func (l *loader) resolve(source, entry string) (string, error) {
	kind, ref, err := ParseExtends(entry)
	if err != nil {
		return "", &Error{Source: source, Err: err}
	}
	switch kind {
	case ExtendsPath:
		p := filepath.FromSlash(entry)
		if !filepath.IsAbs(p) {
			p = filepath.Join(filepath.Dir(source), p)
		}
		return filepath.Clean(p), nil
	case ExtendsPack:
		if l.resolver == nil {
			return "", &Error{Source: source, Err: fmt.Errorf("extends %s: no pack resolver is configured", ref)}
		}
		p, err := l.resolver.ResolvePolicy(ref)
		if err != nil {
			return "", &Error{Source: source, Err: fmt.Errorf("extends %s: %w", ref, err)}
		}
		return filepath.Clean(p), nil
	default:
		panic(fmt.Sprintf("policy: unhandled extends kind %d", kind))
	}
}

func readFile(name string) (*File, error) {
	fh, err := os.Open(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, &Error{Source: name, Err: err, IO: true}
	}
	defer func() { _ = fh.Close() }()
	data, err := io.ReadAll(io.LimitReader(fh, MaxFileBytes+1))
	if err != nil {
		return nil, &Error{Source: name, Err: err, IO: true}
	}
	f, err := Parse(data)
	if err != nil {
		return nil, &Error{Source: name, Err: err}
	}
	return f, nil
}

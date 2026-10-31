package policy

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/vgmartinez/tripcord/internal/rules"
)

// Policy file locations relative to the repository root.
const (
	RepoFile  = ".tripcord/policy.yaml"
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

// Options configures Load.
type Options struct {
	// RepoRoot holds .tripcord/policy.yaml and .tripcord/policy.local.yaml.
	// Both are optional.
	RepoRoot string
	Env      *rules.Env
	// Catalog may be nil; see Merge.
	Catalog RuleCatalog
	// Resolver resolves pack references in extends. Nil rejects them.
	Resolver Resolver
}

// Load reads the repo and local policy files, resolves extends, and
// merges the layers: org (everything reached through extends from the
// repo file), then repo, then local. Errors are *Error; invalid policy
// maps to exit code 3.
func Load(opts Options) (*Effective, error) {
	layers, err := LoadLayers(opts)
	if err != nil {
		return nil, err
	}
	return Merge(opts.Env, opts.Catalog, layers)
}

// LoadLayers returns the parsed layers in merge order.
func LoadLayers(opts Options) ([]Layer, error) {
	var layers []Layer
	repo := filepath.Join(opts.RepoRoot, filepath.FromSlash(RepoFile))
	f, err := readFile(repo)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		l := &loader{resolver: opts.Resolver, seen: map[string]bool{repo: true}, chain: []string{repo}}
		if err := l.extends(repo, f, 0); err != nil {
			return nil, err
		}
		layers = append(l.layers, Layer{Kind: LayerRepo, Source: repo, File: f})
	}

	local := filepath.Join(opts.RepoRoot, filepath.FromSlash(LocalFile))
	f, err = readFile(local)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if len(f.Extends) > 0 {
			return nil, &Error{Source: local, Err: errors.New("extends is only allowed in the repo policy and the files it extends")}
		}
		layers = append(layers, Layer{Kind: LayerLocal, Source: local, File: f})
	}
	return layers, nil
}

type loader struct {
	resolver Resolver
	seen     map[string]bool
	// chain is the path of files from the repo policy to the current one.
	chain  []string
	layers []Layer
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
		l.layers = append(l.layers, Layer{Kind: LayerOrg, Source: target, File: parent})
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

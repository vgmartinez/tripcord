package rules

import (
	"cmp"
	"errors"
	"os"
	"slices"

	corepack "github.com/vgmartinez/tripcord/rules"
)

// CoreSource labels the embedded built-in pack in errors.
const CoreSource = "builtin:rules"

// LoadCore loads the built-in pack embedded from rules/.
func LoadCore(env *Env) (*Pack, error) {
	return LoadPack(corepack.FS, CoreSource, env)
}

// LoadDir loads the pack in directory dir.
func LoadDir(dir string, env *Env) (*Pack, error) {
	return LoadPack(os.DirFS(dir), dir, env)
}

// Catalog is a set of packs with globally unique rule ids.
type Catalog struct {
	packs []*Pack
	rules []*Rule
	byID  map[string]*Rule
}

// NewCatalog combines packs. It rejects two packs with the same name
// and a rule id that appears in more than one pack.
func NewCatalog(packs ...*Pack) (*Catalog, error) {
	c := &Catalog{byID: map[string]*Rule{}}
	names := map[string]string{}
	owner := map[string]string{}
	var errs []error
	for _, p := range packs {
		if prev, ok := names[p.Ref.Name]; ok {
			errs = append(errs, invalid(p.Source, "pack %s is already loaded from %s", p.Ref.Name, prev))
			continue
		}
		names[p.Ref.Name] = p.Source
		c.packs = append(c.packs, p)
		for _, r := range p.Rules {
			if prev, ok := owner[r.ID]; ok {
				errs = append(errs, invalid(p.Source, "duplicate rule id %s, also in %s", r.ID, prev))
				continue
			}
			owner[r.ID] = p.Source
			c.byID[r.ID] = r
			c.rules = append(c.rules, r)
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	slices.SortFunc(c.rules, func(a, b *Rule) int { return cmp.Compare(a.ID, b.ID) })
	return c, nil
}

// Rule returns the rule with id.
func (c *Catalog) Rule(id string) (*Rule, bool) {
	r, ok := c.byID[id]
	return r, ok
}

// Rules returns every rule, sorted by id.
func (c *Catalog) Rules() []*Rule { return append([]*Rule(nil), c.rules...) }

// Packs returns the packs in load order.
func (c *Catalog) Packs() []*Pack { return append([]*Pack(nil), c.packs...) }

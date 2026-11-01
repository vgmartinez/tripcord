package rules

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
)

// Fixture directories inside <ID>.test/. The names follow the spec.
const (
	PositiveDir = "positivos"
	NegativeDir = "negativos"
)

// FixtureExt is the engine fixture format: a JSON ConfigItem, or an
// array of them. An empty sha256 is filled in as the SHA-256 of the
// payload bytes.
const FixtureExt = ".json"

// DiscoverFunc normalizes the repository at root into config items, the
// way `tripcord scan` does. It runs raw config fixtures: a subdirectory
// of positivos/ or negativos/ is a repository tree of real config files.
// It returns an error when the tree cannot be read in full.
type DiscoverFunc func(ctx context.Context, root string) ([]model.ConfigItem, error)

// CheckRuleFixtures runs rule against packDir/<ID>.test/. Every fixture
// in positivos/ must produce at least one match and every fixture in
// negativos/ must produce none. Evaluation errors fail either kind.
// Each directory needs at least one fixture, and that fixture must
// contain an item inside the rule's harness and file globs. A negative
// whose items are all out of scope would pass without testing when.
//
// A fixture is a .json engine fixture or a subdirectory holding a raw
// repository tree, which discover normalizes. A nil discover rejects
// raw fixtures.
func CheckRuleFixtures(ctx context.Context, env *Env, packDir string, rule *Rule, discover DiscoverFunc) error {
	base := filepath.Join(packDir, rule.ID+TestDirSuffix)
	engine := NewEngine(env, []*Rule{rule})
	var errs []error
	for _, kind := range []string{PositiveDir, NegativeDir} {
		dir := filepath.Join(base, kind)
		fixtures, err := fixtureEntries(dir, discover != nil)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, f := range fixtures {
			var items []model.ConfigItem
			if f.raw {
				items, err = discover(ctx, f.path)
				if err != nil {
					err = fmt.Errorf("%s: %w", f.path, err)
				}
			} else {
				items, err = readFixture(f.path)
			}
			if err == nil {
				err = checkFixture(ctx, engine, rule, f.path, items, kind == PositiveDir)
			}
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

type fixtureEntry struct {
	path string
	raw  bool
}

func fixtureEntries(dir string, rawAllowed bool) ([]fixtureEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	var out []fixtureEntry
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		switch {
		case e.IsDir() && !rawAllowed:
			return nil, fmt.Errorf("%s: raw config fixtures need the harness adapters; run them with a DiscoverFunc", path)
		case e.IsDir():
			out = append(out, fixtureEntry{path: path, raw: true})
		case filepath.Ext(e.Name()) != FixtureExt:
			return nil, fmt.Errorf("%s: a fixture is a %s ConfigItem document or a directory holding a raw config tree", path, FixtureExt)
		default:
			out = append(out, fixtureEntry{path: path})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: needs at least one fixture", dir)
	}
	slices.SortFunc(out, func(a, b fixtureEntry) int { return strings.Compare(a.path, b.path) })
	return out, nil
}

func checkFixture(ctx context.Context, engine *Engine, rule *Rule, file string, items []model.ConfigItem, positive bool) error {
	if len(items) == 0 {
		return fmt.Errorf("%s: no config items", file)
	}
	// A positive that never enters the rule's harness and file globs did
	// not test the rule. A negative in the same position passes without
	// exercising the expression, so it is rejected too.
	if !slices.ContainsFunc(items, rule.Applies) {
		return fmt.Errorf("%s: no item matches the rule's harness and files", file)
	}
	res := engine.ScanConfig(ctx, items)
	if len(res.Errors) > 0 {
		errs := make([]error, len(res.Errors))
		for i, e := range res.Errors {
			errs[i] = e
		}
		return fmt.Errorf("%s: %w", file, errors.Join(errs...))
	}
	switch {
	case positive && len(res.Matches) == 0:
		return fmt.Errorf("%s: positive fixture did not trigger %s", file, rule.ID)
	case !positive && len(res.Matches) > 0:
		return fmt.Errorf("%s: negative fixture triggered %s on %s", file, rule.ID, res.Matches[0].Item.Path)
	}
	return nil
}

func readFixture(file string) ([]model.ConfigItem, error) {
	raw, err := readLimited(os.DirFS(filepath.Dir(file)), filepath.Base(file), 1<<20)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	raw = bytes.TrimSpace(raw)
	var items []model.ConfigItem
	if bytes.HasPrefix(raw, []byte("[")) {
		err = json.Unmarshal(raw, &items)
	} else {
		var item model.ConfigItem
		err = json.Unmarshal(raw, &item)
		items = []model.ConfigItem{item}
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("%s: no config items", file)
	}
	for i := range items {
		if items[i].SHA256 == "" {
			sum := sha256.Sum256(items[i].Payload)
			items[i].SHA256 = hex.EncodeToString(sum[:])
		}
		if err := items[i].Validate(); err != nil {
			return nil, fmt.Errorf("%s: item %d: %w", file, i, err)
		}
	}
	return items, nil
}

package rules

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/strictyaml"
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

// ExpectFile, in <ID>.test/, says what each fixture must produce, keyed
// by the fixture's file or directory name:
//
//	positivos:
//	  curl-pipe: high
//	  two-hooks: [high, medium]
//	negativos:
//	  args-object.json: error
//
// A positive lists the distinct severities of its matches. Every
// positive of a rule with severity_when needs an entry; a positive of
// any other rule defaults to the rule's severity. A negative may only be
// marked error: the rule must fail to evaluate it, which a scan reports
// as an incomplete-scan diagnostic, and it must not match.
const ExpectFile = "expect.yaml"

const expectError = "error"

type expectations struct {
	Positive map[string]outcome `yaml:"positivos"`
	Negative map[string]outcome `yaml:"negativos"`
}

// outcome is a severity, a list of severities, or error.
type outcome []string

func (o *outcome) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*o = outcome{n.Value}
		return nil
	}
	var list []string
	if err := n.Decode(&list); err != nil {
		return err
	}
	*o = list
	return nil
}

func readExpectations(base string) (expectations, error) {
	var exp expectations
	path := filepath.Join(base, ExpectFile)
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return exp, nil
	}
	if err == nil {
		err = strictyaml.Decode(raw, &exp)
	}
	if err != nil {
		return exp, fmt.Errorf("%s: %w", path, err)
	}
	for name, o := range exp.Positive {
		if len(o) == 0 {
			return exp, fmt.Errorf("%s: positivos %s: no severity", path, name)
		}
		seen := map[string]bool{}
		for _, sev := range o {
			if _, err := model.ParseSeverity(sev); err != nil {
				return exp, fmt.Errorf("%s: positivos %s: %w", path, name, err)
			}
			if seen[sev] {
				return exp, fmt.Errorf("%s: positivos %s: %s is listed twice", path, name, sev)
			}
			seen[sev] = true
		}
	}
	for name, o := range exp.Negative {
		if !slices.Equal(o, outcome{expectError}) {
			return exp, fmt.Errorf("%s: negativos %s: a negative can only expect %s", path, name, expectError)
		}
	}
	return exp, nil
}

// DiscoverFunc normalizes the repository at root into config items, the
// way `tripcord scan` does. It runs raw config fixtures: a subdirectory
// of positivos/ or negativos/ is a repository tree of real config files.
// It returns an error when the tree cannot be read in full.
type DiscoverFunc func(ctx context.Context, root string) ([]model.ConfigItem, error)

// CheckRuleFixtures runs rule against packDir/<ID>.test/. Every fixture
// in positivos/ must produce at least one match, with the severities
// ExpectFile lists, and every fixture in negativos/ must produce none.
// Evaluation errors fail either kind, except a negative ExpectFile marks
// error, which must fail to evaluate.
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
	exp, err := readExpectations(base)
	if err != nil {
		return err
	}
	var errs []error
	for _, kind := range []string{PositiveDir, NegativeDir} {
		dir := filepath.Join(base, kind)
		want := exp.Negative
		if kind == PositiveDir {
			want = exp.Positive
		}
		fixtures, err := fixtureEntries(dir, discover != nil)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		names := map[string]bool{}
		for _, f := range fixtures {
			names[filepath.Base(f.path)] = true
		}
		for _, name := range slices.Sorted(maps.Keys(want)) {
			if !names[name] {
				errs = append(errs, fmt.Errorf("%s: %s %s: no such fixture", filepath.Join(base, ExpectFile), kind, name))
			}
		}
		for _, f := range fixtures {
			// Windows CI may materialize a committed symlink as a regular
			// file. Skip those fixtures there; Linux and macOS run them.
			if f.raw && runtime.GOOS == "windows" && treeHasSymlink(f.path) {
				continue
			}
			expected, listed := want[filepath.Base(f.path)]
			if kind == PositiveDir && !listed {
				if len(rule.SeverityWhen) > 0 {
					errs = append(errs, fmt.Errorf("%s: no expected severity in %s (the rule has severity_when)", f.path, ExpectFile))
					continue
				}
				expected = outcome{string(rule.Severity)}
			}
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
				err = checkFixture(ctx, engine, rule, f.path, items, kind == PositiveDir, expected)
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

func treeHasSymlink(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || found {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
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

func checkFixture(ctx context.Context, engine *Engine, rule *Rule, file string, items []model.ConfigItem, positive bool, want outcome) error {
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
	if slices.Equal(want, outcome{expectError}) {
		switch {
		case len(res.Errors) == 0:
			return fmt.Errorf("%s: expected %s to fail to evaluate", file, rule.ID)
		case len(res.Matches) > 0:
			return fmt.Errorf("%s: fixture expected to fail triggered %s on %s", file, rule.ID, res.Matches[0].Item.Path)
		}
		return nil
	}
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
	case positive:
		var got []string
		for _, m := range res.Matches {
			got = append(got, string(m.Severity))
		}
		slices.Sort(got)
		got = slices.Compact(got)
		w := slices.Sorted(slices.Values(want))
		if !slices.Equal(got, w) {
			return fmt.Errorf("%s: %s severities = %v, want %v", file, rule.ID, got, w)
		}
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

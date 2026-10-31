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
// payload bytes. Raw config files are a later step, with the harness
// adapters.
const FixtureExt = ".json"

// CheckRuleFixtures runs rule against packDir/<ID>.test/. Every file in
// positivos/ must produce at least one match and every file in
// negativos/ must produce none. Evaluation errors fail either kind.
// Each directory needs at least one fixture.
func CheckRuleFixtures(ctx context.Context, env *Env, packDir string, rule *Rule) error {
	base := filepath.Join(packDir, rule.ID+TestDirSuffix)
	engine := NewEngine(env, []*Rule{rule})
	var errs []error
	for _, kind := range []string{PositiveDir, NegativeDir} {
		dir := filepath.Join(base, kind)
		files, err := fixtureFiles(dir)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, file := range files {
			if err := checkFixture(ctx, engine, rule, file, kind == PositiveDir); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func fixtureFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if filepath.Ext(e.Name()) != FixtureExt {
			return nil, fmt.Errorf("%s: engine fixtures are %s ConfigItem documents; raw config fixtures come with the harness adapters", path, FixtureExt)
		}
		files = append(files, path)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s: needs at least one fixture", dir)
	}
	slices.Sort(files)
	return files, nil
}

func checkFixture(ctx context.Context, engine *Engine, rule *Rule, file string, positive bool) error {
	items, err := readFixture(file)
	if err != nil {
		return err
	}
	if positive && !slices.ContainsFunc(items, rule.Applies) {
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

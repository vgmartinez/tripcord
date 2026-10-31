package rules

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"

	"github.com/vgmartinez/tripcord/internal/strictyaml"
)

// ManifestFile names the pack manifest in a pack directory.
const ManifestFile = "pack.yaml"

// TestDirSuffix marks a rule's fixture directory: rules/<ID>.test/.
const TestDirSuffix = ".test"

const maxManifestBytes = 4 << 10

// Manifest is pack.yaml.
//
//	pack: tripcord/core@2026.11
type Manifest struct {
	Pack string `yaml:"pack"`
}

// Pack is a loaded, compiled rule pack.
type Pack struct {
	Ref      PackRef
	Source   string
	Rules    []*Rule
	Registry *Registry
}

// LoadPack loads the pack at the root of fsys. source labels errors.
//
// A pack directory holds pack.yaml, REGISTRY, and one <ID>.yaml per
// rule. Each rule's pack field names the manifest pack and inherits its
// version, and its id
// must be active in REGISTRY. Every active id must have a rule file and
// no retired id may have one. <ID>.test/ fixture directories and other
// non-YAML files are ignored. All problems are reported together.
func LoadPack(fsys fs.FS, source string, env *Env) (*Pack, error) {
	raw, err := readLimited(fsys, ManifestFile, maxManifestBytes)
	if err != nil {
		return nil, wrap(source, err)
	}
	var m Manifest
	if err := strictyaml.Decode(raw, &m); err != nil {
		return nil, invalid(path.Join(source, ManifestFile), "%v", err)
	}
	ref, err := ParsePackRef(m.Pack)
	if err != nil {
		return nil, invalid(path.Join(source, ManifestFile), "%v", err)
	}

	raw, err = readLimited(fsys, RegistryFile, 1<<20)
	if err != nil {
		return nil, wrap(source, err)
	}
	reg, err := ParseRegistry(raw)
	if err != nil {
		return nil, invalid(path.Join(source, RegistryFile), "%v", err)
	}

	var errs []error
	for _, e := range reg.Entries() {
		if e.Introduced.Name != ref.Name {
			errs = append(errs, invalid(path.Join(source, RegistryFile), "line %d: %s was introduced in %s, not pack %s", e.Line, e.ID, e.Introduced, ref.Name))
		}
	}

	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, wrap(source, err)
	}
	pack := &Pack{Ref: ref, Source: source, Registry: reg}
	seen := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		file := path.Join(source, name)
		if strings.HasSuffix(name, ".yml") {
			errs = append(errs, invalid(file, "rule files use the .yaml extension"))
			continue
		}
		if !strings.HasSuffix(name, ".yaml") || name == ManifestFile {
			continue
		}
		if !entry.Type().IsRegular() {
			errs = append(errs, invalid(file, "not a regular file"))
			continue
		}
		id := strings.TrimSuffix(name, ".yaml")
		rule, err := loadRule(fsys, name, id, ref, reg, env)
		if err != nil {
			errs = append(errs, wrap(file, err))
			continue
		}
		seen[id] = true
		pack.Rules = append(pack.Rules, rule)
	}
	for _, e := range reg.Entries() {
		if e.Status == StatusActive && !seen[e.ID] {
			errs = append(errs, invalid(path.Join(source, RegistryFile), "line %d: %s is active but %s.yaml is missing; retire it instead of deleting the file", e.Line, e.ID, e.ID))
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return pack, nil
}

func loadRule(fsys fs.FS, name, id string, ref PackRef, reg *Registry, env *Env) (*Rule, error) {
	if !ValidID(id) {
		return nil, fmt.Errorf("file name must be <ID>.yaml with a rule id such as TC-CFG-001")
	}
	raw, err := readLimited(fsys, name, MaxRuleBytes)
	if err != nil {
		return nil, err
	}
	spec, err := ParseSpec(raw)
	if err != nil {
		return nil, err
	}
	if spec.ID != id {
		return nil, fmt.Errorf("id %s does not match the file name", spec.ID)
	}
	if spec.Pack != ref.Name {
		return nil, fmt.Errorf("pack %s does not match the manifest %s", spec.Pack, ref)
	}
	entry, ok := reg.Lookup(id)
	switch {
	case !ok:
		return nil, fmt.Errorf("%s is not in %s; append it as active", id, RegistryFile)
	case entry.Status == StatusRetired:
		return nil, fmt.Errorf("%s is retired in %s; rule ids are never reused", id, RegistryFile)
	}
	return Compile(spec, ref, env)
}

// readLimited reads name from fsys, failing when it exceeds limit bytes.
func readLimited(fsys fs.FS, name string, limit int64) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", name, limit)
	}
	return data, nil
}

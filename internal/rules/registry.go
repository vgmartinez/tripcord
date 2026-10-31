package rules

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// RegistryFile is the name of the id registry in a pack directory.
const RegistryFile = "REGISTRY"

// RegistryStatus is the state of an allocated rule id.
type RegistryStatus string

const (
	// StatusActive ids must have a rule file in the pack.
	StatusActive RegistryStatus = "active"
	// StatusRetired ids must not have a rule file and are never reused.
	StatusRetired RegistryStatus = "retired"
)

// RegistryEntry is one allocated id.
type RegistryEntry struct {
	ID         string
	Status     RegistryStatus
	Introduced PackRef
	Line       int
}

// Registry is every rule id a pack has ever allocated. It is
// append-only: CheckRegistryEvolution rejects edits that would let an
// id be reused.
//
// Format: one entry per line, "<id> <active|retired> <pack@version>",
// where the pack is the release that introduced the id. Blank lines
// and lines starting with # are ignored.
type Registry struct {
	entries []RegistryEntry
	byID    map[string]RegistryEntry
}

// ParseRegistry parses a REGISTRY file.
func ParseRegistry(data []byte) (*Registry, error) {
	r := &Registry{byID: map[string]RegistryEntry{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 3 {
			return nil, fmt.Errorf("line %d: want \"<id> <active|retired> <pack@version>\"", line)
		}
		id, status, introduced := fields[0], RegistryStatus(fields[1]), fields[2]
		if !ValidID(id) {
			return nil, fmt.Errorf("line %d: id %q is not a rule id", line, id)
		}
		if status != StatusActive && status != StatusRetired {
			return nil, fmt.Errorf("line %d: status %q: want active or retired", line, status)
		}
		ref, err := ParsePackRef(introduced)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if prev, ok := r.byID[id]; ok {
			return nil, fmt.Errorf("line %d: id %s already registered on line %d", line, id, prev.Line)
		}
		entry := RegistryEntry{ID: id, Status: status, Introduced: ref, Line: line}
		r.entries = append(r.entries, entry)
		r.byID[id] = entry
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

// Lookup returns the entry for id.
func (r *Registry) Lookup(id string) (RegistryEntry, bool) {
	e, ok := r.byID[id]
	return e, ok
}

// Entries returns the entries in file order.
func (r *Registry) Entries() []RegistryEntry {
	return append([]RegistryEntry(nil), r.entries...)
}

// CheckRegistryEvolution reports edits from old to next that would let
// an id be reused: removing an entry, changing the release that
// introduced it, or moving a retired id back to active. Adding entries
// and retiring active ones are allowed.
func CheckRegistryEvolution(old, next *Registry) error {
	var errs []error
	for _, prev := range old.entries {
		cur, ok := next.byID[prev.ID]
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("%s: removed from the registry; retire it instead", prev.ID))
		case cur.Introduced != prev.Introduced:
			errs = append(errs, fmt.Errorf("%s: introduced release changed from %s to %s", prev.ID, prev.Introduced, cur.Introduced))
		case prev.Status == StatusRetired && cur.Status != StatusRetired:
			errs = append(errs, fmt.Errorf("%s: retired ids cannot be reactivated; allocate a new id", prev.ID))
		}
	}
	return errors.Join(errs...)
}

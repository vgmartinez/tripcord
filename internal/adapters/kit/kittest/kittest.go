// Package kittest holds test helpers shared by the adapter packages:
// fixture trees, golden files, discovery with validation, and the
// fingerprint a finding citing an item would mint.
package kittest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/fpkey"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/rules"
)

// Discovery is the golden form of one Discover call.
type Discovery struct {
	Items       []model.ConfigItem `json:"items"`
	Diagnostics []string           `json:"diagnostics"`
}

// Discover runs a and fails the test on a fatal error or an invalid item.
func Discover(t testing.TB, a adapters.Adapter, root string) Discovery {
	t.Helper()
	items, err := a.Discover(context.Background(), root)
	var diag *adapters.DiagnosticError
	if err != nil && !errors.As(err, &diag) {
		t.Fatalf("Discover: %v", err)
	}
	out := Discovery{Items: items, Diagnostics: []string{}}
	if diag != nil {
		for _, d := range diag.Diagnostics {
			out.Diagnostics = append(out.Diagnostics, d.String())
		}
	}
	for _, item := range items {
		CheckItem(t, item)
	}
	return out
}

// HasDiag reports whether any diagnostic contains part.
func (d Discovery) HasDiag(part string) bool {
	for _, msg := range d.Diagnostics {
		if strings.Contains(msg, part) {
			return true
		}
	}
	return false
}

// Blocking runs a and reports whether Discover returned a diagnostic that
// is not informational and contains part. Only a blocking diagnostic
// makes `tripcord scan` exit non-zero; an informational one does not.
func Blocking(t testing.TB, a adapters.Adapter, root, part string) bool {
	t.Helper()
	_, err := a.Discover(context.Background(), root)
	var diag *adapters.DiagnosticError
	if !errors.As(err, &diag) {
		return false
	}
	for _, d := range diag.Diagnostics {
		if !d.Informational && strings.Contains(d.String(), part) {
			return true
		}
	}
	return false
}

// Find returns the items whose path and kind match.
func (d Discovery) Find(path string, kind model.ConfigKind) []model.ConfigItem {
	var out []model.ConfigItem
	for _, item := range d.Items {
		if item.Path == path && item.Kind == kind {
			out = append(out, item)
		}
	}
	return out
}

// CheckItem fails the test unless item validates, has an ID, and carries
// a non-empty evidence key.
func CheckItem(t testing.TB, item model.ConfigItem) {
	t.Helper()
	if err := item.Validate(); err != nil {
		t.Fatalf("invalid item %+v: %v", item, err)
	}
	if _, err := item.ID(); err != nil {
		t.Fatalf("item id: %v", err)
	}
	if key, _ := Payload(t, item)["key"].(string); key == "" {
		t.Fatalf("item without key: %s", item.Payload)
	}
}

// Payload decodes an item payload.
func Payload(t testing.TB, item model.ConfigItem) map[string]any {
	t.Helper()
	var payload map[string]any
	dec := json.NewDecoder(bytes.NewReader(item.Payload))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	return payload
}

// Fingerprint is the fingerprint of a finding whose only evidence cites
// item by ID and the evidence key the rules engine derives from it.
func Fingerprint(t testing.TB, item model.ConfigItem) string {
	t.Helper()
	id, err := item.ID()
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	key := rules.ConfigEvidenceKey(item)
	fp, err := model.Fingerprint("TC-TEST-000", model.Location{Harness: item.Harness, Scope: item.Scope, Path: item.Path}, []model.Evidence{{Config: &model.ConfigRef{ID: id, Key: key}}})
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	return fp
}

// WriteFile creates path with content, making parent directories.
func WriteFile(t testing.TB, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// CopyTree copies the fixture directory from into a fresh temporary
// directory and returns it.
func CopyTree(t testing.TB, from string) string {
	t.Helper()
	root := t.TempDir()
	err := filepath.WalkDir(from, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		dest := filepath.Join(root, rel)
		if entry.IsDir() {
			return os.MkdirAll(dest, 0o700)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dest, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// GoldenJSON renders d as indented JSON with each replacement applied
// (machine-specific temporary paths to fixed names).
func GoldenJSON(t testing.TB, d Discovery, replace map[string]string) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for from, to := range replace {
		raw = bytes.ReplaceAll(raw, []byte(from), []byte(to))
	}
	return append(raw, '\n')
}

// AssertGolden compares got with testdata/name. UPDATE_GOLDEN=1 rewrites
// the file.
func AssertGolden(t testing.TB, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch\n--- got ---\n%s--- want ---\n%s", name, got, want)
	}
}

// Env returns a Getenv function that knows only the given pairs.
func Env(pairs ...string) func(string) string {
	return func(name string) string {
		for i := 0; i+1 < len(pairs); i += 2 {
			if pairs[i] == name {
				return pairs[i+1]
			}
		}
		return ""
	}
}

// TestFingerprintKey is the k1 fingerprint key adapter tests use. It is
// a fixed test value, never a real key. fpkey.New requires a hex
// string, so this is 64 hex characters, matching a generated key file's
// length, even though no test here reads it from a file.
const TestFingerprintKey = "cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d"

// FingerprintKey returns TestFingerprintKey as a key, for adapter
// options in tests that expect k1 semantics.
func FingerprintKey() *fpkey.Key {
	k, err := fpkey.New(TestFingerprintKey)
	if err != nil {
		panic(err)
	}
	return k
}

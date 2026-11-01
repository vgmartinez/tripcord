package kit

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/fpkey"
	"github.com/vgmartinez/tripcord/internal/model"
)

var (
	k1Part = regexp.MustCompile(`^sig:k1:[0-9a-f]{16}#[0-9]+$`)
	s1Part = regexp.MustCompile(`^sig:s1:[^#]*#[0-9]+$`)
)

// sigParts returns the evidence key parts of every item s's collector
// holds, in insertion order.
func sigParts(t *testing.T, c *Collector) [][]string {
	t.Helper()
	var out [][]string
	for _, item := range c.Items() {
		var payload map[string]any
		if err := json.Unmarshal(item.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		var parts []string
		if err := json.Unmarshal([]byte(payload["key"].(string)), &parts); err != nil {
			t.Fatal(err)
		}
		out = append(out, parts)
	}
	return out
}

func dockerServer(privateKey, pass string) map[string]any {
	return map[string]any{
		"command": "docker",
		"args":    []any{"run", "-i", "--rm", "-e", "PRIVATE_KEY=" + privateKey, "-ePASS=" + pass, "img:1"},
	}
}

func last(parts []string) string { return parts[len(parts)-1] }

func TestDiscriminatorModes(t *testing.T) {
	t.Parallel()
	keyed := func(pk, pass string) []string {
		s := source(model.ScopeRepo, ".mcp.json")
		s.MCPServers(map[string]any{"app": dockerServer(pk, pass)}, "mcpServers")
		return sigParts(t, s.c)[0]
	}
	structural := func(pk, pass string) []string {
		s := s1Source(model.ScopeRepo, ".mcp.json")
		s.MCPServers(map[string]any{"app": dockerServer(pk, pass)}, "mcpServers")
		return sigParts(t, s.c)[0]
	}
	base, rotated := keyed("zsX01q", "zsY01q"), keyed("zsX02q", "zsY01q")
	if !k1Part.MatchString(last(base)) {
		t.Fatalf("k1 key has no k1 marker: %v", base)
	}
	if EvidenceKey(base) == EvidenceKey(rotated) {
		t.Fatalf("k1: a different secret kept the key %v", base)
	}
	s1Base, s1Rotated := structural("zsX01q", "zsY01q"), structural("zsX02q", "zsY02q")
	if want := "sig:s1:args[0],args[1]#0"; last(s1Base) != want {
		t.Fatalf("s1 discriminator = %q, want %q", last(s1Base), want)
	}
	if EvidenceKey(s1Base) != EvidenceKey(s1Rotated) {
		t.Fatalf("s1: a rotated secret changed the key: %v vs %v", s1Base, s1Rotated)
	}
	if EvidenceKey(s1Base) == EvidenceKey(base) {
		t.Fatal("k1 and s1 keys collide")
	}
	for _, k := range [][]string{base, rotated, s1Base, s1Rotated} {
		for _, secret := range []string{"zsX01q", "zsX02q", "zsY01q", "zsY02q"} {
			if strings.Contains(EvidenceKey(k), secret) {
				t.Fatalf("key leaks %q: %v", secret, k)
			}
		}
	}
	for range 200 {
		if got := keyed("zsX01q", "zsY01q"); EvidenceKey(got) != EvidenceKey(base) {
			t.Fatalf("k1 not deterministic: %v vs %v", got, base)
		}
		if got := structural("zsX01q", "zsY01q"); EvidenceKey(got) != EvidenceKey(s1Base) {
			t.Fatalf("s1 not deterministic: %v vs %v", got, s1Base)
		}
	}
}

func TestS1OrdinalSeparatesIdenticalDuplicates(t *testing.T) {
	t.Parallel()
	hooks := func(s *Source, tokens ...string) {
		var list []any
		for _, token := range tokens {
			list = append(list, map[string]any{"command": "notify --token " + token})
		}
		s.Hooks(map[string]any{"stop": list}, Flat, []string{"command"})
	}
	s := s1Source(model.ScopeRepo, ".cursor/hooks.json")
	hooks(s, "zsA01q", "zsB01q", "zsC01q")
	got := sigParts(t, s.c)
	if len(got) != 3 {
		t.Fatalf("items = %v", got)
	}
	for i, parts := range got {
		if want := "sig:s1:command[0]#" + string(rune('0'+i)); last(parts) != want {
			t.Fatalf("entry %d discriminator = %q, want %q", i, last(parts), want)
		}
		if EvidenceKey(parts[:len(parts)-1]) != EvidenceKey(got[0][:len(got[0])-1]) {
			t.Fatalf("duplicates differ before the ordinal: %v vs %v", parts, got[0])
		}
	}
	rotated := s1Source(model.ScopeRepo, ".cursor/hooks.json")
	hooks(rotated, "zsA02q", "zsB02q", "zsC02q")
	for i, parts := range sigParts(t, rotated.c) {
		if EvidenceKey(parts) != EvidenceKey(got[i]) {
			t.Fatalf("rotation changed entry %d: %v vs %v", i, parts, got[i])
		}
	}
	other := s1Source(model.ScopeRepo, ".cursor/other.json")
	hooks(other, "zsA01q")
	if last(sigParts(t, other.c)[0]) != "sig:s1:command[0]#0" {
		t.Fatal("the ordinal is not per file")
	}

	k1 := source(model.ScopeRepo, ".cursor/hooks.json")
	hooks(k1, "zsA01q", "zsB01q")
	keyed := sigParts(t, k1.c)
	if !k1Part.MatchString(last(keyed[0])) || EvidenceKey(keyed[0]) == EvidenceKey(keyed[1]) {
		t.Fatalf("k1 duplicates with different secrets = %v", keyed)
	}
}

// TestK1OrdinalSeparatesIdenticalDuplicates is TestS1OrdinalSeparatesIdenticalDuplicates's
// k1 counterpart: k1 entries identical after sanitizing, including the
// same secret, are told apart only by the ordinal appended after "#",
// the same stable per-file, in-file-order rule s1 uses, not by the k1
// HMAC alone (which would be identical for every one of them).
func TestK1OrdinalSeparatesIdenticalDuplicates(t *testing.T) {
	t.Parallel()
	hooks := func(s *Source, tokens ...string) {
		var list []any
		for _, token := range tokens {
			list = append(list, map[string]any{"command": "notify --token " + token})
		}
		s.Hooks(map[string]any{"stop": list}, Flat, []string{"command"})
	}
	s := source(model.ScopeRepo, ".cursor/hooks.json")
	hooks(s, "zsE01q", "zsE01q", "zsE01q")
	got := sigParts(t, s.c)
	if len(got) != 3 {
		t.Fatalf("items = %v", got)
	}
	for i, parts := range got {
		if !k1Part.MatchString(last(parts)) {
			t.Fatalf("entry %d discriminator = %q, not k1", i, last(parts))
		}
		want := "#" + string(rune('0'+i))
		if !strings.HasSuffix(last(parts), want) {
			t.Fatalf("entry %d discriminator = %q, want suffix %q", i, last(parts), want)
		}
		if EvidenceKey(parts) == EvidenceKey(got[0]) && i != 0 {
			t.Fatalf("entries %d and 0 share a key: %v", i, parts)
		}
		beforeOrdinal := strings.TrimSuffix(last(parts), want)
		if want0 := strings.TrimSuffix(last(got[0]), "#0"); beforeOrdinal != want0 {
			t.Fatalf("duplicates differ before the ordinal: %q vs %q", beforeOrdinal, want0)
		}
	}
	other := source(model.ScopeRepo, ".cursor/other.json")
	hooks(other, "zsE01q")
	if got := last(sigParts(t, other.c)[0]); !strings.HasSuffix(got, "#0") {
		t.Fatalf("the ordinal is not per file: %q", got)
	}
}

func TestNoDiscriminatorWithoutRemovals(t *testing.T) {
	t.Parallel()
	for _, s := range []*Source{source(model.ScopeRepo, "a"), s1Source(model.ScopeRepo, "a")} {
		s.MCPServers(map[string]any{"x": map[string]any{"command": "npx", "args": []any{"-y", "pkg@1"}}}, "mcpServers")
		parts := sigParts(t, s.c)[0]
		if k1Part.MatchString(last(parts)) || s1Part.MatchString(last(parts)) {
			t.Fatalf("entry with nothing removed got a discriminator: %v", parts)
		}
	}
}

func TestStructuralDiscriminatorUsesNoValue(t *testing.T) {
	t.Parallel()
	a := StructuralDiscriminator(map[string]any{
		"args": []any{Redacted, "x", Redacted},
		"env":  map[string]any{"A": Redacted},
	})
	b := StructuralDiscriminator(map[string]any{
		"args": []any{Redacted, "y", Redacted},
		"env":  map[string]any{"A": Redacted},
	})
	if a != b || a != "args[0],args[1],env[0]" {
		t.Fatalf("StructuralDiscriminator = %q and %q", a, b)
	}
	fieldName := "ghp_" + strings.Repeat("a", 36)
	if got := StructuralDiscriminator(map[string]any{fieldName: Redacted}); strings.Contains(got, "ghp_") {
		t.Fatalf("field name was not redacted: %q", got)
	}
	if got := StructuralDiscriminator(map[string]any{"command": "echo " + Redacted}); got != "command[0]" {
		t.Fatalf("embedded marker not counted: %q", got)
	}
	if got := StructuralDiscriminator(map[string]any{"clean": "nothing here"}); got != "" {
		t.Fatalf("field with no marker produced a part: %q", got)
	}
}

// TestK1HexCaseKeepsFingerprint: the HMAC key is the decoded hex, so the
// same key written in uppercase and lowercase produces the same evidence
// key and the same fingerprint.
func TestK1HexCaseKeepsFingerprint(t *testing.T) {
	t.Parallel()
	fingerprint := func(text string) (key, fp string) {
		t.Helper()
		k, err := fpkey.New(text)
		if err != nil {
			t.Fatal(err)
		}
		c := NewCollector(model.HarnessCodex, "Codex")
		c.SetHome("/home/dev")
		c.SetFingerprintKey(k)
		s := c.Source(model.ScopeRepo, ".mcp.json", nil)
		s.MCPServers(map[string]any{"app": dockerServer("zsX01q", "zsY01q")}, "mcpServers")
		key = EvidenceKey(sigParts(t, c)[0])
		fp, err = model.Fingerprint("TC-TEST-006", model.Location{
			Harness: model.HarnessCodex,
			Scope:   model.ScopeRepo,
			Path:    ".mcp.json",
		}, []model.Evidence{{Config: &model.ConfigRef{ID: "codex:repo:.mcp.json", Key: key}}})
		if err != nil {
			t.Fatal(err)
		}
		return key, fp
	}
	lowerKey, lowerFP := fingerprint(testKey)
	upperKey, upperFP := fingerprint(strings.ToUpper(testKey))
	if lowerKey != upperKey || lowerFP != upperFP {
		t.Fatalf("case changed the key or fingerprint\n lower %s %s\n upper %s %s", lowerKey, lowerFP, upperKey, upperFP)
	}
}

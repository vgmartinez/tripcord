package codex

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/model"
)

// In an opaque rules file a secret flag and its value are separate
// string literals; the value must still be redacted from the content
// and still discriminate the key.
func TestRulesFileOpaqueRedactsFlagValueLiterals(t *testing.T) {
	t.Parallel()
	opaque := func(secret string) (string, string) {
		root := t.TempDir()
		kittest.WriteFile(t, filepath.Join(root, ".codex", "rules", "default.rules"),
			"prefix_rule(pattern = [\"aws\", \"configure\", \"--secret-access-key\", \""+secret+"\"]) + unknown\n"+
				"prefix_rule(pattern = ['gh', '--token', 'GH"+secret+"'])\n"+
				"# kept: \"--verbose\"\n")
		got := kittest.Discover(t, New(Options{FingerprintKey: kittest.FingerprintKey()}), root)
		items := got.Find(".codex/rules/default.rules", model.ConfigKindPermissions)
		if len(items) != 1 {
			t.Fatalf("items = %+v, want one opaque item", got.Items)
		}
		p := kittest.Payload(t, items[0])
		content, _ := p["content"].(string)
		key, _ := p["key"].(string)
		return content, key
	}
	contentA, keyA := opaque("AWSSAKVALUEONE")
	contentB, keyB := opaque("AWSSAKVALUETWO")
	for _, leak := range []string{"AWSSAKVALUE", "GHAWSSAK"} {
		if strings.Contains(contentA, leak) || strings.Contains(keyA, leak) {
			t.Fatalf("opaque content or key leaks %q: %s / %s", leak, contentA, keyA)
		}
	}
	if contentA != contentB {
		t.Fatalf("sanitized content depends on the secret:\n%s\n%s", contentA, contentB)
	}
	if keyA == keyB {
		t.Fatalf("entries differing only in a redacted literal share key %s", keyA)
	}
	for _, kept := range []string{`"--secret-access-key", "[REDACTED]"`, `'--token', '[REDACTED]'`, "+ unknown", `# kept: "--verbose"`} {
		if !strings.Contains(contentA, kept) {
			t.Fatalf("content lost %q: %s", kept, contentA)
		}
	}
}

func TestSanitizeRulesLiteralsEdgeCases(t *testing.T) {
	t.Parallel()
	c := kit.NewCollector(model.HarnessCodex, "Codex")
	f := &file{Source: c.Source(model.ScopeRepo, ".codex/rules/x.rules", nil)}
	cases := map[string]string{
		`x = """--token TRIPLESECRET""" + y`:      `x = """--token [REDACTED]""" + y`,
		`x = ["--token", "a\"b\x41"]`:             `x = ["--token", "[REDACTED]"]`,
		`x = ["--token", 'it\'s']`:                `x = ["--token", '[REDACTED]']`,
		"x = [\"--token\", \"unterminated\n]":     "x = [\"--token\", \"unterminated\n]",
		`x = """never closed --token Q`:           `x = """never closed --token Q`,
		`x = ["\x41", "keep\\me"] # "--token" no`: `x = ["\x41", "keep\\me"] # "--token" no`,
		`"\`: `"\`,
	}
	for in, want := range cases {
		if got := f.sanitizeRulesLiterals([]byte(in)); got != want {
			t.Errorf("sanitizeRulesLiterals(%q) = %q, want %q", in, got, want)
		}
	}
}

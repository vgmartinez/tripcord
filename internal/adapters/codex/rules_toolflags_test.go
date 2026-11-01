package codex

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/model"
)

// A tool-specific secret flag in a prefix_rule pattern (or a match
// example) is redacted in the payload and the key, and still
// discriminates the key, as in an MCP server's argv.
func TestRulesPatternRedactsToolSecretFlags(t *testing.T) {
	t.Parallel()
	patterns := map[string]string{
		`["redis-cli", "--pass", "%s"]`:      `["redis-cli","--pass","[REDACTED]"]`,
		`["redis-cli", "-a", "%s"]`:          `["redis-cli","-a","[REDACTED]"]`,
		`["sshpass", "-p%s"]`:                `["sshpass","-p[REDACTED]"]`,
		`["sshpass", "-p", "%s"]`:            `["sshpass","-p","[REDACTED]"]`,
		`["openssl", "enc", "-K", "%s"]`:     `["openssl","enc","-K","[REDACTED]"]`,
		`["openssl", "-pass", "pass:%s"]`:    `["openssl","-pass","pass:[REDACTED]"]`,
		`["mysql", "-p%s"]`:                  `["mysql","-p[REDACTED]"]`,
		`["redis-cli", "--pass=%s", "ping"]`: `["redis-cli","--pass=[REDACTED]","ping"]`,
		`["/usr/bin/sshpass", "-p", "%s"]`:   `["/usr/bin/sshpass","-p","[REDACTED]"]`,
	}
	rule := func(pattern, secret string) (string, string) {
		home := t.TempDir()
		kittest.WriteFile(t, filepath.Join(home, ".codex", "rules", "default.rules"),
			"prefix_rule(pattern = "+strings.ReplaceAll(pattern, "%s", secret)+`, decision = "allow", match = [`+strings.ReplaceAll(pattern, "%s", "M"+secret)+"])\n")
		got := kittest.Discover(t, New(Options{FingerprintKey: kittest.FingerprintKey(), IncludeUser: true, HomeDir: home, Getenv: kittest.Env()}), t.TempDir())
		items := got.Find("~/.codex/rules/default.rules", model.ConfigKindPermissions)
		if len(items) != 1 {
			t.Fatalf("%s: items = %+v", pattern, got.Items)
		}
		return string(items[0].Payload), kittest.Payload(t, items[0])["key"].(string)
	}
	for pattern, want := range patterns {
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()
			payloadA, keyA := rule(pattern, "RA5SECRET")
			_, keyB := rule(pattern, "RB6SECRET")
			if strings.Contains(payloadA, "SECRET") {
				t.Errorf("payload leaks the secret: %s", payloadA)
			}
			if !strings.Contains(keyA, strings.ReplaceAll(strings.ReplaceAll(want, `\`, `\\`), `"`, `\"`)) {
				t.Errorf("key %s does not hold the redacted pattern %s", keyA, want)
			}
			if keyA == keyB {
				t.Errorf("rules differing only in the secret share key %s", keyA)
			}
		})
	}
}

// In an opaque rules file a tool word activates its secret flags for the
// literals after it.
func TestRulesFileOpaqueRedactsToolSecretFlags(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".codex", "rules", "default.rules"),
		"x = unknown\n"+
			`prefix_rule(pattern = ["mysql", "-pOPQ1"])`+"\n"+
			`prefix_rule(pattern = ["redis-cli", "--pass", "OPQ2"])`+"\n"+
			`prefix_rule(pattern = ["sshpass", "-pOPQ4"])`+"\n"+
			`prefix_rule(pattern = ["openssl", "enc", "-K", "OPQ6"])`+"\n")
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".codex/rules/default.rules", model.ConfigKindPermissions)
	if len(items) != 1 {
		t.Fatalf("items = %+v, want one opaque item", got.Items)
	}
	p := kittest.Payload(t, items[0])
	content, _ := p["content"].(string)
	key, _ := p["key"].(string)
	if strings.Contains(content+key, "OPQ") {
		t.Fatalf("opaque content or key leaks a tool secret: %s / %s", content, key)
	}
}

// In a fully literal rules file a tool word activates its flags only
// within its own list: a later, unrelated pattern keeps its arguments.
func TestRulesFileScopesToolFlagsToEachList(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".codex", "rules", "default.rules"),
		`prefix_rule(pattern = ["redis-cli", "info"])`+"\n"+
			`prefix_rule(pattern = ["make", "-a", "all"])`+"\n"+
			`prefix_rule(pattern = ["mysql", "-pOPQ7"])`+"\n"+
			`prefix_rule(pattern = ["jq", "-pretty"])`+"\n"+
			`prefix_rule(pattern = ["redis-cli", "-a", "OPQ8"])`+"\n")
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".codex/rules/default.rules", model.ConfigKindPermissions)
	if len(items) != 5 {
		t.Fatalf("items = %+v, want five parsed items", got.Items)
	}
	var content strings.Builder
	for _, item := range items {
		content.Write(item.Payload)
	}
	for _, kept := range []string{`"pattern":["make","-a","all"]`, `"pattern":["jq","-pretty"]`, `"pattern":["mysql","-p[REDACTED]"]`, `"pattern":["redis-cli","-a","[REDACTED]"]`} {
		if !strings.Contains(content.String(), kept) {
			t.Errorf("content lost %q: %s", kept, content.String())
		}
	}
	if strings.Contains(content.String(), "OPQ") {
		t.Fatalf("parsed content leaks a tool secret: %s", content.String())
	}
}

func TestRulesFileOpaqueTokenizesIdentifiersOutsideStringsAndComments(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".codex", "rules", "default.rules"),
		`T = "redis-cli"`+"\n"+
			"[\n# tool\nT, \"-a\", \"QS01\"]\n"+
			"[ # c\n T, \"-a\", \"QS02\"]\n"+
			"[(T), \"-a\", \"QS03\"]\n"+
			`["%s" % T, "-a", "QS04"]`+"\n"+
			`["{}".format(T), "-a", "QS05"]`+"\n"+
			"list((T, \"-a\", \"QS06\"))\n"+
			`["-a" if 0 else T, "QS07"]`+"\n"+
			`(T, "-a", "QS08")`+"\n")
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".codex/rules/default.rules", model.ConfigKindPermissions)
	if len(items) != 1 {
		t.Fatalf("items = %+v, want one opaque item", got.Items)
	}
	content, _ := kittest.Payload(t, items[0])["content"].(string)
	for _, secret := range []string{"QS01", "QS02", "QS03", "QS04", "QS05", "QS06", "QS07", "QS08"} {
		if strings.Contains(content, secret) {
			t.Errorf("opaque content leaks %q: %s", secret, content)
		}
	}
}

func TestRulesFileOpaqueIgnoresStringAndCommentOperators(t *testing.T) {
	t.Parallel()
	raw := []byte("# q16 +\n" +
		`prefix_rule(pattern = ["redis-cli", "q12 + q16"])` + "\n" +
		`prefix_rule(pattern = ["make", "-a", "all"])`)
	if !isStrictLiteralRulesFile(raw) {
		t.Fatal("string/comment + incorrectly enabled conservative fallback")
	}
}

func TestRulesFileOpaqueRejectsAllValueIdentifiersAndOperators(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".codex", "rules", "default.rules"),
		`pattern = "redis-cli"`+"\n"+
			`match = "redis-cli"`+"\n"+
			`True = "redis-cli"`+"\n"+
			`decision = "redis-cli"`+"\n"+
			`not_match = "redis-cli"`+"\n"+
			`prefix_rule(pattern = [pattern, "-a", "QE01X"])`+"\n"+
			`prefix_rule(pattern = [match, "-a", "QE02X"])`+"\n"+
			`prefix_rule(pattern = [True, "-a", "QE03X"])`+"\n"+
			`prefix_rule(pattern = [decision, "-a", "QE04X"])`+"\n"+
			`prefix_rule(pattern = [not_match, "-a", "QE05X"])`+"\n"+
			`prefix_rule(pattern = [None, "-a", "QE06X"])`+"\n"+
			`prefix_rule(pattern = ["xredis-cli"[1:], "-a", "QE07X"])`+"\n"+
			`prefix_rule(pattern = ["redis%s" % "cli", "-a", "QE08X"])`+"\n"+
			`prefix_rule(pattern = ["\x64edis-cli", "-a", "QE09X"])`+"\n"+
			`prefix_rule(pattern = ["\u0072edis-cli", "-a", "QE10X"])`+"\n"+
			`prefix_rule(pattern = ["-%s" % "a", "QE11X"])`+"\n"+
			`prefix_rule(pattern = ["-p%s" % "S", "QE12X"])`+"\n"+
			"ţ = \"redis-cli\"\n")
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".codex/rules/default.rules", model.ConfigKindPermissions)
	if len(items) != 1 {
		t.Fatalf("items = %+v, want one opaque item", got.Items)
	}
	content, _ := kittest.Payload(t, items[0])["content"].(string)
	for _, secret := range []string{"QE01X", "QE02X", "QE03X", "QE04X", "QE05X", "QE06X", "QE07X", "QE08X", "QE09X", "QE10X", "QE11X", "QE12X"} {
		if strings.Contains(content, secret) {
			t.Errorf("opaque content leaks %q: %s", secret, content)
		}
	}
}

func TestRulesFileOpaqueRedactsEveryValueAfterCredentialFlag(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".codex", "rules", "default.rules"),
		`T = "redis-cli"`+"\n"+
			`[T, "-a", "QB17", "QQ10"]`+"\n")
	got := kittest.Discover(t, New(Options{}), root)
	item := got.Find(".codex/rules/default.rules", model.ConfigKindPermissions)[0]
	content, _ := kittest.Payload(t, item)["content"].(string)
	if strings.Contains(content, "QB17") || strings.Contains(content, "QQ10") {
		t.Fatalf("credential-flag tail leaks: %s", content)
	}
}

func TestRulesFileOpaqueConservativelyRedactsNestedAndUnresolvedArgv(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".codex", "rules", "default.rules"),
		"x = unknown\n"+
			`prefix_rule(pattern = ["mysql", ("-pQR09X", "-pQR09Y")])`+"\n"+
			`["redis-cli"] + ["-a", "QR07X"]`+"\n"+
			`T = "redis-cli"`+"\n"+
			`prefix_rule(pattern = [T, "-a", "QR06X"]) + unknown`+"\n"+
			`TOOLS + [`+"\n"+
			`  "-a", "QR06Y",`+"\n"+
			`]`+"\n"+
			`["redis-cli"] + A`+"\n"+
			`def policy():`+"\n"+
			`  return ["-a", "QR06Z"]`+"\n")
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".codex/rules/default.rules", model.ConfigKindPermissions)
	if len(items) != 1 {
		t.Fatalf("items = %+v, want one opaque item", got.Items)
	}
	content, _ := kittest.Payload(t, items[0])["content"].(string)
	for _, secret := range []string{"QR09X", "QR09Y", "QR07X", "QR06X", "QR06Y", "QR06Z"} {
		if strings.Contains(content, secret) {
			t.Errorf("opaque content leaks %q: %s", secret, content)
		}
	}
}

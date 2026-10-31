package codex

import (
	"path/filepath"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/model"
)

func TestRulesFileWithRawControlByteInStringIsOpaque(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"CR":  "prefix_rule(pattern = [\"git\r\", \"push\"], decision = \"allow\")\n",
		"NUL": "prefix_rule(pattern = [\"rm\x00 -rf\"], decision = \"allow\")\n",
	} {
		root := t.TempDir()
		kittest.WriteFile(t, filepath.Join(root, ".codex", "rules", "default.rules"), body)
		a := New(Options{})
		got := kittest.Discover(t, a, root)
		items := got.Find(".codex/rules/default.rules", model.ConfigKindPermissions)
		if len(items) != 1 || kittest.Payload(t, items[0])["role"] != "rules-file" {
			t.Fatalf("%s: items = %+v, want one opaque rules-file item", name, got.Items)
		}
		if !kittest.Blocking(t, a, root, "does not parse conservatively") {
			t.Fatalf("%s: diagnostics = %v, want the opaque blocking diagnostic", name, got.Diagnostics)
		}
	}
}
